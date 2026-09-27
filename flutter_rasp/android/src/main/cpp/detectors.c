#include "detectors.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

/* Case-insensitive substring test (strcasestr is a GNU extension not guaranteed on the NDK). */
static int ci_contains(const char *haystack, const char *needle) {
    size_t nl = strlen(needle);
    if (nl == 0) {
        return 1;
    }
    for (const char *p = haystack; *p != '\0'; p++) {
        size_t i = 0;
        while (i < nl && p[i] != '\0' &&
               tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i])) {
            i++;
        }
        if (i == nl) {
            return 1;
        }
    }
    return 0;
}

const char *rasp_match_any(const char *haystack, const char *const *needles, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (strstr(haystack, needles[i]) != NULL) {
            return needles[i];
        }
    }
    return NULL;
}

int rasp_parse_tracer_pid(const char *status_text) {
    const char *line = strstr(status_text, "TracerPid:");
    if (line == NULL) {
        return -1;
    }
    return atoi(line + strlen("TracerPid:"));
}

/* Reads a small text file fully. Returns bytes read, or -1. */
static ssize_t read_text_file(const char *path, char *buf, size_t buf_len) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    size_t total = 0;
    while (total + 1 < buf_len) {
        ssize_t n = read(fd, buf + total, buf_len - 1 - total);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            break;
        }
        total += (size_t)n;
    }
    close(fd);
    buf[total] = '\0';
    return (ssize_t)total;
}

/* Calls `on_line` for each line of `path` until it returns non-zero. */
static void for_each_line(const char *path, int (*on_line)(const char *line, void *ctx), void *ctx) {
    FILE *file = fopen(path, "re");
    if (file == NULL) {
        return;
    }
    char line[512];
    while (fgets(line, sizeof(line), file) != NULL) {
        if (on_line(line, ctx) != 0) {
            break;
        }
    }
    fclose(file);
}

void rasp_detect_su_binaries(rasp_signal_list_t *list) {
    static const char *const paths[] = {
        "/system/bin/su",       "/system/xbin/su",   "/sbin/su",
        "/su/bin/su",           "/data/local/su",    "/data/local/bin/su",
        "/data/local/xbin/su",  "/system/sd/xbin/su", "/vendor/bin/su",
        "/system/app/Superuser.apk",
    };
    static const char *const root_dirs[] = {
        "/data/adb/magisk", "/data/adb/ksu", "/data/adb/ap", "/debug_ramdisk/.magisk",
    };
    for (size_t i = 0; i < ARRAY_LEN(paths); i++) {
        if (access(paths[i], F_OK) == 0) {
            rasp_signals_add(list, RASP_THREAT_ROOT, "native.su_binary", 90, paths[i]);
            break;
        }
    }
    for (size_t i = 0; i < ARRAY_LEN(root_dirs); i++) {
        if (access(root_dirs[i], F_OK) == 0) {
            rasp_signals_add(list, RASP_THREAT_ROOT, "native.root_manager_dir", 90, root_dirs[i]);
            break;
        }
    }
}

typedef struct {
    rasp_signal_list_t *list;
    rasp_threat_t threat;
    const char *detector;
    int confidence;
    const char *const *needles;
    size_t needle_count;
} line_match_ctx_t;

static int match_line(const char *line, void *ctx_ptr) {
    line_match_ctx_t *ctx = ctx_ptr;
    const char *hit = rasp_match_any(line, ctx->needles, ctx->needle_count);
    if (hit == NULL) {
        return 0;
    }
    char evidence[RASP_EVIDENCE_LEN];
    snprintf(evidence, sizeof(evidence), "%s", line);
    evidence[strcspn(evidence, "\n")] = '\0';
    rasp_signals_add(ctx->list, ctx->threat, ctx->detector, ctx->confidence, evidence);
    return 1;
}

void rasp_detect_root_mounts(rasp_signal_list_t *list) {
    static const char *const needles[] = {
        "magisk", "/data/adb", "core/mirror", "KSU", "APatch", "zygisk",
    };
    line_match_ctx_t ctx = {list, RASP_THREAT_ROOT, "native.root_mounts", 80, needles, ARRAY_LEN(needles)};
    for_each_line("/proc/self/mounts", match_line, &ctx);
}

void rasp_detect_selinux_permissive(rasp_signal_list_t *list) {
    char buf[8];
    if (read_text_file("/sys/fs/selinux/enforce", buf, sizeof(buf)) > 0 && buf[0] == '0') {
        rasp_signals_add(list, RASP_THREAT_ROOT, "native.selinux_permissive", 60, "enforce=0");
    }
}

void rasp_detect_emulator_files(rasp_signal_list_t *list) {
    static const char *const paths[] = {
        "/dev/qemu_pipe",          "/dev/goldfish_pipe",       "/dev/socket/qemud",
        "/system/bin/qemu-props",  "/sys/qemu_trace",          "/system/lib/libc_malloc_debug_qemu.so",
        "/dev/goldfish_address_space",
    };
    for (size_t i = 0; i < ARRAY_LEN(paths); i++) {
        if (access(paths[i], F_OK) == 0) {
            rasp_signals_add(list, RASP_THREAT_EMULATOR, "native.emulator_files", 80, paths[i]);
            return;
        }
    }
}

void rasp_detect_tracer(rasp_signal_list_t *list) {
    char status[4096];
    if (read_text_file("/proc/self/status", status, sizeof(status)) <= 0) {
        return;
    }
    int tracer = rasp_parse_tracer_pid(status);
    if (tracer > 0) {
        char evidence[32];
        snprintf(evidence, sizeof(evidence), "TracerPid=%d", tracer);
        rasp_signals_add(list, RASP_THREAT_DEBUGGER, "native.tracer_pid", 95, evidence);
    }
}

void rasp_detect_instrumentation_maps(rasp_signal_list_t *list) {
    static const char *const needles[] = {
        "frida", "gadget", "libgum", "xposed", "lsposed", "substrate", "libriru", "zygisk",
    };
    line_match_ctx_t ctx = {list, RASP_THREAT_HOOKING, "native.instrumentation_maps", 90, needles,
                            ARRAY_LEN(needles)};
    for_each_line("/proc/self/maps", match_line, &ctx);
}

void rasp_detect_instrumentation_threads(rasp_signal_list_t *list) {
    static const char *const needles[] = {"gum-js-loop", "gmain", "gdbus", "pool-frida"};
    DIR *tasks = opendir("/proc/self/task");
    if (tasks == NULL) {
        return;
    }
    struct dirent *entry;
    while ((entry = readdir(tasks)) != NULL) {
        if (entry->d_name[0] == '.') {
            continue;
        }
        char path[288];
        char comm[64];
        snprintf(path, sizeof(path), "/proc/self/task/%s/comm", entry->d_name);
        if (read_text_file(path, comm, sizeof(comm)) <= 0) {
            continue;
        }
        const char *hit = rasp_match_any(comm, needles, ARRAY_LEN(needles));
        if (hit != NULL) {
            rasp_signals_add(list, RASP_THREAT_HOOKING, "native.instrumentation_threads", 85, hit);
            break;
        }
    }
    closedir(tasks);
}

void rasp_detect_instrumentation_port(rasp_signal_list_t *list) {
    /* frida-server listens on 127.0.0.1:27042 by default. */
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(27042);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    int connected = connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0;
    if (!connected && errno == EINPROGRESS) {
        struct pollfd pfd = {.fd = fd, .events = POLLOUT};
        if (poll(&pfd, 1, 100) == 1) {
            int err = 0;
            socklen_t len = sizeof(err);
            connected = getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0;
        }
    }
    close(fd);
    if (connected) {
        rasp_signals_add(list, RASP_THREAT_HOOKING, "native.instrumentation_port", 70, "127.0.0.1:27042 open");
    }
}

/* Behavioral, not name-based: an executable mapping backed by a scratch, memfd or deleted file is how
 * injected code (a gadget, a dumped-and-patched .so) is typically run, whatever it is named. Complements the
 * name-based map scan so a renamed Frida build is still caught. */
static int match_exec_suspicious(const char *line, void *ctx_ptr) {
    line_match_ctx_t *ctx = ctx_ptr;
    /* Address bytes are hex (no 'x'); 'x' appears only in the permission field, so this means executable. */
    if (strchr(line, 'x') == NULL) {
        return 0;
    }
    const char *hit = rasp_match_any(line, ctx->needles, ctx->needle_count);
    if (hit == NULL) {
        return 0;
    }
    char evidence[RASP_EVIDENCE_LEN];
    snprintf(evidence, sizeof(evidence), "%s", line);
    evidence[strcspn(evidence, "\n")] = '\0';
    rasp_signals_add(ctx->list, ctx->threat, ctx->detector, ctx->confidence, evidence);
    return 1;
}

void rasp_detect_maps_exec_suspicious(rasp_signal_list_t *list) {
    static const char *const needles[] = {"/data/local/tmp", "memfd:", "(deleted)"};
    line_match_ctx_t ctx = {list, RASP_THREAT_HOOKING, "native.maps_exec_suspicious", 75, needles,
                            ARRAY_LEN(needles)};
    for_each_line("/proc/self/maps", match_exec_suspicious, &ctx);
}

/* --- Emulator: a second and third independent signal beyond the qemu device files ------------------------- */

int rasp_cpuinfo_is_emulator(const char *cpuinfo) {
    static const char *const needles[] = {"goldfish", "ranchu", "genymotion", "vbox86", "virtualbox"};
    for (size_t i = 0; i < ARRAY_LEN(needles); i++) {
        if (ci_contains(cpuinfo, needles[i])) {
            return 1;
        }
    }
    return 0;
}

void rasp_detect_cpuinfo_emulator(rasp_signal_list_t *list) {
    char buf[8192];
    if (read_text_file("/proc/cpuinfo", buf, sizeof(buf)) > 0 && rasp_cpuinfo_is_emulator(buf)) {
        rasp_signals_add(list, RASP_THREAT_EMULATOR, "native.cpuinfo_emulator", 70, "cpuinfo hardware");
    }
}

int rasp_ttydrivers_is_emulator(const char *drivers) {
    /* The Android emulator exposes a goldfish tty driver in /proc/tty/drivers. */
    return ci_contains(drivers, "goldfish");
}

void rasp_detect_ttydrivers_emulator(rasp_signal_list_t *list) {
    char buf[4096];
    if (read_text_file("/proc/tty/drivers", buf, sizeof(buf)) > 0 && rasp_ttydrivers_is_emulator(buf)) {
        rasp_signals_add(list, RASP_THREAT_EMULATOR, "native.ttydrivers_emulator", 70, "goldfish tty");
    }
}

/* --- Root-hiding side channel: one of our OWN threads parked in a KernelSU/APatch kernel routine ----------- */

int rasp_wchan_is_suspicious(const char *wchan) {
    /* Match specific KernelSU/APatch markers; avoid generic "su" which hits legit kernel threads (e.g. sugov). */
    static const char *const needles[] = {"kernelsu", "ksud", "apatch", "apd_"};
    for (size_t i = 0; i < ARRAY_LEN(needles); i++) {
        if (ci_contains(wchan, needles[i])) {
            return 1;
        }
    }
    return 0;
}

/* Reads the wait channel of each of THIS process's own threads (/proc/self/task/<tid>/wchan). It cannot see a
 * separate KernelSU/APatch worker daemon — modern Android hides other processes' /proc under hidepid — but it
 * flags the case where one of our threads is blocked inside a KSU/APatch kernel routine (e.g. a syscall that
 * the root manager hooks), which is a cheap in-process side channel. Broader process-tree scanning is out of
 * scope. */
void rasp_detect_ksu_wchan(rasp_signal_list_t *list) {
    DIR *tasks = opendir("/proc/self/task");
    if (tasks == NULL) {
        return;
    }
    struct dirent *entry;
    while ((entry = readdir(tasks)) != NULL) {
        if (entry->d_name[0] == '.') {
            continue;
        }
        char path[288];
        char wchan[128];
        snprintf(path, sizeof(path), "/proc/self/task/%s/wchan", entry->d_name);
        if (read_text_file(path, wchan, sizeof(wchan)) <= 0) {
            continue;
        }
        if (rasp_wchan_is_suspicious(wchan)) {
            rasp_signals_add(list, RASP_THREAT_ROOT, "native.ksu_wchan", 75, wchan);
            break;
        }
    }
    closedir(tasks);
}

/* --- Debugger: a behavioral self-ptrace check independent of the TracerPid read ------------------------- */

int rasp_selfptrace_is_debugged(long traceme_ret) {
    /* In a fresh child, PTRACE_TRACEME returns 0; it fails only if the child is already being traced
     * (a debugger following forks), so a non-zero return means a debugger is attached. */
    return traceme_ret != 0;
}

void rasp_detect_self_ptrace(rasp_signal_list_t *list) {
    pid_t child = fork();
    if (child == 0) {
        long r = ptrace(PTRACE_TRACEME, 0, 0, 0);
        _exit(rasp_selfptrace_is_debugged(r) ? 1 : 0);
    }
    if (child > 0) {
        int status = 0;
        while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
            /* retry */
        }
        if (WIFEXITED(status) && WEXITSTATUS(status) == 1) {
            rasp_signals_add(list, RASP_THREAT_DEBUGGER, "native.self_ptrace", 85, "PTRACE_TRACEME denied");
        }
    }
}

void rasp_run_all(rasp_signal_list_t *list) {
    rasp_detect_su_binaries(list);
    rasp_detect_root_mounts(list);
    rasp_detect_selinux_permissive(list);
    rasp_detect_ksu_wchan(list);
    rasp_detect_emulator_files(list);
    rasp_detect_cpuinfo_emulator(list);
    rasp_detect_ttydrivers_emulator(list);
    rasp_detect_tracer(list);
    rasp_detect_self_ptrace(list);
    rasp_detect_instrumentation_maps(list);
    rasp_detect_instrumentation_threads(list);
    rasp_detect_instrumentation_port(list);
    rasp_detect_maps_exec_suspicious(list);
}
