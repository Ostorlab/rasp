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
    RASP_LIT(TRACER_LABEL, lit_tracer_label);
    const char *line = strstr(status_text, lit_tracer_label);
    if (line == NULL) {
        return -1;
    }
    return atoi(line + strlen(lit_tracer_label));
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
    RASP_LIT(SU_PATH_1, lit_su_path_1);
    RASP_LIT(SU_PATH_2, lit_su_path_2);
    RASP_LIT(SU_PATH_3, lit_su_path_3);
    RASP_LIT(SU_PATH_4, lit_su_path_4);
    RASP_LIT(SU_PATH_5, lit_su_path_5);
    RASP_LIT(SU_PATH_6, lit_su_path_6);
    RASP_LIT(SU_PATH_7, lit_su_path_7);
    RASP_LIT(SU_PATH_8, lit_su_path_8);
    RASP_LIT(SU_PATH_9, lit_su_path_9);
    RASP_LIT(SU_PATH_10, lit_su_path_10);
    RASP_LIT(ROOT_DIR_1, lit_root_dir_1);
    RASP_LIT(ROOT_DIR_2, lit_root_dir_2);
    RASP_LIT(ROOT_DIR_3, lit_root_dir_3);
    RASP_LIT(ROOT_DIR_4, lit_root_dir_4);
    RASP_LIT(SIG_SU_BIN, lit_sig_su_bin);
    RASP_LIT(SIG_ROOT_DIR, lit_sig_root_dir);
    const char *const paths[] = {
        lit_su_path_1,       lit_su_path_2,   lit_su_path_3,
        lit_su_path_4,           lit_su_path_5,    lit_su_path_6,
        lit_su_path_7,  lit_su_path_8, lit_su_path_9,
        lit_su_path_10,
    };
    const char *const root_dirs[] = {
        lit_root_dir_1, lit_root_dir_2, lit_root_dir_3, lit_root_dir_4,
    };
    for (size_t i = 0; i < ARRAY_LEN(paths); i++) {
        if (access(paths[i], F_OK) == 0) {
            rasp_signals_add(list, RASP_THREAT_ROOT, lit_sig_su_bin, 90, paths[i]);
            break;
        }
    }
    for (size_t i = 0; i < ARRAY_LEN(root_dirs); i++) {
        if (access(root_dirs[i], F_OK) == 0) {
            rasp_signals_add(list, RASP_THREAT_ROOT, lit_sig_root_dir, 90, root_dirs[i]);
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
    RASP_LIT(MNT_MAGISK, lit_mnt_magisk);
    RASP_LIT(MNT_DATA_ADB, lit_mnt_data_adb);
    RASP_LIT(MNT_CORE_MIRROR, lit_mnt_core_mirror);
    RASP_LIT(MNT_KSU, lit_mnt_ksu);
    RASP_LIT(MNT_APATCH, lit_mnt_apatch);
    RASP_LIT(NEEDLE_ZYGISK, lit_needle_zygisk);
    RASP_LIT(SIG_ROOT_MOUNTS, lit_sig_root_mounts);
    RASP_LIT(PATH_MOUNTS, lit_path_mounts);
    const char *const needles[] = {
        lit_mnt_magisk, lit_mnt_data_adb, lit_mnt_core_mirror, lit_mnt_ksu, lit_mnt_apatch, lit_needle_zygisk,
    };
    line_match_ctx_t ctx = {list, RASP_THREAT_ROOT, lit_sig_root_mounts, 80, needles, ARRAY_LEN(needles)};
    for_each_line(lit_path_mounts, match_line, &ctx);
}

void rasp_detect_selinux_permissive(rasp_signal_list_t *list) {
    RASP_LIT(PATH_SELINUX, lit_path_selinux);
    RASP_LIT(SIG_SELINUX, lit_sig_selinux);
    RASP_LIT(EV_SELINUX, lit_ev_selinux);
    char buf[8];
    if (read_text_file(lit_path_selinux, buf, sizeof(buf)) > 0 && buf[0] == '0') {
        rasp_signals_add(list, RASP_THREAT_ROOT, lit_sig_selinux, 60, lit_ev_selinux);
    }
}

void rasp_detect_emulator_files(rasp_signal_list_t *list) {
    RASP_LIT(EMU_PATH_1, lit_emu_path_1);
    RASP_LIT(EMU_PATH_2, lit_emu_path_2);
    RASP_LIT(EMU_PATH_3, lit_emu_path_3);
    RASP_LIT(EMU_PATH_4, lit_emu_path_4);
    RASP_LIT(EMU_PATH_5, lit_emu_path_5);
    RASP_LIT(EMU_PATH_6, lit_emu_path_6);
    RASP_LIT(EMU_PATH_7, lit_emu_path_7);
    RASP_LIT(SIG_EMU_FILES, lit_sig_emu_files);
    const char *const paths[] = {
        lit_emu_path_1,          lit_emu_path_2,       lit_emu_path_3,
        lit_emu_path_4,  lit_emu_path_5,          lit_emu_path_6,
        lit_emu_path_7,
    };
    for (size_t i = 0; i < ARRAY_LEN(paths); i++) {
        if (access(paths[i], F_OK) == 0) {
            rasp_signals_add(list, RASP_THREAT_EMULATOR, lit_sig_emu_files, 80, paths[i]);
            return;
        }
    }
}

void rasp_detect_tracer(rasp_signal_list_t *list) {
    RASP_LIT(PATH_STATUS, lit_path_status);
    RASP_LIT(FMT_TRACER, lit_fmt_tracer);
    RASP_LIT(SIG_TRACER, lit_sig_tracer);
    char status[4096];
    if (read_text_file(lit_path_status, status, sizeof(status)) <= 0) {
        return;
    }
    int tracer = rasp_parse_tracer_pid(status);
    if (tracer > 0) {
        char evidence[32];
        snprintf(evidence, sizeof(evidence), lit_fmt_tracer, tracer);
        rasp_signals_add(list, RASP_THREAT_DEBUGGER, lit_sig_tracer, 95, evidence);
    }
}

void rasp_detect_instrumentation_maps(rasp_signal_list_t *list) {
    RASP_LIT(HOOK_FRIDA, lit_hook_frida);
    RASP_LIT(HOOK_GADGET, lit_hook_gadget);
    RASP_LIT(HOOK_LIBGUM, lit_hook_libgum);
    RASP_LIT(HOOK_XPOSED, lit_hook_xposed);
    RASP_LIT(HOOK_LSPOSED, lit_hook_lsposed);
    RASP_LIT(HOOK_SUBSTRATE, lit_hook_substrate);
    RASP_LIT(HOOK_LIBRIRU, lit_hook_libriru);
    RASP_LIT(NEEDLE_ZYGISK, lit_needle_zygisk);
    RASP_LIT(SIG_MAPS, lit_sig_maps);
    RASP_LIT(PATH_MAPS, lit_path_maps);
    const char *const needles[] = {
        lit_hook_frida, lit_hook_gadget, lit_hook_libgum, lit_hook_xposed, lit_hook_lsposed, lit_hook_substrate, lit_hook_libriru, lit_needle_zygisk,
    };
    line_match_ctx_t ctx = {list, RASP_THREAT_HOOKING, lit_sig_maps, 90, needles,
                            ARRAY_LEN(needles)};
    for_each_line(lit_path_maps, match_line, &ctx);
}

void rasp_detect_instrumentation_threads(rasp_signal_list_t *list) {
    RASP_LIT(THREAD_GUM, lit_thread_gum);
    RASP_LIT(THREAD_GMAIN, lit_thread_gmain);
    RASP_LIT(THREAD_GDBUS, lit_thread_gdbus);
    RASP_LIT(THREAD_POOL, lit_thread_pool);
    RASP_LIT(PATH_TASK, lit_path_task);
    RASP_LIT(FMT_COMM, lit_fmt_comm);
    RASP_LIT(SIG_THREADS, lit_sig_threads);
    const char *const needles[] = {lit_thread_gum, lit_thread_gmain, lit_thread_gdbus, lit_thread_pool};
    DIR *tasks = opendir(lit_path_task);
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
        snprintf(path, sizeof(path), lit_fmt_comm, entry->d_name);
        if (read_text_file(path, comm, sizeof(comm)) <= 0) {
            continue;
        }
        const char *hit = rasp_match_any(comm, needles, ARRAY_LEN(needles));
        if (hit != NULL) {
            rasp_signals_add(list, RASP_THREAT_HOOKING, lit_sig_threads, 85, hit);
            break;
        }
    }
    closedir(tasks);
}

void rasp_detect_instrumentation_port(rasp_signal_list_t *list) {
    RASP_LIT(SIG_PORT, lit_sig_port);
    RASP_LIT(EV_PORT, lit_ev_port);
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
        rasp_signals_add(list, RASP_THREAT_HOOKING, lit_sig_port, 70, lit_ev_port);
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
    RASP_LIT(EXEC_TMP, lit_exec_tmp);
    RASP_LIT(EXEC_MEMFD, lit_exec_memfd);
    RASP_LIT(EXEC_DELETED, lit_exec_deleted);
    RASP_LIT(SIG_EXEC, lit_sig_exec);
    RASP_LIT(PATH_MAPS, lit_path_maps);
    const char *const needles[] = {lit_exec_tmp, lit_exec_memfd, lit_exec_deleted};
    line_match_ctx_t ctx = {list, RASP_THREAT_HOOKING, lit_sig_exec, 75, needles,
                            ARRAY_LEN(needles)};
    for_each_line(lit_path_maps, match_exec_suspicious, &ctx);
}

/* --- Emulator: a second and third independent signal beyond the qemu device files ------------------------- */

int rasp_cpuinfo_is_emulator(const char *cpuinfo) {
    RASP_LIT(EMUW_GOLDFISH, lit_emuw_goldfish);
    RASP_LIT(EMUW_RANCHU, lit_emuw_ranchu);
    RASP_LIT(EMUW_GENY, lit_emuw_geny);
    RASP_LIT(EMUW_VBOX86, lit_emuw_vbox86);
    RASP_LIT(EMUW_VBOX, lit_emuw_vbox);
    const char *const needles[] = {lit_emuw_goldfish, lit_emuw_ranchu, lit_emuw_geny, lit_emuw_vbox86, lit_emuw_vbox};
    for (size_t i = 0; i < ARRAY_LEN(needles); i++) {
        if (ci_contains(cpuinfo, needles[i])) {
            return 1;
        }
    }
    return 0;
}

void rasp_detect_cpuinfo_emulator(rasp_signal_list_t *list) {
    RASP_LIT(PATH_CPUINFO, lit_path_cpuinfo);
    RASP_LIT(SIG_CPUINFO, lit_sig_cpuinfo);
    RASP_LIT(EV_CPUINFO, lit_ev_cpuinfo);
    char buf[8192];
    if (read_text_file(lit_path_cpuinfo, buf, sizeof(buf)) > 0 && rasp_cpuinfo_is_emulator(buf)) {
        rasp_signals_add(list, RASP_THREAT_EMULATOR, lit_sig_cpuinfo, 70, lit_ev_cpuinfo);
    }
}

int rasp_ttydrivers_is_emulator(const char *drivers) {
    RASP_LIT(EMUW_GOLDFISH, lit_emuw_goldfish);
    /* The Android emulator exposes a goldfish tty driver in /proc/tty/drivers. */
    return ci_contains(drivers, lit_emuw_goldfish);
}

void rasp_detect_ttydrivers_emulator(rasp_signal_list_t *list) {
    RASP_LIT(PATH_TTY, lit_path_tty);
    RASP_LIT(SIG_TTY, lit_sig_tty);
    RASP_LIT(EV_TTY, lit_ev_tty);
    char buf[4096];
    if (read_text_file(lit_path_tty, buf, sizeof(buf)) > 0 && rasp_ttydrivers_is_emulator(buf)) {
        rasp_signals_add(list, RASP_THREAT_EMULATOR, lit_sig_tty, 70, lit_ev_tty);
    }
}

/* --- Root-hiding side channel: one of our OWN threads parked in a KernelSU/APatch kernel routine ----------- */

int rasp_wchan_is_suspicious(const char *wchan) {
    RASP_LIT(WCH_KSU, lit_wch_ksu);
    RASP_LIT(WCH_KSUD, lit_wch_ksud);
    RASP_LIT(WCH_APATCH, lit_wch_apatch);
    RASP_LIT(WCH_APD, lit_wch_apd);
    /* Match specific KernelSU/APatch markers; avoid generic "su" which hits legit kernel threads (e.g. sugov). */
    const char *const needles[] = {lit_wch_ksu, lit_wch_ksud, lit_wch_apatch, lit_wch_apd};
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
    RASP_LIT(PATH_TASK, lit_path_task);
    RASP_LIT(FMT_WCHAN, lit_fmt_wchan);
    RASP_LIT(SIG_WCHAN, lit_sig_wchan);
    DIR *tasks = opendir(lit_path_task);
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
        snprintf(path, sizeof(path), lit_fmt_wchan, entry->d_name);
        if (read_text_file(path, wchan, sizeof(wchan)) <= 0) {
            continue;
        }
        if (rasp_wchan_is_suspicious(wchan)) {
            rasp_signals_add(list, RASP_THREAT_ROOT, lit_sig_wchan, 75, wchan);
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
    RASP_LIT(SIG_PTRACE, lit_sig_ptrace);
    RASP_LIT(EV_PTRACE, lit_ev_ptrace);
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
            rasp_signals_add(list, RASP_THREAT_DEBUGGER, lit_sig_ptrace, 85, lit_ev_ptrace);
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
