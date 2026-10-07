#define _GNU_SOURCE
#include "rasp_build.h"
#include "rasp_runtime.h"
#include <arpa/inet.h>
#include <dlfcn.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <pthread.h>
#include <poll.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Integration symbols are explicitly marked with public visibility. */
__attribute__((visibility("default"))) int connect(int, const struct sockaddr *, socklen_t);

#define DOCUMENT_MAX 8192
#define RESPONSE_MAX 16384
#define FILE_MAX_BYTES (256LL * 1024 * 1024)
#define THREAD_SCAN_MAX 4096
#define STATUS_MAX_BYTES 65536
#define THREAT_TAMPER 1u
#define THREAT_DEBUGGER 2u
#define THREAT_PRELOAD 4u
#define THREAT_FAILURE 8u

struct manifest {
    char build[65], exe[65], runtime[65], client_public[65], server_public[65];
    char endpoint[1024], host[256], port[6];
    unsigned interval_ms;
    bool tls;
};
static struct manifest config;
static char executable_path[PATH_MAX], runtime_path[PATH_MAX], manifest_path[PATH_MAX];
static char manifest_hash[65];
static EVP_PKEY *client_key;
typedef int (*connect_function)(int, const struct sockaddr *, socklen_t);
static _Atomic(connect_function) original_connect;
static _Thread_local bool transport_bypass;
static atomic_bool initialized;
static pid_t owner_pid;
static pthread_mutex_t authorization_lock = PTHREAD_MUTEX_INITIALIZER;

static void report(const char *kind, const char *detail) {
    fprintf(stderr, "RASP {\"type\":\"%s\",\"detail\":\"%s\"}\n", kind, detail);
}
static void fatal(const char *detail) {
    report("failure", detail);
    _exit(173);
}
static bool hex_valid(const char *text, size_t bytes) {
    if (strlen(text) != bytes * 2) return false;
    for (size_t i = 0; i < bytes * 2; ++i)
        if (!((text[i] >= '0' && text[i] <= '9') || (text[i] >= 'a' && text[i] <= 'f'))) return false;
    return true;
}
static bool unhex(const char *text, unsigned char *bytes, size_t length) {
    if (!hex_valid(text, length)) return false;
    for (size_t i = 0; i < length; ++i) {
        unsigned a = text[i * 2] <= '9' ? (unsigned)(text[i * 2] - '0') : (unsigned)(text[i * 2] - 'a' + 10);
        unsigned b = text[i * 2 + 1] <= '9' ? (unsigned)(text[i * 2 + 1] - '0') : (unsigned)(text[i * 2 + 1] - 'a' + 10);
        bytes[i] = (unsigned char)(a * 16 + b);
    }
    return true;
}
static void hex_encode(const unsigned char *bytes, size_t length, char *text) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < length; ++i) {
        text[i * 2] = digits[bytes[i] >> 4];
        text[i * 2 + 1] = digits[bytes[i] & 15];
    }
    text[length * 2] = '\0';
}
static bool hash_bytes(const void *data, size_t length, char result[65]) {
    unsigned char digest[32];
    unsigned int digest_length = 0;
    if (EVP_Digest(data, length, digest, &digest_length, EVP_sha256(), NULL) != 1 || digest_length != 32) return false;
    hex_encode(digest, sizeof(digest), result);
    return true;
}
static bool hash_file(const char *path, char result[65]) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return false;
    struct stat before, after;
    if (fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) || before.st_size < 0 || before.st_size > FILE_MAX_BYTES) { close(fd); return false; }
    off_t remaining = before.st_size;
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    bool ok = context && EVP_DigestInit_ex(context, EVP_sha256(), NULL) == 1;
    unsigned char buffer[16384], digest[32];
    unsigned int length = 0;
    ssize_t count;
    while (ok && remaining > 0) {
        size_t chunk = remaining < (off_t)sizeof(buffer) ? (size_t)remaining : sizeof(buffer);
        count = read(fd, buffer, chunk);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { ok = false; break; }
        remaining -= count;
        ok = EVP_DigestUpdate(context, buffer, (size_t)count) == 1;
    }
    if (ok) ok = fstat(fd, &after) == 0 && before.st_size == after.st_size &&
        before.st_mtim.tv_sec == after.st_mtim.tv_sec && before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
        before.st_ctim.tv_sec == after.st_ctim.tv_sec && before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
    if (ok) ok = EVP_DigestFinal_ex(context, digest, &length) == 1 && length == 32;
    close(fd);
    EVP_MD_CTX_free(context);
    if (ok) hex_encode(digest, sizeof(digest), result);
    return ok;
}
static bool read_document(const char *path, char *buffer, size_t capacity, size_t *length) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return false;
    struct stat status;
    if (fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) || status.st_size <= 0 || (uint64_t)status.st_size >= capacity) { close(fd); return false; }
    size_t used = 0;
    bool ok = true;
    while (used < capacity - 1) {
        ssize_t count = read(fd, buffer + used, capacity - 1 - used);
        if (count == 0) break;
        if (count < 0) { if (errno == EINTR) continue; ok = false; break; }
        used += (size_t)count;
    }
    char extra;
    if (ok && read(fd, &extra, 1) != 0) ok = false;
    close(fd);
    buffer[used] = '\0';
    *length = used;
    return ok && used > 0 && !memchr(buffer, '\0', used);
}
/* Parse exactly one ordered field without changing the signed document bytes. */
static bool field(const char **cursor, const char *name, char *value, size_t capacity) {
    size_t prefix = strlen(name);
    if (strncmp(*cursor, name, prefix) != 0 || (*cursor)[prefix] != '=') return false;
    const char *start = *cursor + prefix + 1;
    const char *end = strchr(start, '\n');
    if (!end || (size_t)(end - start) >= capacity) return false;
    memcpy(value, start, (size_t)(end - start));
    value[end - start] = '\0';
    *cursor = end + 1;
    return true;
}
static bool decimal(const char *text, uint64_t *value) {
    if (!*text) return false;
    uint64_t number = 0;
    for (const char *p = text; *p; ++p) {
        if (*p < '0' || *p > '9' || number > (UINT64_MAX - (unsigned)(*p - '0')) / 10) return false;
        number = number * 10 + (unsigned)(*p - '0');
    }
    *value = number;
    return true;
}
static bool verify_signature(const char *public_hex, const char *signature_hex, const void *data, size_t length) {
    unsigned char public_bytes[32], signature[64];
    if (!unhex(public_hex, public_bytes, sizeof(public_bytes)) || !unhex(signature_hex, signature, sizeof(signature))) return false;
    EVP_PKEY *key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, public_bytes, sizeof(public_bytes));
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    bool ok = key && context && EVP_DigestVerifyInit(context, NULL, NULL, NULL, key) == 1 && EVP_DigestVerify(context, signature, sizeof(signature), data, length) == 1;
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(key);
    return ok;
}
static bool parse_endpoint(void) {
    if (!config.endpoint[0]) return true;
    if (strlen(config.endpoint) > 512 || strcmp(config.server_public, "0000000000000000000000000000000000000000000000000000000000000000") == 0) return false;
    const char *authority;
    if (strncmp(config.endpoint, "https://", 8) == 0) { config.tls = true; authority = config.endpoint + 8; }
    else if (strncmp(config.endpoint, "http://", 7) == 0) authority = config.endpoint + 7;
    else return false;
    if (strpbrk(authority, "/?#@\\ \t\r\n")) return false;
    for (const char *p = authority; *p; ++p)
        if (!((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || strchr(".:[]-", *p))) return false;
    const char *port, *host = authority;
    size_t host_length;
    if (*host == '[') {
        host++;
        const char *end = strchr(host, ']');
        if (!end || end[1] != ':') return false;
        host_length = (size_t)(end - host);
        port = end + 2;
    } else {
        const char *end = strchr(host, ':');
        if (!end || strchr(end + 1, ':')) return false;
        host_length = (size_t)(end - host);
        port = end + 1;
    }
    if (!host_length || host_length >= sizeof(config.host) || strlen(port) >= sizeof(config.port)) return false;
    memcpy(config.host, host, host_length);
    config.host[host_length] = '\0';
    uint64_t number;
    if (!decimal(port, &number) || number == 0 || number > 65535) return false;
    strcpy(config.port, port);
    struct in_addr ipv4;
    struct in6_addr ipv6;
    bool v4 = inet_pton(AF_INET, config.host, &ipv4) == 1;
    bool v6 = inet_pton(AF_INET6, config.host, &ipv6) == 1;
    if (authority[0] == '[' && !v6) return false;
    if (!config.tls && !((v4 && (ntohl(ipv4.s_addr) >> 24) == 127) || (v6 && IN6_IS_ADDR_LOOPBACK(&ipv6)))) return false;
    return true;
}
static bool load_manifest(void) {
    char document[DOCUMENT_MAX], version[64], interval[32], signature[129];
    size_t length;
    if (!read_document(manifest_path, document, sizeof(document), &length)) return false;
    const char *cursor = document;
    if (!field(&cursor, "v", version, sizeof(version)) || strcmp(version, "rasp-elf-manifest-1") ||
        !field(&cursor, "build", config.build, sizeof(config.build)) || !hex_valid(config.build, 32) ||
        !field(&cursor, "exe", config.exe, sizeof(config.exe)) || !hex_valid(config.exe, 32) ||
        !field(&cursor, "runtime", config.runtime, sizeof(config.runtime)) || !hex_valid(config.runtime, 32) ||
        !field(&cursor, "endpoint", config.endpoint, sizeof(config.endpoint)) ||
        !field(&cursor, "interval_ms", interval, sizeof(interval)) ||
        !field(&cursor, "client_public", config.client_public, sizeof(config.client_public)) || !hex_valid(config.client_public, 32) ||
        !field(&cursor, "server_public", config.server_public, sizeof(config.server_public)) || !hex_valid(config.server_public, 32)) return false;
    size_t signed_length = (size_t)(cursor - document);
    if (!field(&cursor, "signature", signature, sizeof(signature)) || *cursor || !verify_signature(RASP_PUBLISHER_PUBLIC_HEX, signature, document, signed_length)) return false;
    uint64_t number;
    if (!decimal(interval, &number) || number < 100 || number > 60000) return false;
    config.interval_ms = (unsigned)number;
    if (!parse_endpoint() || !hash_bytes(document, length, manifest_hash)) return false;
    unsigned char private_bytes[32], public_bytes[32];
    size_t public_length = sizeof(public_bytes);
    if (!unhex(RASP_CLIENT_PRIVATE_HEX, private_bytes, sizeof(private_bytes))) return false;
    client_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, private_bytes, sizeof(private_bytes));
    OPENSSL_cleanse(private_bytes, sizeof(private_bytes));
    char public_hex[65];
    if (!client_key || EVP_PKEY_get_raw_public_key(client_key, public_bytes, &public_length) != 1 || public_length != 32) return false;
    hex_encode(public_bytes, public_length, public_hex);
    return strcmp(config.client_public, public_hex) == 0;
}
static bool thread_disappeared(int directory, const char *name) {
    struct stat status;
    return fstatat(directory, name, &status, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
}
static bool thread_tracer(int fd, bool *traced) {
    char document[STATUS_MAX_BYTES + 1];
    size_t used = 0;
    while (used < STATUS_MAX_BYTES) {
        ssize_t count = read(fd, document + used, STATUS_MAX_BYTES - used);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) return false;
        if (count == 0) break;
        used += (size_t)count;
    }
    if (used == STATUS_MAX_BYTES) {
        char extra;
        ssize_t count;
        do { count = read(fd, &extra, 1); } while (count < 0 && errno == EINTR);
        if (count != 0) return false;
    }
    if (!used || document[used - 1] != '\n' || memchr(document, '\0', used)) return false;
    document[used] = '\0';
    bool found = false;
    *traced = false;
    char *line = document;
    while (*line) {
        char *end = strchr(line, '\n');
        if (!end) return false;
        if (strncmp(line, "TracerPid:", 10) == 0) {
            if (found) return false;
            found = true;
            char *number = line + 10;
            while (number < end && (*number == ' ' || *number == '\t')) number++;
            *end = '\0';
            uint64_t tracer;
            if (!decimal(number, &tracer) || tracer > INT_MAX) return false;
            *traced = tracer != 0;
        }
        line = end + 1;
    }
    return found;
}
static unsigned debugger_threats(void) {
    DIR *tasks = opendir("/proc/self/task");
    if (!tasks) return THREAT_FAILURE;
    unsigned threats = 0, seen = 0, parsed = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(tasks);
        if (!entry) { if (errno) threats |= THREAT_FAILURE; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (++seen > THREAD_SCAN_MAX) { threats |= THREAT_FAILURE; break; }
        uint64_t thread;
        if (!decimal(entry->d_name, &thread) || !thread || thread > INT_MAX) { threats |= THREAT_FAILURE; continue; }
        char path[32];
        int length = snprintf(path, sizeof(path), "%s/status", entry->d_name);
        if (length < 0 || (size_t)length >= sizeof(path)) { threats |= THREAT_FAILURE; continue; }
        int fd = openat(dirfd(tasks), path, O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW);
        if (fd < 0) {
            if (errno != ENOENT) threats |= THREAT_FAILURE;
            continue;
        }
        bool traced = false;
        bool ok = thread_tracer(fd, &traced);
        close(fd);
        if (!ok) {
            /* A task may exit between enumeration, open, and reading its
             * status. Only disappearance excuses a failed status read. */
            if (!thread_disappeared(dirfd(tasks), entry->d_name)) threats |= THREAT_FAILURE;
            continue;
        }
        parsed++;
        if (traced) threats |= THREAT_DEBUGGER;
    }
    if (!parsed) threats |= THREAT_FAILURE;
    if (closedir(tasks) != 0) threats |= THREAT_FAILURE;
    return threats;
}
static unsigned scan(char exe_hash[65], char library_hash[65]) {
    unsigned threats = 0;
    if (!hash_file(executable_path, exe_hash)) { strcpy(exe_hash, config.exe); threats |= THREAT_FAILURE; }
    else if (strcmp(exe_hash, config.exe)) threats |= THREAT_TAMPER;
    if (!hash_file(runtime_path, library_hash)) { strcpy(library_hash, config.runtime); threats |= THREAT_FAILURE; }
    else if (strcmp(library_hash, config.runtime)) threats |= THREAT_TAMPER;
    char hash[65];
    if (!hash_file(manifest_path, hash) || strcmp(hash, manifest_hash)) threats |= THREAT_TAMPER;
    threats |= debugger_threats();
    const char *preload = getenv("LD_PRELOAD"), *audit = getenv("LD_AUDIT");
    if ((preload && *preload) || (audit && *audit)) threats |= THREAT_PRELOAD;
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) threats |= THREAT_FAILURE;
    else {
        char line[PATH_MAX + 256];
        while (fgets(line, sizeof(line), maps))
            if (strcasestr(line, "frida") || strcasestr(line, "libgum") || strcasestr(line, "libgadget") || strcasestr(line, "libpin.so") || strcasestr(line, "dynamorio")) threats |= THREAT_PRELOAD;
        if (ferror(maps)) threats |= THREAT_FAILURE;
        fclose(maps);
    }
    return threats;
}
static void threats_text(unsigned threats, char text[128]) {
    text[0] = '\0';
    const char *names[] = {"tamper", "debugger", "preload", "detectorFailure"};
    for (unsigned i = 0; i < 4; ++i) if (threats & (1u << i)) {
        if (*text) strcat(text, ",");
        strcat(text, names[i]);
    }
    if (!*text) strcpy(text, "none");
}

/* Transport uses independent nonblocking sockets. One monotonic deadline
 * covers DNS return, all address candidates, TLS, sending, and receiving.
 * getaddrinfo itself follows system resolver limits and cannot be cancelled. */
struct connection { int fd; SSL_CTX *context; SSL *ssl; struct timespec deadline; };
static void close_connection(struct connection *connection) {
    SSL_free(connection->ssl);
    SSL_CTX_free(connection->context);
    if (connection->fd >= 0) close(connection->fd);
}
static int remaining_ms(const struct connection *connection) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    int64_t remaining = (int64_t)(connection->deadline.tv_sec - now.tv_sec) * 1000000000 + connection->deadline.tv_nsec - now.tv_nsec;
    if (remaining <= 0) { errno = ETIMEDOUT; return 0; }
    /* Round up for poll; the monotonic clock is checked again after waiting. */
    return (int)((remaining + 999999) / 1000000);
}
static bool wait_ready(struct connection *connection, short events) {
    for (;;) {
        int timeout = remaining_ms(connection);
        if (timeout == 0) return false;
        struct pollfd descriptor = {.fd = connection->fd, .events = events, .revents = 0};
        int result = poll(&descriptor, 1, timeout);
        if (result < 0 && errno == EINTR) continue;
        if (result < 0) return false;
        if (result == 0) continue;
        if (remaining_ms(connection) == 0) return false;
        if (descriptor.revents & POLLNVAL) { errno = EBADF; return false; }
        return (descriptor.revents & (events | POLLERR | POLLHUP)) != 0;
    }
}
static bool wait_tls(struct connection *connection, int error) {
    if (error == SSL_ERROR_WANT_READ) return wait_ready(connection, POLLIN);
    if (error == SSL_ERROR_WANT_WRITE) return wait_ready(connection, POLLOUT);
    if (error == SSL_ERROR_SYSCALL && errno == EINTR) return remaining_ms(connection) != 0;
    return false;
}
static bool open_connection(struct connection *connection) {
    memset(connection, 0, sizeof(*connection));
    connection->fd = -1;
    if (clock_gettime(CLOCK_MONOTONIC, &connection->deadline) != 0) return false;
    connection->deadline.tv_sec += 2;
    struct addrinfo hints = {0}, *addresses = NULL;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    if (getaddrinfo(config.host, config.port, &hints, &addresses) != 0) return false;
    connect_function real_connect = atomic_load_explicit(&original_connect, memory_order_acquire);
    for (struct addrinfo *address = addresses; address; address = address->ai_next) {
        if (remaining_ms(connection) == 0) break;
        connection->fd = socket(address->ai_family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, address->ai_protocol);
        if (connection->fd < 0) continue;
        int result = real_connect(connection->fd, address->ai_addr, address->ai_addrlen);
        bool connected = result == 0;
        if (!connected && (errno == EINPROGRESS || errno == EALREADY || errno == EWOULDBLOCK || errno == EINTR) && wait_ready(connection, POLLOUT)) {
            int error = 0;
            socklen_t length = sizeof(error);
            connected = getsockopt(connection->fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && error == 0;
        }
        if (connected) break;
        close(connection->fd);
        connection->fd = -1;
    }
    freeaddrinfo(addresses);
    if (connection->fd < 0 || remaining_ms(connection) == 0) return false;
    if (!config.tls) return true;
    connection->context = SSL_CTX_new(TLS_client_method());
    if (!connection->context || SSL_CTX_set_min_proto_version(connection->context, TLS1_2_VERSION) != 1 || SSL_CTX_set_default_verify_paths(connection->context) != 1) return false;
    SSL_CTX_set_verify(connection->context, SSL_VERIFY_PEER, NULL);
    connection->ssl = SSL_new(connection->context);
    if (!connection->ssl || SSL_set_fd(connection->ssl, connection->fd) != 1) return false;
    struct in_addr ipv4;
    struct in6_addr ipv6;
    X509_VERIFY_PARAM *parameters = SSL_get0_param(connection->ssl);
    X509_VERIFY_PARAM_set_hostflags(parameters, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    if (inet_pton(AF_INET, config.host, &ipv4) == 1 || inet_pton(AF_INET6, config.host, &ipv6) == 1) {
        if (X509_VERIFY_PARAM_set1_ip_asc(parameters, config.host) != 1) return false;
    } else {
        if (SSL_set_tlsext_host_name(connection->ssl, config.host) != 1 || SSL_set1_host(connection->ssl, config.host) != 1) return false;
    }
    for (;;) {
        if (remaining_ms(connection) == 0) return false;
        int result = SSL_connect(connection->ssl);
        if (result == 1) return SSL_get_verify_result(connection->ssl) == X509_V_OK && remaining_ms(connection) != 0;
        if (!wait_tls(connection, SSL_get_error(connection->ssl, result))) return false;
    }
}
static ssize_t receive_data(struct connection *connection, char *buffer, size_t length) {
    for (;;) {
        if (remaining_ms(connection) == 0) return -1;
        if (connection->ssl) {
            int count = SSL_read(connection->ssl, buffer, (int)length);
            if (count > 0) return count;
            int error = SSL_get_error(connection->ssl, count);
            if (error == SSL_ERROR_ZERO_RETURN) return 0;
            if (!wait_tls(connection, error)) return -1;
        } else {
            ssize_t count = recv(connection->fd, buffer, length, 0);
            if (count >= 0) return count;
            if (errno == EINTR) continue;
            if ((errno != EAGAIN && errno != EWOULDBLOCK) || !wait_ready(connection, POLLIN)) return -1;
        }
    }
}
static bool send_all(struct connection *connection, const char *buffer, size_t length) {
    while (length) {
        if (remaining_ms(connection) == 0) return false;
        ssize_t count;
        if (connection->ssl) {
            count = SSL_write(connection->ssl, buffer, (int)length);
            if (count <= 0) { if (!wait_tls(connection, SSL_get_error(connection->ssl, (int)count))) return false; continue; }
        } else {
            count = send(connection->fd, buffer, length, MSG_NOSIGNAL);
            if (count < 0 && errno == EINTR) continue;
            if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) { if (!wait_ready(connection, POLLOUT)) return false; continue; }
            if (count <= 0) return false;
        }
        buffer += count;
        length -= (size_t)count;
    }
    return remaining_ms(connection) != 0;
}
static bool http_post(const char *path, const char *body, size_t length, char *result, size_t capacity) {
    struct connection connection;
    bool prior_bypass = transport_bypass;
    transport_bypass = true;
    bool ok = open_connection(&connection);
    char request[DOCUMENT_MAX + 2048];
    int request_length = snprintf(request, sizeof(request), "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n", path, config.endpoint + (config.tls ? 8 : 7), length);
    if (ok && (request_length < 0 || (size_t)request_length + length >= sizeof(request))) ok = false;
    if (ok) {
        memcpy(request + request_length, body, length);
        ok = send_all(&connection, request, (size_t)request_length + length);
    }
    char response[RESPONSE_MAX + 1];
    size_t used = 0, header_length = 0, content_length = 0;
    bool have_header = false;
    while (ok) {
        if (used == RESPONSE_MAX) { ok = false; break; }
        ssize_t count = receive_data(&connection, response + used, RESPONSE_MAX - used);
        if (count <= 0) { ok = false; break; }
        used += (size_t)count;
        response[used] = '\0';
        if (memchr(response, '\0', used)) { ok = false; break; }
        if (!have_header) {
            char *separator = strstr(response, "\r\n\r\n");
            if (!separator) continue;
            header_length = (size_t)(separator - response) + 4;
            char *line = strstr(response, "\r\n");
            if (!line || !((strncmp(response, "HTTP/1.1 200", 12) == 0 || strncmp(response, "HTTP/1.0 200", 12) == 0) && (response[12] == ' ' || response[12] == '\r'))) { ok = false; break; }
            bool found_length = false;
            line += 2;
            while (line < separator) {
                char *end = strstr(line, "\r\n");
                if (!end || end > separator) { ok = false; break; }
                char *colon = memchr(line, ':', (size_t)(end - line));
                if (!colon) { ok = false; break; }
                size_t name_length = (size_t)(colon - line);
                if (name_length == 14 && strncasecmp(line, "Content-Length", 14) == 0) {
                    if (found_length) { ok = false; break; }
                    char number[32];
                    const char *start = colon + 1;
                    while (start < end && (*start == ' ' || *start == '\t')) start++;
                    size_t digits = (size_t)(end - start);
                    uint64_t parsed;
                    if (!digits || digits >= sizeof(number)) { ok = false; break; }
                    memcpy(number, start, digits); number[digits] = '\0';
                    if (!decimal(number, &parsed) || parsed >= capacity || parsed > RESPONSE_MAX - header_length) { ok = false; break; }
                    content_length = (size_t)parsed;
                    found_length = true;
                } else if (name_length == 17 && strncasecmp(line, "Transfer-Encoding", 17) == 0) { ok = false; break; }
                line = end + 2;
            }
            if (!ok || !found_length) { ok = false; break; }
            have_header = true;
        }
        if (have_header && used >= header_length + content_length) {
            if (used != header_length + content_length) { ok = false; break; }
            memcpy(result, response + header_length, content_length);
            result[content_length] = '\0';
            break;
        }
    }
    ok = ok && have_header && remaining_ms(&connection) != 0;
    close_connection(&connection);
    transport_bypass = prior_bypass;
    return ok;
}
static bool signed_decision(const char *document, const char *nonce, const char *evidence_hash) {
    const char *cursor = document;
    char version[64], build[65], returned_nonce[65], hash[65], action[16], expiry[32], signature[129];
    if (!field(&cursor, "v", version, sizeof(version)) || strcmp(version, "rasp-elf-decision-1") ||
        !field(&cursor, "build", build, sizeof(build)) || strcmp(build, config.build) ||
        !field(&cursor, "nonce", returned_nonce, sizeof(returned_nonce)) || strcmp(returned_nonce, nonce) ||
        !field(&cursor, "evidence", hash, sizeof(hash)) || strcmp(hash, evidence_hash) ||
        !field(&cursor, "action", action, sizeof(action)) ||
        !field(&cursor, "expires", expiry, sizeof(expiry))) return false;
    size_t signed_length = (size_t)(cursor - document);
    if (!field(&cursor, "signature", signature, sizeof(signature)) || *cursor || !verify_signature(config.server_public, signature, document, signed_length)) return false;
    uint64_t expires;
    time_t now = time(NULL);
    if (now < 0 || !decimal(expiry, &expires) || expires <= (uint64_t)now || expires > (uint64_t)now + 60) return false;
    if (strcmp(action, "allow") != 0) { report("decision", strcmp(action, "step_up") == 0 ? "step_up" : "deny"); return false; }
    return true;
}
struct prepared_evidence {
    char wire[DOCUMENT_MAX], nonce[65], hash[65];
    size_t length;
};
static bool prepare_evidence(const char *operation, const void *payload, size_t payload_length,
                             const char *exe_hash, const char *library_hash, const char *threats,
                             struct prepared_evidence *prepared) {
    prepared->wire[0] = '\0';
    prepared->length = 0;
    char request_hash[65];
    if (!hash_bytes(payload, payload_length, request_hash)) return false;
    char challenge_body[80], challenge[512];
    int challenge_length = snprintf(challenge_body, sizeof(challenge_body), "build=%s\n", config.build);
    if (challenge_length < 0 || !http_post("/v1/challenge", challenge_body, (size_t)challenge_length, challenge, sizeof(challenge))) { report("failure", "backendChallenge"); return false; }
    const char *cursor = challenge;
    if (!field(&cursor, "nonce", prepared->nonce, sizeof(prepared->nonce)) || *cursor || !hex_valid(prepared->nonce, 32)) { report("failure", "backendChallenge"); return false; }
    int length = snprintf(prepared->wire, sizeof(prepared->wire), "v=rasp-elf-evidence-1\nbuild=%s\nnonce=%s\npid=%ld\nexe=%s\nruntime=%s\nthreats=%s\noperation=%s\nrequest=%s\n", config.build, prepared->nonce, (long)getpid(), exe_hash, library_hash, threats, operation, request_hash);
    if (length < 0 || (size_t)length + 140 >= sizeof(prepared->wire) || !hash_bytes(prepared->wire, (size_t)length, prepared->hash)) return false;
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    unsigned char signature[64];
    size_t signature_length = sizeof(signature);
    bool ok = context && EVP_DigestSignInit(context, NULL, NULL, NULL, client_key) == 1 && EVP_DigestSign(context, signature, &signature_length, (unsigned char *)prepared->wire, (size_t)length) == 1 && signature_length == 64;
    EVP_MD_CTX_free(context);
    if (!ok) return false;
    char signature_hex[129];
    hex_encode(signature, signature_length, signature_hex);
    int suffix = snprintf(prepared->wire + length, sizeof(prepared->wire) - (size_t)length, "signature=%s\n", signature_hex);
    if (suffix < 0 || (size_t)suffix >= sizeof(prepared->wire) - (size_t)length) return false;
    prepared->length = (size_t)length + (size_t)suffix;
    return true;
}
static bool authorize(const char *operation, const void *payload, size_t payload_length) {
    char exe_hash[65], library_hash[65], threats[128];
    unsigned flags = scan(exe_hash, library_hash);
    threats_text(flags, threats);
    if (flags) report("threat", threats);
    if (!config.endpoint[0]) return flags == 0;
    struct prepared_evidence prepared;
    if (!prepare_evidence(operation, payload, payload_length, exe_hash, library_hash, threats, &prepared)) return false;
    char decision[DOCUMENT_MAX];
    if (!http_post("/v1/authorize", prepared.wire, prepared.length, decision, sizeof(decision))) { report("failure", "backendAuthorize"); return false; }
    bool ok = signed_decision(decision, prepared.nonce, prepared.hash);
    if (!ok) report("failure", "backendDecision");
    return ok && flags == 0;
}
static bool check_locked(const char *operation, const void *payload, size_t length) {
    /* A fork may inherit a locked mutex with no owner thread. Multiprocess
     * protection is unsupported; reject before touching that inherited lock. */
    if (getpid() != owner_pid) { report("failure", "unsupportedFork"); return false; }
    pthread_mutex_lock(&authorization_lock);
    bool ok = authorize(operation, payload, length);
    pthread_mutex_unlock(&authorization_lock);
    return ok;
}
__attribute__((visibility("default"))) int rasp_checkpoint(const void *payload, size_t length) {
    if (!atomic_load_explicit(&initialized, memory_order_acquire) || (!payload && length)) { errno = EINVAL; return -1; }
    if (!check_locked("checkpoint", payload ? payload : "", length)) { errno = EACCES; return -1; }
    return 0;
}
__attribute__((visibility("default"))) int rasp_prepare_request(const void *payload, size_t length, char *evidence, size_t capacity) {
    if (evidence && capacity) evidence[0] = '\0';
    if (!atomic_load_explicit(&initialized, memory_order_acquire) || (!payload && length) || !evidence || !capacity) { errno = EINVAL; return -1; }
    if (getpid() != owner_pid) { report("failure", "unsupportedFork"); errno = EACCES; return -1; }
    if (!config.endpoint[0]) { errno = ENOTSUP; return -1; }
    pthread_mutex_lock(&authorization_lock);
    char exe_hash[65], library_hash[65], threats[128];
    unsigned flags = scan(exe_hash, library_hash);
    threats_text(flags, threats);
    if (flags) report("threat", threats);
    struct prepared_evidence prepared;
    bool ok = flags == 0 && prepare_evidence("checkpoint", payload ? payload : "", length, exe_hash, library_hash, threats, &prepared);
    int result = -1, error = EACCES;
    if (ok) {
        if (prepared.length >= capacity) error = EMSGSIZE;
        else { memcpy(evidence, prepared.wire, prepared.length + 1); result = (int)prepared.length; }
    }
    pthread_mutex_unlock(&authorization_lock);
    if (result < 0) errno = error;
    return result;
}
__attribute__((visibility("default"))) int connect(int fd, const struct sockaddr *address, socklen_t length) {
    connect_function real_connect = atomic_load_explicit(&original_connect, memory_order_acquire);
    if (!real_connect) { errno = EACCES; return -1; }
    if (transport_bypass || !atomic_load_explicit(&initialized, memory_order_acquire)) return real_connect(fd, address, length);
    if (address && length >= sizeof(sa_family_t) && (address->sa_family == AF_INET || address->sa_family == AF_INET6)) {
        int type = 0;
        socklen_t type_length = sizeof(type);
        if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &type_length) != 0) return -1;
        if (type == SOCK_STREAM) {
            size_t minimum = address->sa_family == AF_INET ? sizeof(struct sockaddr_in) : offsetof(struct sockaddr_in6, sin6_scope_id);
            if (length < minimum || length > sizeof(struct sockaddr_storage)) { errno = EINVAL; return -1; }
            if (!check_locked("connect", address, length)) fatal("connectDenied");
        }
    }
    return real_connect(fd, address, length);
}
static void *monitor(void *unused) {
    (void)unused;
    struct timespec interval = {.tv_sec = config.interval_ms / 1000, .tv_nsec = (long)(config.interval_ms % 1000) * 1000000};
    for (;;) {
        struct timespec remaining = interval;
        while (nanosleep(&remaining, &remaining) != 0 && errno == EINTR) {}
        if (!check_locked("monitor", "", 0)) fatal("monitorDenied");
    }
    return NULL;
}
__attribute__((constructor)) static void initialize(void) {
    /* dlsym's POSIX function-pointer conversion avoids aliasing assumptions. */
    void *symbol = dlsym(RTLD_NEXT, "connect");
    connect_function real_connect;
    memcpy(&real_connect, &symbol, sizeof(real_connect));
    if (!real_connect) fatal("connectResolver");
    atomic_store_explicit(&original_connect, real_connect, memory_order_release);
    owner_pid = getpid();
    ssize_t length = readlink("/proc/self/exe", executable_path, sizeof(executable_path) - 1);
    if (length <= 0 || (size_t)length >= sizeof(executable_path) - 1) fatal("executablePath");
    executable_path[length] = '\0';
    Dl_info library;
    if (!dladdr((void *)&initialize, &library) || !library.dli_fname || !realpath(library.dli_fname, runtime_path)) fatal("runtimePath");
    char *slash = strrchr(executable_path, '/');
    if (!slash || (size_t)(slash - executable_path) + sizeof("/rasp.manifest") > sizeof(manifest_path)) fatal("manifestPath");
    memcpy(manifest_path, executable_path, (size_t)(slash - executable_path));
    strcpy(manifest_path + (slash - executable_path), "/rasp.manifest");
    if (!load_manifest()) fatal("invalidManifest");
    if (!check_locked("startup", "", 0)) fatal("startupDenied");
    atomic_store_explicit(&initialized, true, memory_order_release);
    pthread_t thread;
    if (pthread_create(&thread, NULL, monitor, NULL) != 0) fatal("monitorStart");
    if (pthread_detach(thread) != 0) fatal("monitorStart");
}
