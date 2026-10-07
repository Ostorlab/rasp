#include "integrity.h"

#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static const char MESH_SEED[] = "raxp/guard-mesh/v1";

/* SHA-256 over `length` bytes at `offset` of `fd`, streamed. Returns 0, or -1 on a short/failed read. */
static int hash_region(int fd, uint64_t offset, uint64_t length, uint8_t digest[RASP_SHA256_DIGEST_LEN]) {
    rasp_sha256_ctx ctx;
    rasp_sha256_init(&ctx);
    uint8_t buf[4096];
    uint64_t remaining = length;
    while (remaining > 0) {
        size_t want = remaining < sizeof(buf) ? (size_t)remaining : sizeof(buf);
        ssize_t n = pread(fd, buf, want, (off_t)offset);
        if (n <= 0) {
            return -1;
        }
        rasp_sha256_update(&ctx, buf, (size_t)n);
        offset += (uint64_t)n;
        remaining -= (uint64_t)n;
    }
    rasp_sha256_final(&ctx, digest);
    return 0;
}

int rasp_integrity_root_from_file(const char *path, const rasp_file_region_t *regions, size_t count,
                                  uint8_t out[RASP_SHA256_DIGEST_LEN]) {
    if (path == NULL || (regions == NULL && count > 0)) {
        return -1;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }

    uint8_t acc[RASP_SHA256_DIGEST_LEN];
    rasp_sha256((const uint8_t *)MESH_SEED, sizeof(MESH_SEED) - 1, acc);

    int rc = 0;
    for (size_t i = 0; i < count; i++) {
        uint8_t digest[RASP_SHA256_DIGEST_LEN];
        if (hash_region(fd, regions[i].offset, regions[i].length, digest) != 0) {
            rc = -1;
            break;
        }
        uint8_t block[RASP_SHA256_DIGEST_LEN * 2];
        memcpy(block, acc, RASP_SHA256_DIGEST_LEN);
        memcpy(block + RASP_SHA256_DIGEST_LEN, digest, RASP_SHA256_DIGEST_LEN);
        rasp_sha256(block, sizeof(block), acc);
    }

    close(fd);
    if (rc == 0) {
        memcpy(out, acc, RASP_SHA256_DIGEST_LEN);
    }
    return rc;
}
