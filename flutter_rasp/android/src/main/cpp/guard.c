#include "guard.h"

#include <string.h>

static const char MESH_SEED[] = "raxp/guard-mesh/v1";

void rasp_guard_root(const rasp_region_t *regions, size_t count, uint8_t out[RASP_SHA256_DIGEST_LEN]) {
    uint8_t acc[RASP_SHA256_DIGEST_LEN];
    rasp_sha256((const uint8_t *)MESH_SEED, sizeof(MESH_SEED) - 1, acc);

    for (size_t i = 0; i < count; i++) {
        uint8_t digest[RASP_SHA256_DIGEST_LEN];
        rasp_sha256(regions[i].data, regions[i].len, digest);

        /* acc = SHA256(acc || SHA256(region)) */
        uint8_t block[RASP_SHA256_DIGEST_LEN * 2];
        memcpy(block, acc, RASP_SHA256_DIGEST_LEN);
        memcpy(block + RASP_SHA256_DIGEST_LEN, digest, RASP_SHA256_DIGEST_LEN);
        rasp_sha256(block, sizeof(block), acc);
    }
    memcpy(out, acc, RASP_SHA256_DIGEST_LEN);
}

uint64_t rasp_guard_offset(const rasp_region_t *regions, size_t count, uint64_t modulus) {
    uint8_t root[RASP_SHA256_DIGEST_LEN];
    rasp_guard_root(regions, count, root);
    uint64_t value = 0;
    for (int i = 0; i < 8; i++) {
        value = (value << 8) | root[i];
    }
    return modulus ? value % modulus : 0;
}
