#ifndef RASP_SHA256_H
#define RASP_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define RASP_SHA256_DIGEST_LEN 32

/* Self-contained SHA-256 and HMAC-SHA256. The NDK ships no crypto library, and the sealed report must be
 * MAC'd inside the native core with the per-build key, so the primitive lives here. */

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t buffer[64];
    size_t buffer_len;
} rasp_sha256_ctx;

void rasp_sha256_init(rasp_sha256_ctx *ctx);
void rasp_sha256_update(rasp_sha256_ctx *ctx, const uint8_t *data, size_t len);
void rasp_sha256_final(rasp_sha256_ctx *ctx, uint8_t out[RASP_SHA256_DIGEST_LEN]);

void rasp_sha256(const uint8_t *data, size_t len, uint8_t out[RASP_SHA256_DIGEST_LEN]);

void rasp_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
                      uint8_t out[RASP_SHA256_DIGEST_LEN]);

/* Writes `len` bytes of `data` as lowercase hex into `out` (needs 2*len+1 bytes). */
void rasp_hex_encode(const uint8_t *data, size_t len, char *out);

#endif
