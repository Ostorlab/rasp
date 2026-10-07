#include "securestore.h"

#include <string.h>

#include "wbaes.h"

/* Constant-time equality: returns 1 if the `n` bytes match, 0 otherwise (no early exit on the tag compare). */
static int ct_equal(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

int rasp_secure_store_seal(const uint32_t *type2, const uint8_t *last,
                           const uint8_t nonce[RASP_SECURESTORE_NONCE_LEN], const uint8_t *plain,
                           size_t len, uint8_t *out) {
    if (type2 == NULL || last == NULL || nonce == NULL || out == NULL || (plain == NULL && len > 0)) {
        return -1;
    }
    memcpy(out, nonce, RASP_SECURESTORE_NONCE_LEN);
    rasp_wbaes_ctr(type2, last, nonce, plain, len, out + RASP_SECURESTORE_NONCE_LEN);
    /* Tag over nonce || ciphertext = out[0 .. NONCE_LEN + len). */
    rasp_wbaes_cmac(type2, last, out, RASP_SECURESTORE_NONCE_LEN + len,
                    out + RASP_SECURESTORE_NONCE_LEN + len);
    return (int)(len + RASP_SECURESTORE_OVERHEAD);
}

int rasp_secure_store_open(const uint32_t *type2, const uint8_t *last, const uint8_t *sealed,
                           size_t sealed_len, uint8_t *out) {
    if (type2 == NULL || last == NULL || sealed == NULL || sealed_len < RASP_SECURESTORE_OVERHEAD) {
        return -1;
    }
    size_t body_len = sealed_len - RASP_SECURESTORE_TAG_LEN;  /* nonce || ciphertext */
    size_t len = body_len - RASP_SECURESTORE_NONCE_LEN;       /* plaintext */

    uint8_t tag[RASP_SECURESTORE_TAG_LEN];
    rasp_wbaes_cmac(type2, last, sealed, body_len, tag);
    if (ct_equal(tag, sealed + body_len, RASP_SECURESTORE_TAG_LEN) == 0) {
        return -1;  /* integrity failure: do not decrypt */
    }
    rasp_wbaes_ctr(type2, last, sealed, sealed + RASP_SECURESTORE_NONCE_LEN, len, out);
    return (int)len;
}
