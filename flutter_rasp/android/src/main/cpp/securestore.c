#include "securestore.h"

#include <string.h>

#include "wbaes.h"

int rasp_secure_store_seal(const uint32_t *type2, const uint8_t *last,
                           const uint8_t nonce[RASP_SECURESTORE_NONCE_LEN], const uint8_t *plain,
                           size_t len, uint8_t *out) {
    if (type2 == NULL || last == NULL || nonce == NULL || out == NULL || (plain == NULL && len > 0)) {
        return -1;
    }
    memcpy(out, nonce, RASP_SECURESTORE_NONCE_LEN);
    rasp_wbaes_ctr(type2, last, nonce, plain, len, out + RASP_SECURESTORE_NONCE_LEN);
    return (int)(len + RASP_SECURESTORE_OVERHEAD);
}

int rasp_secure_store_open(const uint32_t *type2, const uint8_t *last, const uint8_t *sealed,
                           size_t sealed_len, uint8_t *out) {
    if (type2 == NULL || last == NULL || sealed == NULL || sealed_len < RASP_SECURESTORE_OVERHEAD) {
        return -1;
    }
    size_t len = sealed_len - RASP_SECURESTORE_OVERHEAD;
    rasp_wbaes_ctr(type2, last, sealed, sealed + RASP_SECURESTORE_NONCE_LEN, len, out);
    return (int)len;
}
