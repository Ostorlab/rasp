#include "strobf.h"

void rasp_strobf_decode(const uint8_t *cipher, size_t len, int idx, const uint8_t *key, char *out) {
    /* Volatile reads keep whole-program optimization from folding decoded literals back into .rodata. */
    const volatile uint8_t *encoded = cipher;
    const volatile uint8_t *stream = key;
    for (size_t i = 0; i < len; i++) {
        /* Mirrors strenc._keybyte: key[(idx*7 + i) % 32] ^ ((idx + i) & 0xFF). */
        uint8_t k = (uint8_t)(stream[((size_t)idx * 7 + i) % RASP_STRING_KEY_LEN] ^
                              (uint8_t)((idx + (int)i) & 0xFF));
        out[i] = (char)(encoded[i] ^ k);
    }
    out[len] = '\0';
}
