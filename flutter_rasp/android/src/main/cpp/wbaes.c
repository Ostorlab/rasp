#include "wbaes.h"

#include <string.h>

/* Row r is cyclically left-shifted by r; column-major flat layout, (r,c) at index c*4+r. */
static void shift_rows(const uint8_t *s, uint8_t *out) {
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            out[c * 4 + r] = s[((c + r) % 4) * 4 + r];
        }
    }
}

void rasp_wbaes_encrypt_block(const uint32_t *type2, const uint8_t *last,
                              const uint8_t in[16], uint8_t out[16]) {
    uint8_t state[16];
    uint8_t x[16];
    memcpy(state, in, 16);

    for (int r = 0; r < 9; r++) {
        shift_rows(state, x);
        for (int c = 0; c < 4; c++) {
            uint32_t acc = 0;
            for (int i = 0; i < 4; i++) {
                int p = c * 4 + i;
                acc ^= type2[((size_t)(r * 16 + p)) * 256 + x[p]];
            }
            state[c * 4 + 0] = (uint8_t)(acc >> 24);
            state[c * 4 + 1] = (uint8_t)(acc >> 16);
            state[c * 4 + 2] = (uint8_t)(acc >> 8);
            state[c * 4 + 3] = (uint8_t)(acc);
        }
    }

    shift_rows(state, x);
    for (int p = 0; p < 16; p++) {
        state[p] = last[(size_t)p * 256 + x[p]];
    }
    memcpy(out, state, 16);
}

void rasp_wbaes_ctr(const uint32_t *type2, const uint8_t *last, const uint8_t nonce[12],
                    const uint8_t *in, size_t len, uint8_t *out) {
    uint8_t counter_block[16];
    uint8_t keystream[16];
    memcpy(counter_block, nonce, 12);

    uint32_t counter = 0;
    size_t offset = 0;
    while (offset < len) {
        counter_block[12] = (uint8_t)(counter >> 24);
        counter_block[13] = (uint8_t)(counter >> 16);
        counter_block[14] = (uint8_t)(counter >> 8);
        counter_block[15] = (uint8_t)(counter);
        rasp_wbaes_encrypt_block(type2, last, counter_block, keystream);

        size_t chunk = len - offset < 16 ? len - offset : 16;
        for (size_t i = 0; i < chunk; i++) {
            out[offset + i] = (uint8_t)(in[offset + i] ^ keystream[i]);
        }
        offset += chunk;
        counter++;
    }
}
