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

static void wbaes_shl1(const uint8_t in[16], uint8_t out[16]) {
    uint8_t carry = 0;
    for (int i = 15; i >= 0; i--) {
        uint8_t b = in[i];
        out[i] = (uint8_t)((b << 1) | carry);
        carry = (uint8_t)((b >> 7) & 1);
    }
}

static void wbaes_xor16(const uint8_t a[16], const uint8_t b[16], uint8_t out[16]) {
    for (int i = 0; i < 16; i++) {
        out[i] = (uint8_t)(a[i] ^ b[i]);
    }
}

void rasp_wbaes_cmac(const uint32_t *type2, const uint8_t *last, const uint8_t *msg, size_t len,
                     uint8_t tag[16]) {
    /* Subkeys K1, K2 from E(0^128), per RFC 4493 (Rb = 0x87 on the last byte). */
    uint8_t zero[16] = {0};
    uint8_t l[16], k1[16], k2[16];
    rasp_wbaes_encrypt_block(type2, last, zero, l);
    wbaes_shl1(l, k1);
    if (l[0] & 0x80) {
        k1[15] ^= 0x87;
    }
    wbaes_shl1(k1, k2);
    if (k1[0] & 0x80) {
        k2[15] ^= 0x87;
    }

    size_t blocks = (len + 15) / 16;
    if (blocks == 0) {
        blocks = 1;
    }
    size_t last_off = (blocks - 1) * 16;
    uint8_t last_block[16];
    if (len > 0 && (len % 16) == 0) {
        wbaes_xor16(msg + last_off, k1, last_block);
    } else {
        uint8_t padded[16] = {0};
        size_t rem = len - last_off;
        if (rem > 0) {
            memcpy(padded, msg + last_off, rem);
        }
        padded[rem] = 0x80;
        wbaes_xor16(padded, k2, last_block);
    }

    uint8_t x[16] = {0};
    for (size_t i = 0; i + 1 < blocks; i++) {
        uint8_t tmp[16];
        wbaes_xor16(x, msg + i * 16, tmp);
        rasp_wbaes_encrypt_block(type2, last, tmp, x);
    }
    uint8_t tmp[16];
    wbaes_xor16(x, last_block, tmp);
    rasp_wbaes_encrypt_block(type2, last, tmp, tag);
}

int rasp_wbaes_encrypt_block_checked(const uint32_t *type2_a, const uint8_t *last_a,
                                    const uint32_t *type2_b, const uint8_t *last_b,
                                    const uint8_t in[16], uint8_t out[16]) {
    if (!type2_a || !last_a || !type2_b || !last_b || !in || !out) return -1;
    uint8_t first[16], second[16];
    rasp_wbaes_encrypt_block(type2_a, last_a, in, first);
    rasp_wbaes_encrypt_block(type2_b, last_b, in, second);
    uint8_t difference = 0;
    for (size_t i = 0; i < 16; i++) difference |= first[i] ^ second[i];
    if (difference == 0) memcpy(out, first, 16);
    volatile uint8_t *wipe_first = first, *wipe_second = second;
    for (size_t i = 0; i < 16; i++) { wipe_first[i] = 0; wipe_second[i] = 0; }
    return difference == 0 ? 0 : -1;
}
