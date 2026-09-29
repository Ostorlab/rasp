#ifndef RASP_STROBF_H
#define RASP_STROBF_H

#include "hardening.h"
#include "literals.h"

#include <stddef.h>
#include <stdint.h>

#define RASP_STRING_KEY_LEN 32

/* Decodes a build-encrypted string literal (see the hardener's strenc.py and the generated build_seed.h) into
 * `out`, which must hold at least `len + 1` bytes. `out` is NUL-terminated. `idx` is the string's table slot
 * and `key` is the per-build key stream (RASP_STRING_KEY_LEN bytes).
 *
 * The transform is a keyed rolling XOR and is its own inverse. It MUST stay byte-identical with strenc.py's
 * `obfuscate`; the cross-language test compiles this against a generated header and asserts the round trip. */
void rasp_strobf_decode(const uint8_t *cipher, size_t len, int idx, const uint8_t *key, char *out);

#endif
