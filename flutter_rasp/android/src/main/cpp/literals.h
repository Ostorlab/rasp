#ifndef RASP_LITERALS_H
#define RASP_LITERALS_H

#include "hardening.h"

/* Protected literals (design §6 obfuscation). literals.def is the single source of truth; in a dev build
 * it expands to plaintext, in a hardened build rasp_lit_decode decrypts the per-build table emitted in
 * build_seed.h (see hardener/rasp_hardener/literals.py and the RASP_LIT call sites). */

enum {
#define RASP_LITERAL(name, text) RASP_SLOT_##name,
#include "literals.def"
#undef RASP_LITERAL
    RASP_SLOT_COUNT
};

#ifndef RASP_LIT_MAXLEN
#define RASP_LIT_MAXLEN 256
#endif

/* Decodes slot into `out`, which must hold at least RASP_LIT_MAXLEN + 1 bytes; `out` is NUL-terminated. */
void rasp_lit_decode(int slot, char *out);

/* Declares `var` as a stack buffer holding literal `name`, decoded. Block scope only (two statements). */
#define RASP_LIT(name, var) \
    char var[RASP_LIT_MAXLEN + 1]; \
    rasp_lit_decode(RASP_SLOT_##name, var)

#endif
