#define RASP_LITERALS_IMPL 1

#include "literals.h"

#include <string.h>

#include "strobf.h"

/* Hardened build: the encrypted table and key come from build_seed.h (included above with the impl macro
 * set, so the static tables live only in this translation unit). Dev build: the registry expands to a
 * plaintext table; dev binaries are not the artifact the gates protect. */
#if defined(__has_include)
#if __has_include("build_seed.h")
#include "build_seed.h"
#define RASP_LITERALS_HARDENED 1
#endif
#endif

#ifndef RASP_LITERALS_HARDENED
#define RASP_LITERAL(name, text) text,
static const char *const r_lits[RASP_SLOT_COUNT] = {
#include "literals.def"
};
#undef RASP_LITERAL
#endif

void rasp_lit_decode(int slot, char *out) {
    if (slot < 0 || slot >= RASP_SLOT_COUNT) {
        out[0] = '\0';
        return;
    }
#ifdef RASP_LITERALS_HARDENED
    rasp_strobf_decode(r_lits[slot], r_lit_lens[slot], slot, r_lkey, out);
#else
    strncpy(out, r_lits[slot], RASP_LIT_MAXLEN);
    out[RASP_LIT_MAXLEN] = '\0';
#endif
}
