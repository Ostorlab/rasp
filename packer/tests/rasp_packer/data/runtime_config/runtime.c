/* A stand-in for the runtime's binary in the packer's tests: it reserves the space for the config as the runtime does
 * (runtime/core/src/embedded_config.cpp), in its own section, starting as `{}`. On Android it also carries stand-in
 * `.packmeta` and `.stubcode` sections, so the packer's self-encryption step (android/self_encrypt.py) has the sections
 * it needs; see runtime/android/src/selfdecrypt for the real ones. */

#ifdef __APPLE__
__attribute__((section("__DATA,__rasp_config"), used))
#else
__attribute__((section(".rasp_config"), used))
#endif
volatile char embedded_config[4096] = "{}";

const volatile char* config(void) { return embedded_config; }

#ifndef __APPLE__
/* The self-decrypt metadata space (sizeof(rasp::android::selfdecrypt::Meta): a 14-word header and 64 region entries of
 * 32 bytes each), starting unpacked (all zero). */
__attribute__((section(".packmeta"), used, aligned(16))) volatile unsigned char embedded_packmeta[2104] = {0};

/* A stand-in for the clear self-decrypt bootstrap, so the packer has a .stubcode section to hash. */
__attribute__((section(".stubcode"), used)) void stubcode(void) {}
#endif
