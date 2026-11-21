/* A stand-in for the runtime's binary in the packer's tests. On iOS it reserves the config space in its own section,
 * starting as `{}`. On Android it carries the slots the packer writes the per-app values into, each starting with its
 * marker, and stand-in `.packmeta` and `.stubcode` sections for the self-encryption step. */

#ifdef __APPLE__
__attribute__((section("__DATA,__rasp_config"), used)) volatile char embedded_config[4096] = "{}";

const volatile char* config(void) { return embedded_config; }
#else
#define SLOT_MAGIC 0x9c, 'R', 'A', 'S', 'P', 'S', 'L', 'T'

const volatile unsigned char build_slot[128] = {SLOT_MAGIC, 'b', 'u', 'i', 'l', 'd'};
const volatile unsigned char checks_slot[16] = {SLOT_MAGIC, 'c', 'h', 'e', 'c', 'k', 's'};
const volatile unsigned char program_slot[512] = {SLOT_MAGIC, 'p', 'r', 'o', 'g', 'r', 'a', 'm'};
const volatile unsigned char digest_slot[32] = {SLOT_MAGIC, 'd', 'i', 'g', 'e', 's', 't'};
const volatile unsigned char pad_slot[32] = {SLOT_MAGIC, 'p', 'a', 'd'};
const volatile unsigned char decoy0_slot[32] = {SLOT_MAGIC, 'd', 'e', 'c', 'o', 'y', '0'};
const volatile unsigned char decoy1_slot[32] = {SLOT_MAGIC, 'd', 'e', 'c', 'o', 'y', '1'};
const volatile unsigned char decoy2_slot[32] = {SLOT_MAGIC, 'd', 'e', 'c', 'o', 'y', '2'};
volatile unsigned char share_slot[32] = {SLOT_MAGIC, 's', 'h', 'a', 'r', 'e'};

unsigned char slots(void) {
  return build_slot[0] ^ checks_slot[0] ^ program_slot[0] ^ digest_slot[0] ^ pad_slot[0] ^ decoy0_slot[0] ^
         decoy1_slot[0] ^ decoy2_slot[0] ^ share_slot[0];
}

/* The self-decrypt metadata space (sizeof(rasp::android::selfdecrypt::Meta): a 15-word header, the 32-byte expected
 * plaintext .text digest, and 64 region entries of 28 bytes each), starting unpacked (all zero). */
__attribute__((section(".packmeta"), used, aligned(16))) volatile unsigned char embedded_packmeta[2104] = {0};

/* A stand-in for the clear self-decrypt bootstrap, so the packer has a .stubcode section to hash. */
__attribute__((section(".stubcode"), used)) void stubcode(void) {}
#endif
