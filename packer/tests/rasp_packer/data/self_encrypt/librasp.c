/* A stand-in for the runtime library in the self-encryption tests (packer/tests/rasp_packer/android/self_encrypt_test.py).
 * It has every section the packer's android/self_encrypt.py reads or encrypts, shaped as the real runtime's linker
 * makes them: the bootstrap's clear .stubcode and its unpacked .packmeta (the size of rasp::android::selfdecrypt::Meta),
 * code in .text, constants in .rodata, a table of pointers in .data.rel.ro that packed relative relocations patch at
 * load, unwind tables in .eh_frame and .eh_frame_hdr, and a soname. */

__attribute__((section(".packmeta"), used, aligned(16))) volatile unsigned char packmeta[2140] = {0};

__attribute__((section(".stubcode"), used)) int stubcode(int value) { return (value * 3) + 1; }

static const unsigned char kTable[64] = {
    3,  1,  4,  1,  5,  9,  2,  6,  5,  3,  5,  8,  9,  7,  9,  3,  2,  3,  8,  4,  6,  2,
    6,  4,  3,  3,  8,  3,  2,  7,  9,  5,  0,  2,  8,  8,  4,  1,  9,  7,  1,  6,  9,  3,
    9,  9,  3,  7,  5,  1,  0,  5,  8,  2,  0,  9,  7,  4,  9,  4,  4,  5,  9,  2,
};

__attribute__((used)) const char* const names[] = {"root.fs_paths", "dbg.tracer_pid", "hook.maps_hits",
                                                  "mitm.tunnels"};

const char* name_at(int index) { return names[index & 3]; }

int checksum(int seed) {
  int sum = seed;
  for (int i = 0; i < 64; i++) {
    sum = (sum * 31) + kTable[i];
  }
  return sum;
}
