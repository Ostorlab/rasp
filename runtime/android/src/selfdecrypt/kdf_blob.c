/// The key-derivation routine, compiled SEPARATELY and never linked into the shipped library. gen_kdf_shovel.py
/// compiles this for the target, extracts the machine code of kdf_blob() (verified relocation-free and self-contained),
/// and emits a builder that materialises those bytes as immediate stores into an RWX page at run time (see
/// selfdecrypt.cpp). So in the shipped library the HKDF/SHA-256 logic is NOT present as disassemblable .text: a static
/// disassembler sees the builder shovelling constants, not the round function.
///
/// To stay self-contained the blob references nothing outside itself: no libc (hand-rolled byte copy/set), no globals,
/// no string or constant tables (the SHA-256 round constants are materialised by assignment, not a .rodata table). That
/// is what makes its bytes position-independent and copyable to any page. It must be compiled with vectorization off
/// (and -mno-sse on x86) so no SIMD constant pool is spilled to .rodata; gen_kdf_shovel.py uses those flags and refuses
/// to proceed if the result is not relocation-free.
///
/// The crypto is unchanged and vetted: Brad Conte's public-domain SHA-256 core (https://github.com/B-Con/crypto-
/// algorithms), HMAC per RFC 2104, HKDF per RFC 5869. kdf_blob computes, byte-for-byte like the packer and the host
/// test: out = HKDF-SHA256(salt = SHA256(stub[0..stublen]), ikm = ikm[0..32], info = "", length = 32).

#include <stddef.h>
#include <stdint.h>

/// Copy `n` bytes from `s` to `d` (no libc).
static void b_copy(uint8_t* d, const uint8_t* s, unsigned long n) {
  for (unsigned long i = 0; i < n; i++) {
    d[i] = s[i];
  }
}

/// Set `n` bytes of `d` to `v` (no libc).
static void b_set(uint8_t* d, uint8_t v, unsigned long n) {
  for (unsigned long i = 0; i < n; i++) {
    d[i] = v;
  }
}

#define KB_ROTR(a, b) (((a) >> (b)) | ((a) << (32 - (b))))
#define KB_CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define KB_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define KB_EP0(x) (KB_ROTR(x, 2) ^ KB_ROTR(x, 13) ^ KB_ROTR(x, 22))
#define KB_EP1(x) (KB_ROTR(x, 6) ^ KB_ROTR(x, 11) ^ KB_ROTR(x, 25))
#define KB_SIG0(x) (KB_ROTR(x, 7) ^ KB_ROTR(x, 18) ^ ((x) >> 3))
#define KB_SIG1(x) (KB_ROTR(x, 17) ^ KB_ROTR(x, 19) ^ ((x) >> 10))

/// Fill `k` with the 64 SHA-256 round constants by assignment (no table).
static void kb_round_constants(uint32_t k[64]) {
  k[0] = 0x428a2f98u;
  k[1] = 0x71374491u;
  k[2] = 0xb5c0fbcfu;
  k[3] = 0xe9b5dba5u;
  k[4] = 0x3956c25bu;
  k[5] = 0x59f111f1u;
  k[6] = 0x923f82a4u;
  k[7] = 0xab1c5ed5u;
  k[8] = 0xd807aa98u;
  k[9] = 0x12835b01u;
  k[10] = 0x243185beu;
  k[11] = 0x550c7dc3u;
  k[12] = 0x72be5d74u;
  k[13] = 0x80deb1feu;
  k[14] = 0x9bdc06a7u;
  k[15] = 0xc19bf174u;
  k[16] = 0xe49b69c1u;
  k[17] = 0xefbe4786u;
  k[18] = 0x0fc19dc6u;
  k[19] = 0x240ca1ccu;
  k[20] = 0x2de92c6fu;
  k[21] = 0x4a7484aau;
  k[22] = 0x5cb0a9dcu;
  k[23] = 0x76f988dau;
  k[24] = 0x983e5152u;
  k[25] = 0xa831c66du;
  k[26] = 0xb00327c8u;
  k[27] = 0xbf597fc7u;
  k[28] = 0xc6e00bf3u;
  k[29] = 0xd5a79147u;
  k[30] = 0x06ca6351u;
  k[31] = 0x14292967u;
  k[32] = 0x27b70a85u;
  k[33] = 0x2e1b2138u;
  k[34] = 0x4d2c6dfcu;
  k[35] = 0x53380d13u;
  k[36] = 0x650a7354u;
  k[37] = 0x766a0abbu;
  k[38] = 0x81c2c92eu;
  k[39] = 0x92722c85u;
  k[40] = 0xa2bfe8a1u;
  k[41] = 0xa81a664bu;
  k[42] = 0xc24b8b70u;
  k[43] = 0xc76c51a3u;
  k[44] = 0xd192e819u;
  k[45] = 0xd6990624u;
  k[46] = 0xf40e3585u;
  k[47] = 0x106aa070u;
  k[48] = 0x19a4c116u;
  k[49] = 0x1e376c08u;
  k[50] = 0x2748774cu;
  k[51] = 0x34b0bcb5u;
  k[52] = 0x391c0cb3u;
  k[53] = 0x4ed8aa4au;
  k[54] = 0x5b9cca4fu;
  k[55] = 0x682e6ff3u;
  k[56] = 0x748f82eeu;
  k[57] = 0x78a5636fu;
  k[58] = 0x84c87814u;
  k[59] = 0x8cc70208u;
  k[60] = 0x90befffau;
  k[61] = 0xa4506cebu;
  k[62] = 0xbef9a3f7u;
  k[63] = 0xc67178f2u;
}

/// Compress one 64-byte block into the eight-word state `s`.
static void kb_transform(uint32_t s[8], const uint8_t data[64]) {
  uint32_t k[64];
  kb_round_constants(k);
  uint32_t m[64];
  for (int i = 0, j = 0; i < 16; ++i, j += 4) {
    m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j + 1] << 16) | ((uint32_t)data[j + 2] << 8) |
           ((uint32_t)data[j + 3]);
  }
  for (int i = 16; i < 64; ++i) {
    m[i] = KB_SIG1(m[i - 2]) + m[i - 7] + KB_SIG0(m[i - 15]) + m[i - 16];
  }
  uint32_t a = s[0], b = s[1], c = s[2], d = s[3];
  uint32_t e = s[4], f = s[5], g = s[6], h = s[7];
  for (int i = 0; i < 64; ++i) {
    uint32_t t1 = h + KB_EP1(e) + KB_CH(e, f, g) + k[i] + m[i];
    uint32_t t2 = KB_EP0(a) + KB_MAJ(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  s[0] += a;
  s[1] += b;
  s[2] += c;
  s[3] += d;
  s[4] += e;
  s[5] += f;
  s[6] += g;
  s[7] += h;
}

/// De-obfuscates one SHA-256 state word: `obfuscated ^ mask`. The volatile local prevents the
/// compiler from folding the XOR back to the standard IV at compile time, so the generated code
/// carries both the obfuscated value and the mask as separate immediates, and the standard IV
/// never appears in the instruction stream. A dump of the runtime-generated page shows two
/// random-looking constants being XORed, not a recognizable SHA-256 IV.
static uint32_t kb_dexor(uint32_t obfuscated, uint32_t mask) {
  volatile uint32_t m = mask;
  return obfuscated ^ m;
}

/// One-shot SHA-256 of `data[0..len)` into `out[32]`.
static void kb_sha256(const uint8_t* data, unsigned long len, uint8_t out[32]) {
  uint32_t s[8];
  // Standard SHA-256 IVs, XOR-obfuscated: each pair of constants XORs to the standard value.
  // The values and masks are fixed source literals; gen_kdf_shovel.py compiles them unchanged.
  s[0] = kb_dexor(0x5573fa39u, 0x3f7a1c5eu);  // 0x6a09e667
  s[1] = kb_dexor(0xd64925cfu, 0x6d2e8b4au);  // 0xbb67ae85
  s[2] = kb_dexor(0xb074ad49u, 0x8c1a5e3bu);  // 0x3c6ef372
  s[3] = kb_dexor(0x8f34b825u, 0x2a7b4d1fu);  // 0xa54ff53a
  s[4] = kb_dexor(0x0f926854u, 0x5e9c3a2bu);  // 0x510e527f
  s[5] = kb_dexor(0x864f14e2u, 0x1d4a7c6eu);  // 0x9b05688c
  s[6] = kb_dexor(0x84ad8691u, 0x9b2e5f3au);  // 0x1f83d9ab
  s[7] = kb_dexor(0x178ad067u, 0x4c6a1d7eu);  // 0x5be0cd19

  unsigned long full = len / 64;
  for (unsigned long b = 0; b < full; b++) {
    kb_transform(s, data + b * 64);
  }

  uint8_t block[64];
  unsigned long rem = len - full * 64;
  b_copy(block, data + full * 64, rem);
  block[rem] = 0x80;
  if (rem >= 56) {
    b_set(block + rem + 1, 0, 64 - rem - 1);
    kb_transform(s, block);
    b_set(block, 0, 56);
  } else {
    b_set(block + rem + 1, 0, 56 - rem - 1);
  }
  uint64_t bits = (uint64_t)len * 8;
  for (int i = 0; i < 8; i++) {
    block[63 - i] = (uint8_t)(bits >> (8 * i));
  }
  kb_transform(s, block);

  for (int i = 0; i < 8; i++) {
    out[i * 4 + 0] = (uint8_t)(s[i] >> 24);
    out[i * 4 + 1] = (uint8_t)(s[i] >> 16);
    out[i * 4 + 2] = (uint8_t)(s[i] >> 8);
    out[i * 4 + 3] = (uint8_t)(s[i]);
  }
}

/// HMAC-SHA256 of `msg` keyed by `key` (key_len <= 64), into `out[32]`.
static void kb_hmac(const uint8_t* key, unsigned long key_len, const uint8_t* msg, unsigned long msg_len,
                    uint8_t out[32]) {
  uint8_t k0[64];
  b_set(k0, 0, 64);
  b_copy(k0, key, key_len);

  uint8_t inner_in[64 + 64];
  for (int i = 0; i < 64; i++) {
    inner_in[i] = (uint8_t)(k0[i] ^ 0x36);
  }
  b_copy(inner_in + 64, msg, msg_len);
  uint8_t inner[32];
  kb_sha256(inner_in, 64 + msg_len, inner);

  uint8_t outer_in[64 + 32];
  for (int i = 0; i < 64; i++) {
    outer_in[i] = (uint8_t)(k0[i] ^ 0x5c);
  }
  b_copy(outer_in + 64, inner, 32);
  kb_sha256(outer_in, 64 + 32, out);
}

/// The derivation. out = HKDF-SHA256(salt = SHA256(stub), ikm, info = "", 32): PRK = HMAC(salt, ikm); OKM = HMAC(PRK,
/// 0x01). Reached only via the run-time builder, never present as .text in the shipped library.
void kdf_blob(const uint8_t* ikm, const uint8_t* stub, unsigned long stublen, uint8_t* out) {
  uint8_t salt[32];
  kb_sha256(stub, stublen, salt);
  uint8_t prk[32];
  kb_hmac(salt, 32, ikm, 32, prk);
  uint8_t counter = 1;
  kb_hmac(prk, 32, &counter, 1, out);
}

/// The post-decrypt verification: whether SHA-256 of `data[0..len)` equals `expected`. The bootstrap calls this on the
/// decrypted `.text` right after the region loop, so a wrong key (tampered metadata, patched ciphertext) produces
/// garbage that fails the comparison instead of executing. Reached only via the run-time builder, like kdf_blob.
int verify_blob(const uint8_t* data, unsigned long len, const uint8_t* expected) {
  uint8_t digest[32];
  kb_sha256(data, len, digest);
  for (int i = 0; i < 32; i++) {
    if (digest[i] != expected[i]) {
      return 0;
    }
  }
  return 1;
}
