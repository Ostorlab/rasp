/// The self-contained ChaCha20 the self-decrypt bootstrap uses to decrypt the library at load. Routed into the clear
/// .stubcode/.stubrodata so it stays runnable and readable while the library's own .text and .rodata are encrypted.

#include "selfdecrypt/chacha20.h"

#include <cstddef>
#include <cstdint>

#pragma clang section text = ".stubcode" rodata = ".stubrodata"

namespace rasp::android::selfdecrypt {

namespace {

/// Rotates a 32-bit word left by `n` bits.
[[nodiscard]] std::uint32_t rotl32(std::uint32_t x, unsigned int n) { return (x << n) | (x >> (32U - n)); }

/// One ChaCha20 quarter-round on the four referenced state words.
void quarter_round(std::uint32_t& a, std::uint32_t& b, std::uint32_t& c, std::uint32_t& d) {
  a += b;
  d = rotl32(d ^ a, 16);
  c += d;
  b = rotl32(b ^ c, 12);
  a += b;
  d = rotl32(d ^ a, 8);
  c += d;
  b = rotl32(b ^ c, 7);
}

/// Runs the 20-round ChaCha20 block function: out = H(in), with the final word-wise add.
void chacha20_block(const std::uint32_t in[16], std::uint32_t out[16]) {
  for (int i = 0; i < 16; i++) {
    out[i] = in[i];
  }
  for (int i = 0; i < 10; i++) {
    quarter_round(out[0], out[4], out[8], out[12]);
    quarter_round(out[1], out[5], out[9], out[13]);
    quarter_round(out[2], out[6], out[10], out[14]);
    quarter_round(out[3], out[7], out[11], out[15]);
    quarter_round(out[0], out[5], out[10], out[15]);
    quarter_round(out[1], out[6], out[11], out[12]);
    quarter_round(out[2], out[7], out[8], out[13]);
    quarter_round(out[3], out[4], out[9], out[14]);
  }
  for (int i = 0; i < 16; i++) {
    out[i] += in[i];
  }
}

/// Reads four bytes as a little-endian 32-bit word.
[[nodiscard]] std::uint32_t load32_le(const std::uint8_t* p) {
  return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
         (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}

}  // namespace

void chacha20_xor(std::uint8_t* data, std::size_t len, const std::uint8_t key[32], const std::uint8_t nonce16[16]) {
  std::uint32_t state[16];
  state[0] = 0x61707865U;
  state[1] = 0x3320646eU;
  state[2] = 0x79622d32U;
  state[3] = 0x6b206574U;
  for (int i = 0; i < 8; i++) {
    state[4 + i] = load32_le(key + 4 * i);
  }
  state[12] = load32_le(nonce16 + 0);
  state[13] = load32_le(nonce16 + 4);
  state[14] = load32_le(nonce16 + 8);
  state[15] = load32_le(nonce16 + 12);

  std::uint32_t block[16];
  std::uint8_t keystream[64];
  std::size_t off = 0;
  while (off < len) {
    chacha20_block(state, block);
    for (int i = 0; i < 16; i++) {
      keystream[4 * i + 0] = static_cast<std::uint8_t>(block[i]);
      keystream[4 * i + 1] = static_cast<std::uint8_t>(block[i] >> 8);
      keystream[4 * i + 2] = static_cast<std::uint8_t>(block[i] >> 16);
      keystream[4 * i + 3] = static_cast<std::uint8_t>(block[i] >> 24);
    }
    std::size_t n = len - off;
    if (n > 64) {
      n = 64;
    }
    for (std::size_t i = 0; i < n; i++) {
      data[off + i] = static_cast<std::uint8_t>(data[off + i] ^ keystream[i]);
    }
    off += n;
    state[12]++;
  }
}

}  // namespace rasp::android::selfdecrypt
