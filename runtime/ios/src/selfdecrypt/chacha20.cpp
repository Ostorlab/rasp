/// The self-contained ChaCha20 the iOS at-rest layer uses to decrypt a guarded region. It is a straight port of the
/// Android bootstrap's cipher (android/src/selfdecrypt/chacha20.cpp), with the same byte layout, so the packer encrypts
/// once and either platform decrypts.

#include "selfdecrypt/chacha20.h"

#include <array>
#include <cstddef>
#include <cstdint>

namespace rasp::ios::selfdecrypt {

namespace {

/// The number of 32-bit words in a ChaCha20 state block.
constexpr std::size_t kStateWords = 16;
/// The number of keystream bytes a ChaCha20 block yields.
constexpr std::size_t kBlockBytes = 64;
/// The number of double-rounds in ChaCha20 (20 rounds).
constexpr int kDoubleRounds = 10;

/// Rotates a 32-bit word left by `n` bits.
[[nodiscard]] std::uint32_t rotl32(std::uint32_t x, unsigned int n) {
  return (x << n) | (x >> (32U - n));
}

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
void chacha20_block(const std::array<std::uint32_t, kStateWords>& in, std::array<std::uint32_t, kStateWords>& out) {
  out = in;
  for (int round = 0; round < kDoubleRounds; round++) {
    quarter_round(out[0], out[4], out[8], out[12]);
    quarter_round(out[1], out[5], out[9], out[13]);
    quarter_round(out[2], out[6], out[10], out[14]);
    quarter_round(out[3], out[7], out[11], out[15]);
    quarter_round(out[0], out[5], out[10], out[15]);
    quarter_round(out[1], out[6], out[11], out[12]);
    quarter_round(out[2], out[7], out[8], out[13]);
    quarter_round(out[3], out[4], out[9], out[14]);
  }
  for (std::size_t i = 0; i < kStateWords; i++) {
    out[i] += in[i];
  }
}

/// Reads four bytes as a little-endian 32-bit word.
[[nodiscard]] std::uint32_t load32_le(const std::uint8_t* p) {
  return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8U) |
         (static_cast<std::uint32_t>(p[2]) << 16U) | (static_cast<std::uint32_t>(p[3]) << 24U);
}

}  // namespace

void chacha20_xor(std::uint8_t* data, std::size_t len, const std::uint8_t key[kKeySize],
                  const std::uint8_t nonce16[kNonceSize]) {
  std::array<std::uint32_t, kStateWords> state{};
  state[0] = 0x61707865U;
  state[1] = 0x3320646eU;
  state[2] = 0x79622d32U;
  state[3] = 0x6b206574U;
  for (std::size_t i = 0; i < 8; i++) {
    state[4 + i] = load32_le(key + (4 * i));
  }
  state[12] = load32_le(nonce16 + 0);
  state[13] = load32_le(nonce16 + 4);
  state[14] = load32_le(nonce16 + 8);
  state[15] = load32_le(nonce16 + 12);

  std::array<std::uint32_t, kStateWords> block{};
  std::array<std::uint8_t, kBlockBytes> keystream{};
  std::size_t off = 0;
  while (off < len) {
    chacha20_block(state, block);
    for (std::size_t i = 0; i < kStateWords; i++) {
      keystream[(4 * i) + 0] = static_cast<std::uint8_t>(block[i]);
      keystream[(4 * i) + 1] = static_cast<std::uint8_t>(block[i] >> 8U);
      keystream[(4 * i) + 2] = static_cast<std::uint8_t>(block[i] >> 16U);
      keystream[(4 * i) + 3] = static_cast<std::uint8_t>(block[i] >> 24U);
    }
    std::size_t take = len - off;
    if (take > kBlockBytes) {
      take = kBlockBytes;
    }
    for (std::size_t i = 0; i < take; i++) {
      data[off + i] = static_cast<std::uint8_t>(data[off + i] ^ keystream[i]);
    }
    off += take;
    state[12]++;
  }
}

}  // namespace rasp::ios::selfdecrypt
