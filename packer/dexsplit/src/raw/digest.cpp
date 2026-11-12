#include "raw/digest.hpp"

#include <bit>
#include <cstring>

#include "common/budget.hpp"

namespace dexsplit::raw {

namespace {

uint32_t load_be32(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | p[3];
}

// Feeds @p data to @p block (64 bytes at a time) with the Merkle-Damgard
// padding both SHA-1 and SHA-256 use: 0x80, zeros, then the bit length as a
// big-endian 64-bit number.  Full blocks are read straight from the input.
template <typename BlockFn>
void for_each_padded_block(std::span<const uint8_t> data, BlockFn block) {
  std::size_t full = data.size() / 64 * 64;
  for (std::size_t off = 0; off < full; off += 64) {
    block(data.data() + off);
  }

  uint8_t tail[128] = {};
  std::size_t rest = data.size() - full;
  if (rest != 0) {
    std::memcpy(tail, data.data() + full, rest);
  }
  tail[rest] = 0x80;
  std::size_t tail_size = rest + 1 + 8 <= 64 ? 64 : 128;
  uint64_t bits = static_cast<uint64_t>(data.size()) * 8;
  for (int i = 0; i < 8; ++i) {
    tail[tail_size - 1 - i] = static_cast<uint8_t>(bits >> (8 * i));
  }
  block(tail);
  if (tail_size == 128) {
    block(tail + 64);
  }
}

}  // namespace

std::array<uint8_t, 20> sha1(std::span<const uint8_t> data) {
  budget::visit(data.size() / 64 + 1);
  uint32_t h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};

  for_each_padded_block(data, [&](const uint8_t* chunk) {
    uint32_t w[80];
    for (int i = 0; i < 16; ++i) {
      w[i] = load_be32(chunk + static_cast<std::size_t>(i) * 4);
    }
    for (int i = 16; i < 80; ++i) {
      w[i] = std::rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    for (int i = 0; i < 80; ++i) {
      uint32_t f, k;
      if (i < 20) {
        f = (b & c) | (~b & d);
        k = 0x5A827999;
      } else if (i < 40) {
        f = b ^ c ^ d;
        k = 0x6ED9EBA1;
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8F1BBCDC;
      } else {
        f = b ^ c ^ d;
        k = 0xCA62C1D6;
      }
      uint32_t tmp = std::rotl(a, 5) + f + e + k + w[i];
      e = d;
      d = c;
      c = std::rotl(b, 30);
      b = a;
      a = tmp;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
  });

  std::array<uint8_t, 20> digest;
  for (int i = 0; i < 5; ++i) {
    for (int j = 0; j < 4; ++j) {
      digest[i * 4 + j] = static_cast<uint8_t>(h[i] >> (24 - 8 * j));
    }
  }
  return digest;
}

std::array<uint8_t, 32> sha256(std::span<const uint8_t> data) {
  static constexpr uint32_t K[64] = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

  uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

  for_each_padded_block(data, [&](const uint8_t* chunk) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
      w[i] = load_be32(chunk + static_cast<std::size_t>(i) * 4);
    }
    for (int i = 16; i < 64; ++i) {
      uint32_t s0 = std::rotr(w[i - 15], 7) ^ std::rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
      uint32_t s1 = std::rotr(w[i - 2], 17) ^ std::rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; ++i) {
      uint32_t S1 = std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25);
      uint32_t ch = (e & f) ^ (~e & g);
      uint32_t t1 = hh + S1 + ch + K[i] + w[i];
      uint32_t S0 = std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22);
      uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
      uint32_t t2 = S0 + maj;
      hh = g;
      g = f;
      f = e;
      e = d + t1;
      d = c;
      c = b;
      b = a;
      a = t1 + t2;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
  });

  std::array<uint8_t, 32> digest;
  for (int i = 0; i < 8; ++i) {
    for (int j = 0; j < 4; ++j) {
      digest[i * 4 + j] = static_cast<uint8_t>(h[i] >> (24 - 8 * j));
    }
  }
  return digest;
}

}  // namespace dexsplit::raw
