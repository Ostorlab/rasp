/// sha256, which runs the SHA-256 compression function over padded 64-byte blocks, and hmac_sha256, which wraps it
/// in the RFC 2104 inner and outer hashes.

#include "rasp/util/sha256.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <ranges>
#include <span>

namespace rasp {

namespace {

/// The size of a SHA-256 block, in bytes.
constexpr std::size_t kBlockSize = 64;

/// The size of the message length at the end of the padding, in bytes.
constexpr std::size_t kLengthSize = 8;

/// The eight 32-bit words of the hash state.
using State = std::array<std::uint32_t, 8>;

/// The 64 round constants of FIPS 180-4.
constexpr std::array<std::uint32_t, 64> kRoundConstants = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

/// The hash state before the first block, from FIPS 180-4.
constexpr State kInitialState = {
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU, 0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
};

/// The byte HMAC XORs into the key for the inner hash.
constexpr std::uint8_t kInnerPad = 0x36;

/// The byte HMAC XORs into the key for the outer hash.
constexpr std::uint8_t kOuterPad = 0x5c;

/// Reads 4 bytes as a big-endian 32-bit word.
[[nodiscard]] std::uint32_t load_big_endian(std::span<const std::uint8_t, 4> bytes) {
  std::uint32_t word = 0;
  for (const std::uint8_t byte : bytes) {
    word = (word << 8U) | static_cast<std::uint32_t>(byte);
  }
  return word;
}

/// Writes `value` into `bytes` in big-endian order, the most significant byte first.
template <typename Word>
void store_big_endian(Word value, std::span<std::uint8_t, sizeof(Word)> bytes) {
  for (std::uint8_t& byte : std::views::reverse(bytes)) {
    byte = static_cast<std::uint8_t>(value);
    value >>= 8U;
  }
}

/// Mixes one 64-byte block into the hash state.
void compress(State& state, std::span<const std::uint8_t, kBlockSize> block) {
  std::array<std::uint32_t, kRoundConstants.size()> schedule{};
  const std::span<std::uint32_t> words(schedule);
  for (std::size_t i = 0; i < 16; ++i) {
    words[i] = load_big_endian(block.subspan(i * 4).first<4>());
  }
  for (std::size_t i = 16; i < words.size(); ++i) {
    const std::uint32_t s0 = std::rotr(words[i - 15], 7) ^ std::rotr(words[i - 15], 18) ^ (words[i - 15] >> 3U);
    const std::uint32_t s1 = std::rotr(words[i - 2], 17) ^ std::rotr(words[i - 2], 19) ^ (words[i - 2] >> 10U);
    words[i] = words[i - 16] + s0 + words[i - 7] + s1;
  }

  auto [a, b, c, d, e, f, g, h] = state;
  for (const auto [constant, word] : std::views::zip(kRoundConstants, schedule)) {
    const std::uint32_t s1 = std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25);
    const std::uint32_t choice = (e & f) ^ (~e & g);
    const std::uint32_t temp1 = h + s1 + choice + constant + word;
    const std::uint32_t s0 = std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22);
    const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temp2 = s0 + majority;
    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  const State mixed = {a, b, c, d, e, f, g, h};
  for (auto [total, value] : std::views::zip(state, mixed)) {
    total += value;
  }
}

/// Gives a copy of `block_key` with each byte XORed with `pad`.
[[nodiscard]] std::array<std::uint8_t, kBlockSize> xor_pad(const std::array<std::uint8_t, kBlockSize>& block_key,
                                                           std::uint8_t pad) {
  std::array<std::uint8_t, kBlockSize> padded = block_key;
  for (std::uint8_t& byte : padded) {
    byte = static_cast<std::uint8_t>(byte ^ pad);
  }
  return padded;
}

/// Mixes the last `data` of a `total_size`-byte message into `state`, which holds the blocks before it, and gives the
/// digest.
[[nodiscard]] Sha256Digest finish(State state, std::span<const std::uint8_t> data, std::size_t total_size) {
  std::span<const std::uint8_t> rest = data;
  while (rest.size() >= kBlockSize) {
    compress(state, rest.first<kBlockSize>());
    rest = rest.subspan(kBlockSize);
  }

  std::array<std::uint8_t, 2 * kBlockSize> tail{};
  const std::span<std::uint8_t> padding(tail);
  std::ranges::copy(rest, padding.begin());
  padding[rest.size()] = 0x80;
  const std::size_t tail_size = (rest.size() < kBlockSize - kLengthSize) ? kBlockSize : 2 * kBlockSize;
  const std::uint64_t bit_length = static_cast<std::uint64_t>(total_size) * 8U;
  store_big_endian(bit_length, padding.subspan(tail_size - kLengthSize).first<kLengthSize>());
  for (std::size_t offset = 0; offset < tail_size; offset += kBlockSize) {
    compress(state, padding.subspan(offset).first<kBlockSize>());
  }

  Sha256Digest digest{};
  std::span<std::uint8_t> out(digest);
  for (const std::uint32_t word : state) {
    store_big_endian(word, out.first<4>());
    out = out.subspan(4);
  }
  return digest;
}

}  // namespace

Sha256Digest sha256(std::span<const std::uint8_t> data) { return finish(kInitialState, data, data.size()); }

Sha256Digest hmac_sha256(std::span<const std::uint8_t> key, std::span<const std::uint8_t> message) {
  std::array<std::uint8_t, kBlockSize> block_key{};
  if (key.size() > kBlockSize) {
    std::ranges::copy(sha256(key), block_key.begin());
  } else {
    std::ranges::copy(key, block_key.begin());
  }

  State inner = kInitialState;
  compress(inner, xor_pad(block_key, kInnerPad));
  const Sha256Digest inner_hash = finish(inner, message, kBlockSize + message.size());

  State outer = kInitialState;
  compress(outer, xor_pad(block_key, kOuterPad));
  return finish(outer, inner_hash, kBlockSize + inner_hash.size());
}

}  // namespace rasp
