/// The iOS at-rest layer: see atrest.h. The key is derived from the runtime's own code hash so that a patched or
/// removed runtime cannot produce it.

#include "selfdecrypt/atrest.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "selfdecrypt/chacha20.h"

namespace rasp::ios::selfdecrypt {

namespace {

/// The 64-bit FNV-1a offset basis, the digest's starting value.
constexpr std::uint64_t kFnvOffset = 0xcbf29ce484222325ULL;
/// The 64-bit FNV-1a prime, mixed in per byte.
constexpr std::uint64_t kFnvPrime = 0x100000001b3ULL;
/// The number of 64-bit lanes the digest keeps, which times eight is kKeyBytes.
constexpr std::size_t kLanes = kKeyBytes / sizeof(std::uint64_t);

/// Writes a 64-bit word little-endian into `out`.
void store64_le(std::uint64_t value, std::uint8_t* out) {
  for (std::size_t i = 0; i < sizeof(value); i++) {
    out[i] = static_cast<std::uint8_t>(value >> (8U * i));
  }
}

}  // namespace

std::array<std::uint8_t, kKeyBytes> hash_region(std::span<const std::uint8_t> bytes) {
  // Four independent FNV-1a lanes, each seeded differently, so the 32-byte digest reflects every input byte and any
  // single-byte change propagates across the key. Dependency-free by design (no TF-PSA-Crypto, no libc).
  std::array<std::uint64_t, kLanes> lanes{};
  for (std::size_t lane = 0; lane < kLanes; lane++) {
    lanes[lane] = kFnvOffset ^ (static_cast<std::uint64_t>(lane) * kFnvPrime);
  }
  std::size_t index = 0;
  for (const std::uint8_t byte : bytes) {
    std::uint64_t& lane = lanes[index % kLanes];
    lane ^= byte;
    lane *= kFnvPrime;
    index++;
  }
  // A final avalanche pass so the lanes depend on the total length and on each other.
  for (std::size_t lane = 0; lane < kLanes; lane++) {
    lanes[lane] ^= static_cast<std::uint64_t>(bytes.size());
    lanes[lane] *= kFnvPrime;
    lanes[lane] ^= lanes[(lane + 1) % kLanes] >> 29U;
  }
  std::array<std::uint8_t, kKeyBytes> digest{};
  for (std::size_t lane = 0; lane < kLanes; lane++) {
    store64_le(lanes[lane], digest.data() + (lane * sizeof(std::uint64_t)));
  }
  return digest;
}

std::array<std::uint8_t, kKeyBytes> hash_functions(std::span<const CodeSpan> regions) {
  // Concatenate each region with an eight-byte little-endian length separator, then hash the whole. The separator makes
  // the boundaries part of the input, so moving a byte from one region to the next still changes the digest, and a
  // missing region (null or empty) still contributes its length rather than being skipped silently.
  std::vector<std::uint8_t> material;
  std::size_t total = 0;
  for (const CodeSpan& region : regions) {
    total += region.size() + sizeof(std::uint64_t);
  }
  material.reserve(total);
  for (const CodeSpan& region : regions) {
    const auto length = static_cast<std::uint64_t>(region.size());
    for (std::size_t i = 0; i < sizeof(length); i++) {
      material.push_back(static_cast<std::uint8_t>(length >> (8U * i)));
    }
    if (region.data() != nullptr) {
      material.insert(material.end(), region.begin(), region.end());
    }
  }
  return hash_region(material);
}

std::array<std::uint8_t, kKeyBytes> derive_key(const std::array<std::uint8_t, kKeyBytes>& code_hash,
                                              std::span<const std::uint8_t> seed) {
  // key = hash_region(seed || code_hash): binds the key to both the embedded secret and the intact code.
  std::vector<std::uint8_t> material;
  material.reserve(seed.size() + code_hash.size());
  material.insert(material.end(), seed.begin(), seed.end());
  material.insert(material.end(), code_hash.begin(), code_hash.end());
  return hash_region(material);
}

void decrypt_region(std::span<std::uint8_t> region, const std::array<std::uint8_t, kKeyBytes>& code_hash,
                    std::span<const std::uint8_t> seed, const std::uint8_t nonce[kNonceSize]) {
  const std::array<std::uint8_t, kKeyBytes> key = derive_key(code_hash, seed);
  chacha20_xor(region.data(), region.size(), key.data(), nonce);
}

}  // namespace rasp::ios::selfdecrypt
