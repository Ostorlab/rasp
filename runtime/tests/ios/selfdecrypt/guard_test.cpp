/// Tests for the at-rest guard. An unpacked build (the default zero blob) reads as not-intact; a blob the packer would
/// write (the marker encrypted under the guard key) decrypts to the marker, which is what at_rest_guard_intact checks.

#include "selfdecrypt/guard.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>

#include "selfdecrypt/atrest.h"
#include "selfdecrypt/chacha20.h"
#include "selfdecrypt/seed.h"

namespace rasp::ios::selfdecrypt {
namespace {

/// The marker and nonce the guard uses, mirrored here so the test builds the blob the packer would.
constexpr std::array<std::uint8_t, 8> kMarker = {0x52, 0x41, 0x53, 0x50, 0x4f, 0x4b, 0x21, 0x21};
constexpr std::array<std::uint8_t, kNonceSize> kNonce = {0x00, 0x00, 0x00, 0x00, 0x61, 0x74, 0x72, 0x73,
                                                         0x74, 0x67, 0x75, 0x61, 0x72, 0x64, 0x30, 0x31};
/// The fixed domain constant the guard binds its key to in this version (matches guard.cpp own_code_hash).
constexpr std::array<std::uint8_t, 16> kDomain = {0x72, 0x61, 0x73, 0x70, 0x2d, 0x61, 0x74, 0x72,
                                                  0x65, 0x73, 0x74, 0x2d, 0x76, 0x31, 0x00, 0x00};

/// Builds the guard key the way guard.cpp does: derive_key(hash(domain), reconstructed seed).
[[nodiscard]] std::array<std::uint8_t, kKeyBytes> guard_key() {
  std::array<std::uint8_t, kSeedBytes> seed{};
  reconstruct_seed(seed);
  return derive_key(hash_region(kDomain), seed);
}

TEST(Guard, atRestGuardIntact_whenUnpacked_isNotIntact) {
  // The linked guard_blob is the default (all zeros, no packer), so the guard must read as not intact.
  EXPECT_FALSE(at_rest_guard_intact());
}

TEST(Guard, packerBlob_whenDecryptedWithTheGuardKey_recoversTheMarker) {
  // The packer encrypts the marker under the guard key; decrypting it must give the marker back, which is the check
  // at_rest_guard_intact performs when the section holds a packed blob.
  std::array<std::uint8_t, 32> blob{};
  for (std::size_t i = 0; i < kMarker.size(); i++) {
    blob[i] = kMarker[i];
  }
  const std::array<std::uint8_t, kKeyBytes> key = guard_key();
  chacha20_xor(blob.data(), blob.size(), key.data(), kNonce.data());  // packer: encrypt
  EXPECT_NE(blob[0], kMarker[0]);                                     // it really is encrypted

  chacha20_xor(blob.data(), blob.size(), key.data(), kNonce.data());  // runtime: decrypt
  for (std::size_t i = 0; i < kMarker.size(); i++) {
    EXPECT_EQ(blob[i], kMarker[i]);
  }
}

}  // namespace
}  // namespace rasp::ios::selfdecrypt
