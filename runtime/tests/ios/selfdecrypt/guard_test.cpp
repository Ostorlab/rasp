/// Tests for the at-rest guard. The host tests exercise two parts:
///
///  1. `at_rest_guard_status` with the linked default blob (all zeros), which must read as kAbsent. The kIntact and
///     kTampered paths run the same derive → decrypt → check that the round-trip tests below exercise, but they read
///     from `guard_blob`, a module-private symbol the host test cannot inject into. A device test with a real packed
///     framework covers those paths.
///
///  2. The round-trip property: a blob the packer would write (the marker encrypted under the guard key) decrypts back
///     to the marker when the code hash matches, and does not when it differs.

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
constexpr std::array<std::uint8_t, kNonceSize> kNonce = {
    0x00, 0x00, 0x00, 0x00, 0x61, 0x74, 0x72, 0x73, 0x74, 0x67, 0x75, 0x61, 0x72, 0x64, 0x30, 0x31,
};
/// Builds a guard key from a stand-in code hash and the reconstructed seed, the way derive_key would from the real
/// __text hash on a device. The host cannot read this framework's own __text, so the code hash is a stand-in here; the
/// device test exercises the real __text binding.
[[nodiscard]] std::array<std::uint8_t, kKeyBytes> guard_key(const std::array<std::uint8_t, kKeyBytes>& code_hash) {
  std::array<std::uint8_t, kSeedBytes> seed{};
  reconstruct_seed(seed);
  return derive_key(code_hash, seed);
}

TEST(Guard, atRestGuardStatus_whenUnpacked_isAbsent) {
  // The linked guard_blob is the default (all zeros, no packer), so the guard must read as absent, not tampered -- an
  // unpacked build must not be treated as tampered and must not be ended.
  EXPECT_EQ(at_rest_guard_status(), GuardStatus::kAbsent);
}

TEST(Guard, packerBlob_whenTheCodeHashMatches_recoversTheMarker) {
  // The packer encrypts the marker under the key from a code hash; decrypting with the same code hash must give the
  // marker back -- the intact case.
  const std::array<std::uint8_t, kKeyBytes> code_hash = hash_region(std::array<std::uint8_t, 4>{1, 2, 3, 4});
  const std::array<std::uint8_t, kKeyBytes> key = guard_key(code_hash);
  std::array<std::uint8_t, 32> blob{};
  for (std::size_t i = 0; i < kMarker.size(); i++) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index): i is bounded by kMarker.size().
    blob[i] = kMarker[i];
  }
  chacha20_xor(blob.data(), blob.size(), key.data(), kNonce.data());  // packer: encrypt
  ASSERT_NE(blob[0], kMarker[0]);

  chacha20_xor(blob.data(), blob.size(), key.data(), kNonce.data());  // runtime: decrypt (same code hash)
  for (std::size_t i = 0; i < kMarker.size(); i++) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index): i is bounded by kMarker.size().
    EXPECT_EQ(blob[i], kMarker[i]);
  }
}

TEST(Guard, packerBlob_whenTheCodeHashDiffers_doesNotRecoverTheMarker) {
  // The packer encrypts under the genuine code hash; decrypting with a different code hash (a patched runtime) must not
  // give the marker back -- the tamper case that breaks the app.
  const std::array<std::uint8_t, kKeyBytes> genuine = hash_region(std::array<std::uint8_t, 4>{1, 2, 3, 4});
  std::array<std::uint8_t, 32> blob{};
  for (std::size_t i = 0; i < kMarker.size(); i++) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index): i is bounded by kMarker.size().
    blob[i] = kMarker[i];
  }
  const std::array<std::uint8_t, kKeyBytes> genuine_key = guard_key(genuine);
  chacha20_xor(blob.data(), blob.size(), genuine_key.data(), kNonce.data());  // packer: encrypt (genuine)

  const std::array<std::uint8_t, kKeyBytes> patched = hash_region(std::array<std::uint8_t, 4>{1, 2, 3, 5});
  const std::array<std::uint8_t, kKeyBytes> patched_key = guard_key(patched);
  chacha20_xor(blob.data(), blob.size(), patched_key.data(), kNonce.data());  // runtime: decrypt (patched)

  bool recovered = true;
  for (std::size_t i = 0; i < kMarker.size(); i++) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index): i is bounded by kMarker.size().
    if (blob[i] != kMarker[i]) {
      recovered = false;
    }
  }
  EXPECT_FALSE(recovered);
}

}  // namespace
}  // namespace rasp::ios::selfdecrypt
