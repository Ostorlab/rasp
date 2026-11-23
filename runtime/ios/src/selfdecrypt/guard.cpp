/// at_rest_guard: see guard.h. The guard blob is decrypted with a key derived from the runtime's own code and the
/// scattered seed, then checked against a known marker.

#include "selfdecrypt/guard.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "selfdecrypt/atrest.h"
#include "selfdecrypt/chacha20.h"
#include "selfdecrypt/seed.h"

namespace rasp::ios::selfdecrypt {

namespace {

/// The size of the guard blob the packer encrypts into the section, in bytes.
constexpr std::size_t kGuardSize = 32;

/// The plaintext marker the blob decrypts to when the runtime is intact: the first bytes the guard checks.
constexpr std::array<std::uint8_t, 8> kMarker = {0x52, 0x41, 0x53, 0x50, 0x4f, 0x4b, 0x21, 0x21};  // "RASPOK!!"

/// The 16-byte counter and nonce the packer uses for the guard blob. Fixed and public; the key is the secret.
constexpr std::array<std::uint8_t, kNonceSize> kNonce = {0x00, 0x00, 0x00, 0x00, 0x61, 0x74, 0x72, 0x73,
                                                         0x74, 0x67, 0x75, 0x61, 0x72, 0x64, 0x30, 0x31};

/// The encrypted guard blob, in a `__DATA` section the packer overwrites in the binary file. It starts as zeros; a
/// packed build replaces it with the ciphertext of the marker (plus padding) under the build's key. An unpacked build
/// leaves it zero, so the guard reads as not-intact rather than falsely intact.
#ifdef __APPLE__
[[gnu::section("__DATA,__rasp_guard"), gnu::used]]
#else
[[gnu::section(".rasp_guard"), gnu::used]]
#endif
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the packer writes it, in the binary's file.
std::array<volatile std::uint8_t, kGuardSize> guard_blob{};

/// A fixed domain-separation constant the guard key is bound to for this first device-test version.
///
/// This version binds the key to the scattered seed only, not to a hash of the runtime's live code. Binding to live
/// code needs a window the packer can locate in the shipped, stripped, obfuscated binary and that is byte-identical in
/// the file and in memory under ASLR; that is the next step. Until then this constant keeps hash_region in the key path
/// so the derive_key shape is unchanged, and the packer uses the same constant, so a packed blob still decrypts.
[[nodiscard]] std::array<std::uint8_t, kKeyBytes> own_code_hash() {
  // "rasp-atrest-v1" padded to 16 bytes.
  constexpr std::array<std::uint8_t, 16> kDomain = {0x72, 0x61, 0x73, 0x70, 0x2d, 0x61, 0x74, 0x72,
                                                    0x65, 0x73, 0x74, 0x2d, 0x76, 0x31, 0x00, 0x00};
  return hash_region(kDomain);
}

}  // namespace

bool at_rest_guard_intact() {
  std::array<std::uint8_t, kGuardSize> blob{};
  for (std::size_t i = 0; i < kGuardSize; i++) {
    blob[i] = guard_blob[i];
  }

  std::array<std::uint8_t, kSeedBytes> seed{};
  reconstruct_seed(seed);
  const std::array<std::uint8_t, kKeyBytes> code_hash = own_code_hash();

  decrypt_region(blob, code_hash, seed, kNonce.data());

  for (std::size_t i = 0; i < kMarker.size(); i++) {
    if (blob[i] != kMarker[i]) {
      return false;
    }
  }
  return true;
}

}  // namespace rasp::ios::selfdecrypt
