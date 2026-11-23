/// at_rest_guard: see guard.h. The guard blob is decrypted with a key derived from the runtime's own code and the
/// scattered seed, then checked against a known marker.

#include "selfdecrypt/guard.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#ifdef __APPLE__
#include <dlfcn.h>
#include <mach-o/getsect.h>
#include <mach-o/loader.h>
#endif

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

/// The bytes of the runtime's own code the guard key is bound to: the `__TEXT,__text` section of this framework.
///
/// The section's bytes are identical in the shipped file and in memory (ASLR slides where `__text` loads, not what it
/// holds), so the packer hashes the same bytes from the file that the runtime hashes from memory. A patch to any of the
/// runtime's code changes `__text`, so the hash and the derived key change and the guard no longer decrypts.
///
/// `getsectiondata` returns the section's live, slide-adjusted address and size from this framework's own Mach-O
/// header, which `dladdr` on a function of this module provides.
[[nodiscard]] std::array<std::uint8_t, kKeyBytes> own_code_hash() {
#ifdef __APPLE__
  Dl_info info{};
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): take the address of a function of this module.
  if (dladdr(reinterpret_cast<const void*>(&chacha20_xor), &info) == 0 || info.dli_fbase == nullptr) {
    return {};
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): dli_fbase is this image's mach_header.
  const auto* header = reinterpret_cast<const mach_header_64*>(info.dli_fbase);
  unsigned long size = 0;
  const std::uint8_t* text = getsectiondata(header, "__TEXT", "__text", &size);
  if (text == nullptr || size == 0) {
    return {};
  }
  return hash_region(std::span<const std::uint8_t>(text, size));
#else
  return {};
#endif
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
