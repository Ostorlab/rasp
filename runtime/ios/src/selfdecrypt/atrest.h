/// The iOS at-rest layer: decrypts a guarded region whose key is bound to the runtime's own intact code.
///
/// A region of bytes (on device, a slice of the app, injected by the packer) ships encrypted. Its ChaCha20 key is not
/// stored; it is derived at runtime from a per-build seed mixed with a hash of the runtime's own code. When the
/// runtime's code is intact the derived key matches the one the packer used and the region decrypts to its plaintext;
/// when the runtime has been patched or removed the hash differs, the key is wrong, and the region stays unusable. The
/// guard is therefore enforced by key derivation, not by a branch an attacker can patch out.
///
/// This header is self-contained (no TF-PSA-Crypto, no libc crypto): the at-rest layer must run before, and
/// independently of, the rest of the runtime.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "selfdecrypt/chacha20.h"

namespace rasp::ios::selfdecrypt {

/// The size of the derived key and of the code hash, in bytes.
inline constexpr std::size_t kKeyBytes = kKeySize;

/// Hashes a span of bytes into a 32-byte digest, with a small self-contained mixing function.
///
/// It is not a cryptographic hash in the collision-resistance sense; it is a fast, dependency-free digest whose only
/// job is that any change to the hashed bytes changes the digest, so a patched runtime derives a different key. The
/// digest feeds derive_key, never a signature.
///
/// @param bytes The bytes to hash, such as the runtime's own code region.
/// @return The 32-byte digest.
[[nodiscard]] std::array<std::uint8_t, kKeyBytes> hash_region(std::span<const std::uint8_t> bytes);

/// A span of the runtime's own code to fold into the key: the first bytes of a function the key must depend on.
///
/// The key covers more than the decrypt path: it covers the check functions too, so an attacker who leaves the decrypt
/// code intact but patches a check still changes the key and breaks the decryption. Each entry is the start of one such
/// function, read from the live binary.
using CodeSpan = std::span<const std::uint8_t>;

/// Hashes several code regions together into one digest, so a change to any of them changes the digest.
///
/// The regions are folded in order with a per-region separator, so patching any single function (a check, the decrypt
/// path, the key derivation) changes the combined digest and therefore the key. A region that is empty or whose pointer
/// is null is folded as its length alone, so a function the build could not locate does not silently drop the others.
///
/// @param regions The code regions to cover, such as the first bytes of each check and of the decrypt path.
/// @return The 32-byte combined digest.
[[nodiscard]] std::array<std::uint8_t, kKeyBytes> hash_functions(std::span<const CodeSpan> regions);

/// Derives the region's ChaCha20 key from the runtime's code hash and the per-build seed.
///
/// The key is `hash_region(seed || code_hash)`, so it depends on both the secret seed the packer embedded and the
/// runtime's intact code. The packer computes the same key from the shipped code and seed when it encrypts the region.
///
/// @param code_hash The hash of the runtime's own code, as hash_region returns it.
/// @param seed The per-build seed the packer embedded.
/// @return The 32-byte ChaCha20 key.
[[nodiscard]] std::array<std::uint8_t, kKeyBytes> derive_key(const std::array<std::uint8_t, kKeyBytes>& code_hash,
                                                            std::span<const std::uint8_t> seed);

/// Decrypts `region` in place with the key derived from `code_hash` and `seed`, using `nonce`.
///
/// When `code_hash` is the one the packer used (the runtime is intact), `region` becomes its plaintext; otherwise it
/// becomes unrelated bytes. The function does not judge the result and has no branch on integrity: the binding is the
/// key alone.
///
/// @param region The bytes to decrypt in place.
/// @param code_hash The hash of the runtime's own code.
/// @param seed The per-build seed the packer embedded.
/// @param nonce The 16-byte counter and nonce the packer used.
void decrypt_region(std::span<std::uint8_t> region, const std::array<std::uint8_t, kKeyBytes>& code_hash,
                    std::span<const std::uint8_t> seed, const std::uint8_t nonce[kNonceSize]);

}  // namespace rasp::ios::selfdecrypt
