/// A self-contained ChaCha20 for the iOS at-rest layer. The runtime's own ChaCha20-Poly1305 (TF-PSA-Crypto) lives in
/// the framework's own code, which cannot be relied on to run before the at-rest layer has decrypted what it guards; so
/// the at-rest layer carries this tiny stream cipher of its own. Its byte layout matches the packer's `cryptography`
/// ChaCha20 and the Android bootstrap's: a 16-byte counter and nonce loaded as four little-endian words into state
/// words 12..15, word 12 the block counter.

#pragma once

#include <cstddef>
#include <cstdint>

namespace rasp::ios::selfdecrypt {

/// The size of a ChaCha20 key, in bytes.
inline constexpr std::size_t kKeySize = 32;
/// The size of the combined counter and nonce the cipher takes, in bytes.
inline constexpr std::size_t kNonceSize = 16;

/// Transforms `data[0..len)` in place with ChaCha20 (the same call encrypts and decrypts).
///
/// @param data The buffer to transform in place.
/// @param len The number of bytes in `data`.
/// @param key The 32-byte ChaCha20 key.
/// @param nonce16 The 16-byte counter and nonce, identical to what the packer used.
void chacha20_xor(std::uint8_t* data, std::size_t len, const std::uint8_t* key, const std::uint8_t* nonce16);

}  // namespace rasp::ios::selfdecrypt
