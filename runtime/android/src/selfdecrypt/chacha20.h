/// A self-contained ChaCha20 for the load-time self-decrypt bootstrap. The payload cipher (payload/cipher.cpp) uses
/// TF-PSA-Crypto's ChaCha20-Poly1305, which lives in the library's own (encrypted) .text and cannot run before the
/// bootstrap has decrypted the library; so the bootstrap carries this tiny stream cipher in the clear .stubcode
/// instead. Its byte layout matches the packer's `cryptography` ChaCha20: a 16-byte counter and nonce loaded as four
/// little-endian words into state words 12..15, word 12 the block counter.

#pragma once

#include <cstddef>
#include <cstdint>

namespace rasp::android::selfdecrypt {

/// Transforms `data[0..len)` in place with ChaCha20 (the same call encrypts and decrypts).
///
/// @param data The buffer to transform in place.
/// @param len The number of bytes in `data`.
/// @param key The 32-byte ChaCha20 key.
/// @param nonce16 The 16-byte counter and nonce, identical to what the packer used.
void chacha20_xor(std::uint8_t* data, std::size_t len, const std::uint8_t key[32], const std::uint8_t nonce16[16]);

}  // namespace rasp::android::selfdecrypt
