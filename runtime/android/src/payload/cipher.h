/// decrypt, which checks and decrypts the packer's payload frame with ChaCha20-Poly1305, and wipe, which zeroes a
/// decrypted buffer.

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace rasp::android::payload {

/// The size of the payload key, in bytes.
inline constexpr std::size_t kKeySize = 32;

/// The size of the nonce at the start of a frame, in bytes, as RFC 8439 fixes it.
inline constexpr std::size_t kNonceSize = 12;

/// The size of the Poly1305 tag at the end of a frame, in bytes.
inline constexpr std::size_t kTagSize = 16;

/// Checks and decrypts a frame that the packer encrypted with ChaCha20-Poly1305, as RFC 8439 defines it.
///
/// A frame is the 12-byte nonce, then the encrypted bytes, then the 16-byte Poly1305 tag. It has no associated data.
/// The packer makes it with the `cryptography` package, and this decrypts it with TF-PSA-Crypto, through the PSA API.
/// Several threads can call it at once: TF-PSA-Crypto is built with its own locking (`MBEDTLS_THREADING_C`, see
/// third_party/tf-psa-crypto/README.md).
///
/// @param key The payload key. It must be exactly kKeySize bytes long.
/// @param frame The frame to decrypt.
/// @return The decrypted bytes, which can be empty. Nothing when the key has the wrong size, when the frame is shorter
/// than a nonce and a tag, when the tag doesn't match, or when the crypto library can't start.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> decrypt(std::span<const std::uint8_t> key,
                                                               std::span<const std::uint8_t> frame);

/// Zeroes `bytes`, so a decrypted dex or map that was copied out of them leaves no copy behind.
///
/// The writes go through a volatile pointer, so the compiler cannot decide they are dead stores and skip them.
///
/// @param bytes The buffer to zero, which may be empty.
void wipe(std::span<std::uint8_t> bytes);

}  // namespace rasp::android::payload
