/// decrypt, which checks and decrypts one frame made by the packer's Android cipher.

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace rasp::android::payload {

/// The size of the payload key, in bytes.
inline constexpr std::size_t kKeySize = 32;

/// Checks the tag of a frame made by the packer's Android cipher, then decrypts it.
///
/// It is the native counterpart of the packer's cipher, and must stay byte for byte compatible with it. A frame is
/// the 4 bytes `RASP`, the version byte 1, a 16-byte nonce, the encrypted bytes, and a 32-byte tag. Two subkeys are
/// derived from the key with HMAC-SHA256: one over the label `rasp/android/authenticate/v1`, and one over the label
/// `rasp/android/encrypt/v1`. The tag is the HMAC-SHA256, under the first subkey, of everything before it, and it is
/// compared in constant time. The encrypted bytes are XORed with a keystream made of 32-byte blocks: block n is the
/// HMAC-SHA256, under the second subkey, of the nonce followed by n as a big-endian 64-bit number. Nothing is
/// decrypted before the tag is checked.
///
/// @param key The payload key. It must be exactly kKeySize bytes long.
/// @param frame The frame to decrypt.
/// @return The decrypted bytes, which can be empty. Nothing when the key has the wrong size, when the frame is too
/// short, starts with other bytes or has another version, or when the tag doesn't match.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> decrypt(std::span<const std::uint8_t> key,
                                                               std::span<const std::uint8_t> frame);

}  // namespace rasp::android::payload
