/// sha256, the SHA-256 digest of some bytes, and hmac_sha256, the HMAC-SHA256 of a message under a key.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace rasp {

/// The size of a SHA-256 digest, in bytes.
inline constexpr std::size_t kSha256Size = 32;

/// A SHA-256 digest.
using Sha256Digest = std::array<std::uint8_t, kSha256Size>;

/// Computes the SHA-256 digest of some bytes, as FIPS 180-4 defines it.
///
/// Any number of bytes can be hashed, including none.
///
/// @param data The bytes to hash.
/// @return The 32-byte digest.
[[nodiscard]] Sha256Digest sha256(std::span<const std::uint8_t> data);

/// Computes the HMAC-SHA256 of a message under a key, as RFC 2104 defines it.
///
/// A key of any size is accepted. A key longer than 64 bytes, the SHA-256 block size, is first replaced with its
/// SHA-256 digest, and a shorter one is padded with zeros, as RFC 2104 says.
///
/// @param key The secret key.
/// @param message The bytes to authenticate.
/// @return The 32-byte tag.
[[nodiscard]] Sha256Digest hmac_sha256(std::span<const std::uint8_t> key, std::span<const std::uint8_t> message);

}  // namespace rasp
