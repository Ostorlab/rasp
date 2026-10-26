/// sha256_hex, the SHA-256 of the iOS checks, computed with TF-PSA-Crypto.

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace rasp::ios::util {

/// The SHA-256 of `bytes` in lowercase hex, computed with TF-PSA-Crypto's `psa_hash_compute`.
///
/// It starts TF-PSA-Crypto with `psa_crypto_init` first, which does nothing when it has already started.
///
/// @param bytes The bytes to hash.
/// @return The 64 hex digits of the digest, or nothing when TF-PSA-Crypto can't start or can't compute the digest.
[[nodiscard]] std::optional<std::string> sha256_hex(std::span<const std::uint8_t> bytes);

}  // namespace rasp::ios::util
