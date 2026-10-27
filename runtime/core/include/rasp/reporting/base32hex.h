/// Base32hex encoder of RFC 4648 section 7: upper-case extended hex alphabet, no padding.

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace rasp::reporting {

/// The number of base32hex characters that encode `byte_count` bytes: ceil(8 * byte_count / 5).
[[nodiscard]] constexpr std::size_t encoded_size(std::size_t byte_count) { return ((byte_count * 8) + 4) / 5; }

/// Encodes bytes as upper-case base32hex text without padding.
///
/// The alphabet is 0-9 A-V (RFC 4648 extended hex). The output is case-insensitive
/// when decoded, and carries safely through DNS labels that may change letter case.
///
/// @param data The bytes to encode.
/// @return The encoded text, `encoded_size(data.size())` characters long.
[[nodiscard]] std::string encode(std::span<const std::uint8_t> data);

}  // namespace rasp::reporting
