/// base64: the standard base64 of RFC 4648 section 4, with padding.

#pragma once

#include <cstdint>
#include <span>
#include <string>

namespace rasp::plugins::adr_pin {

/// Encodes bytes as standard base64 (alphabet `A-Z a-z 0-9 + /`), padded with `=` to a multiple of four characters.
///
/// @param data The bytes to encode.
/// @return The text, `4 * ceil(data.size() / 3)` characters long.
[[nodiscard]] std::string base64(std::span<const std::uint8_t> data);

}  // namespace rasp::plugins::adr_pin
