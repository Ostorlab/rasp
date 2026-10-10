/// random_uuid, which fills a Uuid from arc4random_buf and marks it as version 4, and to_string, which writes its
/// text form.

#include "rasp/util/uuid.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>

namespace rasp {

namespace {

/// The number of characters in the text form of a UUID.
constexpr std::size_t kTextSize = 36;

/// The lowercase hex digit for the lowest 4 bits of `value`.
[[nodiscard]] constexpr char hex_digit(std::uint32_t value) {
  constexpr std::string_view kHexDigits = "0123456789abcdef";
  return kHexDigits[value & 0x0FU];
}

}  // namespace

Uuid random_uuid() {
  Uuid uuid;
  arc4random_buf(uuid.bytes.data(), uuid.bytes.size());
  std::get<6>(uuid.bytes) = static_cast<std::uint8_t>((std::get<6>(uuid.bytes) & 0x0FU) | 0x40U);
  std::get<8>(uuid.bytes) = static_cast<std::uint8_t>((std::get<8>(uuid.bytes) & 0x3FU) | 0x80U);
  return uuid;
}

std::string to_string(const Uuid& uuid) {
  std::string text;
  text.reserve(kTextSize);
  std::size_t index = 0;
  for (const std::uint8_t byte : uuid.bytes) {
    if (index == 4 || index == 6 || index == 8 || index == 10) {
      text.push_back('-');
    }
    const auto value = static_cast<std::uint32_t>(byte);
    text.push_back(hex_digit(value >> 4U));
    text.push_back(hex_digit(value));
    ++index;
  }
  return text;
}

}  // namespace rasp
