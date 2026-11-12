/// Secure random UUID generation shared by installation and telemetry identity.
#include "rasp/util/uuid.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>
namespace rasp::util {
namespace {
/// Number of random bytes in a UUID.
constexpr std::size_t kUuidBytes = 16;
/// Text length of a UUID.
constexpr std::size_t kUuidLength = 36;
/// Hyphen offsets in UUID text.
constexpr std::array<std::size_t, 4> kHyphens{8, 13, 18, 23};
/// Lowercase hexadecimal digits.
constexpr std::string_view kHexDigits = "0123456789abcdef";
}  // namespace
/// Makes a new random UUID, version 4, from `arc4random_buf`, which can't fail.
///
/// @return Its text, 36 lowercase characters.
std::string new_uuid() {
  constexpr unsigned kVersionMask = 0x0FU;
  constexpr unsigned kVersion4 = 0x40U;
  constexpr unsigned kVariantMask = 0x3FU;
  constexpr unsigned kVariantRfc = 0x80U;
  std::array<std::uint8_t, kUuidBytes> bytes{};
  arc4random_buf(bytes.data(), bytes.size());
  bytes[6] = static_cast<std::uint8_t>((unsigned{bytes[6]} & kVersionMask) | kVersion4);
  bytes[8] = static_cast<std::uint8_t>((unsigned{bytes[8]} & kVariantMask) | kVariantRfc);
  std::string text;
  text.reserve(kUuidLength);
  for (const std::uint8_t byte : bytes) {
    if (std::ranges::find(kHyphens, text.size()) != kHyphens.end()) {
      text.push_back('-');
    }
    text.push_back(kHexDigits[byte >> 4U]);
    text.push_back(kHexDigits[byte & 0x0FU]);
  }
  return text;
}

}  // namespace rasp::util
