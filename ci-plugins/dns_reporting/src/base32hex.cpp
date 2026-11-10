/// Base32hex encoder: writes bytes as upper-case base32hex text without
/// padding.

#include "base32hex.h"

#include <array>
#include <cstdint>
#include <span>
#include <string>

namespace rasp::plugins::dns_reporting {

namespace {

/// The 32 characters of the base32hex alphabet (RFC 4648 section 7).
constexpr std::array<char, 32> kAlphabet = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
    'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
};

/// The number of bits per base32hex character.
constexpr std::uint32_t kBitsPerCharacter = 5;

/// The number of bits per input byte.
constexpr std::uint32_t kBitsPerByte = 8;

/// The mask for extracting one 5-bit character value.
constexpr std::uint32_t kCharacterMask = 0x1F;

}  // namespace

std::string encode(std::span<const std::uint8_t> data) {
  std::string output;
  output.reserve(encoded_size(data.size()));

  std::uint32_t buffer = 0;
  std::uint32_t buffered_bits = 0;

  for (const std::uint8_t byte : data) {
    buffer = (buffer << kBitsPerByte) | static_cast<std::uint32_t>(byte);
    buffered_bits += kBitsPerByte;

    while (buffered_bits >= kBitsPerCharacter) {
      const std::uint32_t shift = buffered_bits - kBitsPerCharacter;
      // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
      output += kAlphabet[(buffer >> shift) & kCharacterMask];
      buffered_bits -= kBitsPerCharacter;
    }

    buffer &= (static_cast<std::uint32_t>(1) << buffered_bits) - 1;
  }

  if (buffered_bits > 0) {
    const std::uint32_t shift = kBitsPerCharacter - buffered_bits;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
    output += kAlphabet[(buffer << shift) & kCharacterMask];
  }

  return output;
}

}  // namespace rasp::plugins::dns_reporting
