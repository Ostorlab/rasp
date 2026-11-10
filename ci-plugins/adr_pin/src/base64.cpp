/// base64: writes bytes as standard, padded base64 text.

#include "base64.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace rasp::plugins::adr_pin {

namespace {

/// The 64 characters of the standard base64 alphabet (RFC 4648 section 4).
constexpr std::string_view kAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The mask of one 6-bit character value.
constexpr std::uint32_t kCharacterMask = 0x3f;

}  // namespace

std::string base64(std::span<const std::uint8_t> data) {
  std::string output;
  output.reserve(((data.size() + 2) / 3) * 4);
  std::size_t index = 0;
  for (; data.size() - index >= 3; index += 3) {
    const std::uint32_t group =
        (std::uint32_t{data[index]} << 16U) | (std::uint32_t{data[index + 1]} << 8U) | std::uint32_t{data[index + 2]};
    output += kAlphabet[(group >> 18U) & kCharacterMask];
    output += kAlphabet[(group >> 12U) & kCharacterMask];
    output += kAlphabet[(group >> 6U) & kCharacterMask];
    output += kAlphabet[group & kCharacterMask];
  }
  const std::size_t left = data.size() - index;
  if (left == 1) {
    const std::uint32_t group = std::uint32_t{data[index]} << 16U;
    output += kAlphabet[(group >> 18U) & kCharacterMask];
    output += kAlphabet[(group >> 12U) & kCharacterMask];
    output += "==";
  } else if (left == 2) {
    const std::uint32_t group = (std::uint32_t{data[index]} << 16U) | (std::uint32_t{data[index + 1]} << 8U);
    output += kAlphabet[(group >> 18U) & kCharacterMask];
    output += kAlphabet[(group >> 12U) & kCharacterMask];
    output += kAlphabet[(group >> 6U) & kCharacterMask];
    output += '=';
  }
  return output;
}

}  // namespace rasp::plugins::adr_pin
