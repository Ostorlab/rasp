/// append_string: writes a text as a JSON string, with invalid UTF-8 replaced so the result is always valid JSON.

#include "rasp/util/json.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace rasp::json {

namespace {

/// U+FFFD, the replacement character, as its three UTF-8 bytes.
constexpr std::string_view kReplacementCharacter = "\xEF\xBF\xBD";

/// The lowercase hex digit for the lowest 4 bits of `value`.
[[nodiscard]] constexpr char hex_digit(std::uint32_t value) {
  constexpr std::string_view kHexDigits = "0123456789abcdef";
  return kHexDigits[value & 0xFU];
}

/// The byte at `index` in `value`, as a number from 0 to 255. The caller checks that `index` is in bounds.
[[nodiscard]] std::uint32_t byte_at(std::string_view value, std::size_t index) {
  return static_cast<std::uint32_t>(static_cast<unsigned char>(value[index]));
}

/// Whether `byte` is a UTF-8 continuation byte, from 0x80 to 0xBF.
[[nodiscard]] constexpr bool is_continuation(std::uint32_t byte) { return byte >= 0x80U && byte <= 0xBFU; }

/// The size of the valid UTF-8 sequence that starts at byte `index` of `value`, or 0 when the bytes there aren't one.
[[nodiscard]] std::size_t utf8_sequence_size(std::string_view value, std::size_t index) {
  const std::uint32_t lead = byte_at(value, index);
  std::size_t size = 0;
  std::uint32_t lowest_second = 0x80U;
  std::uint32_t highest_second = 0xBFU;
  if (lead >= 0xC2U && lead <= 0xDFU) {
    size = 2;
  } else if (lead == 0xE0U) {
    size = 3;
    lowest_second = 0xA0U;
  } else if (lead == 0xEDU) {
    size = 3;
    highest_second = 0x9FU;
  } else if (lead >= 0xE1U && lead <= 0xEFU) {
    size = 3;
  } else if (lead == 0xF0U) {
    size = 4;
    lowest_second = 0x90U;
  } else if (lead == 0xF4U) {
    size = 4;
    highest_second = 0x8FU;
  } else if (lead >= 0xF1U && lead <= 0xF3U) {
    size = 4;
  } else {
    return 0;
  }
  if (size > value.size() - index) {
    return 0;
  }
  const std::uint32_t second = byte_at(value, index + 1);
  if (second < lowest_second || second > highest_second) {
    return 0;
  }
  for (std::size_t offset = 2; offset < size; ++offset) {
    if (!is_continuation(byte_at(value, index + offset))) {
      return 0;
    }
  }
  return size;
}

/// Appends one ASCII character, below 0x80, to `out`, escaped as a JSON string requires.
void append_ascii(std::string& out, char c) {
  switch (c) {
    case '"':
      out += R"(\")";
      break;
    case '\\':
      out += R"(\\)";
      break;
    case '\n':
      out += R"(\n)";
      break;
    case '\r':
      out += R"(\r)";
      break;
    case '\t':
      out += R"(\t)";
      break;
    default: {
      const auto byte = static_cast<std::uint32_t>(static_cast<unsigned char>(c));
      if (byte < 0x20U) {
        out += R"(\u00)";
        out.push_back(hex_digit(byte >> 4U));
        out.push_back(hex_digit(byte));
      } else {
        out.push_back(c);
      }
    }
  }
}

}  // namespace

void append_string(std::string& out, std::string_view value) {
  out.push_back('"');
  std::size_t index = 0;
  while (index < value.size()) {
    if (byte_at(value, index) < 0x80U) {
      append_ascii(out, value[index]);
      ++index;
      continue;
    }
    const std::size_t size = utf8_sequence_size(value, index);
    if (size == 0) {
      out += kReplacementCharacter;
      ++index;
    } else {
      out += value.substr(index, size);
      index += size;
    }
  }
  out.push_back('"');
}

}  // namespace rasp::json
