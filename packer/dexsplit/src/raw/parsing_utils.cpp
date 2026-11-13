#include "raw/parsing_utils.hpp"

#include "common/budget.hpp"

namespace dexsplit::raw::parse_utils {

std::expected<std::uint32_t, ParseError> read_uint32(std::span<const std::uint8_t> buf, std::uint32_t& offset) {
  // Subtractive form avoids the uint32 overflow that `offset + 4 > size`
  // suffers when offset is near UINT32_MAX (a crafted header field).
  if (offset > buf.size() || buf.size() - offset < 4) {
    return std::unexpected(ParseError::out_of_bounds(offset, "read_uint32"));
  }
  std::uint32_t b0 = buf[offset];
  std::uint32_t b1 = buf[offset + 1];
  std::uint32_t b2 = buf[offset + 2];
  std::uint32_t b3 = buf[offset + 3];
  offset += 4;
  return b0 | (b1 << 8U) | (b2 << 16U) | (b3 << 24U);
}

std::expected<std::uint16_t, ParseError> read_uint16(std::span<const std::uint8_t> buf, std::uint32_t& offset) {
  if (offset > buf.size() || buf.size() - offset < 2) {
    return std::unexpected(ParseError::out_of_bounds(offset, "read_uint16"));
  }
  std::uint32_t b0 = buf[offset];
  std::uint32_t b1 = buf[offset + 1];
  offset += 2;
  return static_cast<std::uint16_t>(b0 | (b1 << 8U));
}

std::expected<std::uint32_t, ParseError> read_uleb128(std::span<const std::uint8_t> buf, std::uint32_t& offset) {
  std::uint32_t result = 0;
  uint32_t shift = 0;

  for (int i = 0; i < 5; ++i) {
    if (offset >= buf.size()) {
      return std::unexpected(ParseError::out_of_bounds(offset, "read_uleb128"));
    }
    std::uint8_t cur = buf[offset++];
    if (i == 4U && (cur & 0xF0U) != 0U) {
      return std::unexpected(ParseError{ParseError::Code::InvalidLeb128, "ULEB128 overflow", offset});
    }
    result |= static_cast<std::uint32_t>(cur & 0x7FU) << shift;
    if (!(cur & 0x80U)) {
      return result;
    }
    shift += 7;
  }
  return std::unexpected(ParseError{ParseError::Code::InvalidLeb128, "ULEB128 value exceeds 5 bytes", offset});
}

std::expected<std::int32_t, ParseError> read_sleb128(std::span<const std::uint8_t> buf, std::uint32_t& offset) {
  std::uint32_t result = 0;
  uint32_t shift = 0;

  for (int i = 0; i < 5; ++i) {
    if (offset >= buf.size()) {
      return std::unexpected(ParseError::out_of_bounds(offset, "read_sleb128"));
    }
    std::uint8_t cur = buf[offset++];
    if (i == 4U && (cur & 0xF8U) != 0U && (cur & 0xF8U) != 0x78U) {
      return std::unexpected(ParseError{ParseError::Code::InvalidLeb128, "SLEB128 overflow", offset});
    }
    result |= static_cast<std::uint32_t>(cur & 0x7fU) << shift;
    shift += 7;

    if (!(cur & 0x80U)) {
      if (shift < 32U && (cur & 0x40U)) {
        result |= (~0U << shift);
      }
      return static_cast<std::int32_t>(result);
    }
  }
  return std::unexpected(ParseError{ParseError::Code::InvalidLeb128, "SLEB128 value exceeds 5 bytes", offset});
}

namespace {

/** True for a continuation byte of a multi-byte sequence: 10xxxxxx. */
bool is_continuation(std::uint8_t byte) { return (byte & 0xC0U) == 0x80U; }

/** The error for a malformed sequence that starts at @p start. */
std::unexpected<ParseError> invalid_sequence(std::uint32_t start) {
  return std::unexpected(ParseError{ParseError::Code::InvalidUtf8String, "decode_mutf8: invalid byte sequence", start});
}

}  // namespace

std::expected<budget::String, ParseError> decode_mutf8(std::span<const std::uint8_t> buf, std::uint32_t& offset) {
  budget::String str;
  while (true) {
    if (offset >= buf.size()) {
      return std::unexpected(ParseError::out_of_bounds(offset, "decode_mutf8: missing null terminator"));
    }
    if (buf[offset] == 0) {
      offset++;
      return str;
    }
    std::uint32_t start = offset;
    std::uint8_t b1 = buf[offset++];
    if ((b1 & 0x80U) == 0U) {
      str += static_cast<char>(b1);
    } else if ((b1 & 0xE0U) == 0xC0U) {
      if (offset >= buf.size()) {
        return std::unexpected(ParseError::out_of_bounds(offset, "decode_mutf8: truncated 2-byte sequence"));
      }
      std::uint8_t b2 = buf[offset++];
      if (!is_continuation(b2)) {
        return invalid_sequence(start);
      }
      if (b1 == 0xC0 && b2 == 0x80) {
        str += '\0';
        continue;
      }
      // C0 and C1 lead only overlong forms; MUTF-8 allows C0 80 alone.
      if (b1 < 0xC2) {
        return invalid_sequence(start);
      }
      str += static_cast<char>(b1);
      str += static_cast<char>(b2);
    } else if ((b1 & 0xF0U) == 0xE0U) {
      // Needs two more bytes (b2, b3).  offset <= buf.size() here, so the
      // subtractive form is overflow-safe.
      if (buf.size() - offset < 2) {
        return std::unexpected(ParseError::out_of_bounds(offset, "decode_mutf8: truncated 3-byte sequence"));
      }
      std::uint8_t b2 = buf[offset++];
      std::uint8_t b3 = buf[offset++];
      if (!is_continuation(b2) || !is_continuation(b3)) {
        return invalid_sequence(start);
      }
      std::uint32_t cu = (static_cast<std::uint32_t>(b1 & 0x0FU) << 12U) |
                         (static_cast<std::uint32_t>(b2 & 0x3FU) << 6U) | static_cast<std::uint32_t>(b3 & 0x3FU);
      if (cu < 0x800) {
        return invalid_sequence(start);
      }

      // MUTF-8 encodes supplementary characters as a surrogate PAIR of
      // two 3-byte sequences (CESU-8). Combine a high surrogate with a
      // following well-formed low surrogate into one code point and emit
      // it as proper 4-byte UTF-8, so the result is always valid UTF-8
      // (not CESU-8).
      if (cu >= 0xD800U && cu <= 0xDBFFU && buf.size() - offset >= 3U && (buf[offset] & 0xF0U) == 0xE0U &&
          is_continuation(buf[offset + 1]) && is_continuation(buf[offset + 2])) {
        std::uint32_t lo = (static_cast<std::uint32_t>(buf[offset] & 0x0FU) << 12U) |
                           (static_cast<std::uint32_t>(buf[offset + 1U] & 0x3FU) << 6U) |
                           static_cast<std::uint32_t>(buf[offset + 2U] & 0x3FU);
        if (lo >= 0xDC00 && lo <= 0xDFFF) {
          offset += 3;
          std::uint32_t cp = 0x10000U + ((cu - 0xD800U) << 10U) + (lo - 0xDC00U);
          str += static_cast<char>(0xF0U | (cp >> 18U));
          str += static_cast<char>(0x80U | ((cp >> 12U) & 0x3FU));
          str += static_cast<char>(0x80U | ((cp >> 6U) & 0x3FU));
          str += static_cast<char>(0x80U | (cp & 0x3FU));
          continue;
        }
      }
      if (cu >= 0xD800 && cu <= 0xDFFF) {
        // A lone (unpaired) surrogate is not valid UTF-8; substitute the
        // Unicode replacement character U+FFFD to keep the result valid.
        str += static_cast<char>(0xEF);
        str += static_cast<char>(0xBF);
        str += static_cast<char>(0xBD);
      } else {
        str += static_cast<char>(b1);
        str += static_cast<char>(b2);
        str += static_cast<char>(b3);
      }
    } else {
      // A stray continuation byte, or a 4-byte lead: MUTF-8 writes a
      // character above U+FFFF as a surrogate pair, never as 4 bytes.
      return invalid_sequence(start);
    }
  }
}

}  // namespace dexsplit::raw::parse_utils
