#include "raw/parsing_utils.hpp"

namespace dexsplit::raw::parse_utils {

std::expected<std::uint32_t, ParseError> read_uint32(std::span<const std::uint8_t> buf,
                                                     std::uint32_t &offset)
{
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
    return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
}

std::expected<std::uint16_t, ParseError> read_uint16(std::span<const std::uint8_t> buf,
                                                     std::uint32_t &offset)
{
    if (offset > buf.size() || buf.size() - offset < 2) {
        return std::unexpected(ParseError::out_of_bounds(offset, "read_uint16"));
    }
    std::uint16_t b0 = buf[offset];
    std::uint16_t b1 = buf[offset + 1];
    offset += 2;
    return static_cast<std::uint16_t>(b0 | (b1 << 8));
}

std::expected<std::uint32_t, ParseError> read_uleb128(std::span<const std::uint8_t> buf,
                                                      std::uint32_t &offset)
{
    std::uint32_t result = 0;
    int shift = 0;

    for (int i = 0; i < 5; ++i) {
        if (offset >= buf.size()) {
            return std::unexpected(ParseError::out_of_bounds(offset, "read_uleb128"));
        }
        std::uint8_t cur = buf[offset++];
        result |= static_cast<std::uint32_t>(cur & 0x7F) << shift;
        if (!(cur & 0x80)) {
            return result;
        }
        shift += 7;
    }
    return std::unexpected(
        ParseError{ParseError::Code::InvalidLeb128, "ULEB128 value exceeds 5 bytes", offset});
}

std::expected<std::int32_t, ParseError> read_sleb128(std::span<const std::uint8_t> buf,
                                                     std::uint32_t &offset)
{
    std::uint32_t result = 0;
    int shift = 0;

    for (int i = 0; i < 5; ++i) {
        if (offset >= buf.size()) {
            return std::unexpected(ParseError::out_of_bounds(offset, "read_sleb128"));
        }
        std::uint8_t cur = buf[offset++];
        result |= static_cast<std::uint32_t>(cur & 0x7f) << shift;
        shift += 7;

        if (!(cur & 0x80)) {
            if (shift < 32 && (cur & 0x40)) {
                result |= (~0U << shift);
            }
            return static_cast<std::int32_t>(result);
        }
    }
    return std::unexpected(
        ParseError{ParseError::Code::InvalidLeb128, "SLEB128 value exceeds 5 bytes", offset});
}

std::expected<std::string, ParseError> decode_mutf8(std::span<const std::uint8_t> buf,
                                                    std::uint32_t &offset)
{
    std::string str;
    while (true) {
        if (offset >= buf.size()) {
            return std::unexpected(
                ParseError::out_of_bounds(offset, "decode_mutf8: missing null terminator"));
        }
        if (buf[offset] == 0) {
            offset++;
            return str;
        }
        std::uint8_t b1 = buf[offset++];
        if (b1 == 0xC0) {
            if (offset >= buf.size()) {
                return std::unexpected(
                    ParseError::out_of_bounds(offset, "decode_mutf8: truncated 2-byte sequence"));
            }
            if (buf[offset] == 0x80) {
                str += '\0';
                offset++;
                continue;
            }
            // Not null encoding — treat as regular 2-byte UTF-8
            std::uint8_t b2 = buf[offset++];
            str += static_cast<char>(b1);
            str += static_cast<char>(b2);
        }
        else if ((b1 & 0x80) == 0) {
            str += static_cast<char>(b1);
        }
        else if ((b1 & 0xE0) == 0xC0) {
            if (offset >= buf.size()) {
                return std::unexpected(
                    ParseError::out_of_bounds(offset, "decode_mutf8: truncated 2-byte sequence"));
            }
            std::uint8_t b2 = buf[offset++];
            str += static_cast<char>(b1);
            str += static_cast<char>(b2);
        }
        else if ((b1 & 0xF0) == 0xE0) {
            // Needs two more bytes (b2, b3).  offset <= buf.size() here, so the
            // subtractive form is overflow-safe.
            if (buf.size() - offset < 2) {
                return std::unexpected(
                    ParseError::out_of_bounds(offset, "decode_mutf8: truncated 3-byte sequence"));
            }
            std::uint8_t b2 = buf[offset++];
            std::uint8_t b3 = buf[offset++];
            std::uint32_t cu = (static_cast<std::uint32_t>(b1 & 0x0F) << 12) |
                               (static_cast<std::uint32_t>(b2 & 0x3F) << 6) |
                               static_cast<std::uint32_t>(b3 & 0x3F);

            // MUTF-8 encodes supplementary characters as a surrogate PAIR of
            // two 3-byte sequences (CESU-8). Combine a high surrogate with a
            // following low surrogate into one code point and emit it as proper
            // 4-byte UTF-8, so the result is always valid UTF-8 (not CESU-8).
            if (cu >= 0xD800 && cu <= 0xDBFF && buf.size() - offset >= 3 &&
                (buf[offset] & 0xF0) == 0xE0) {
                std::uint32_t lo = (static_cast<std::uint32_t>(buf[offset] & 0x0F) << 12) |
                                   (static_cast<std::uint32_t>(buf[offset + 1] & 0x3F) << 6) |
                                   static_cast<std::uint32_t>(buf[offset + 2] & 0x3F);
                if (lo >= 0xDC00 && lo <= 0xDFFF) {
                    offset += 3;
                    std::uint32_t cp = 0x10000 + ((cu - 0xD800) << 10) + (lo - 0xDC00);
                    str += static_cast<char>(0xF0 | (cp >> 18));
                    str += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
                    str += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                    str += static_cast<char>(0x80 | (cp & 0x3F));
                    continue;
                }
            }
            if (cu >= 0xD800 && cu <= 0xDFFF) {
                // A lone (unpaired) surrogate is not valid UTF-8; substitute the
                // Unicode replacement character U+FFFD to keep the result valid.
                str += static_cast<char>(0xEF);
                str += static_cast<char>(0xBF);
                str += static_cast<char>(0xBD);
            }
            else {
                str += static_cast<char>(b1);
                str += static_cast<char>(b2);
                str += static_cast<char>(b3);
            }
        }
        else if ((b1 & 0xF8) == 0xF0) {
            // Needs three more bytes (b2, b3, b4).  The old `offset + 1 >= size`
            // guard read one past the end when offset + 2 == size.
            if (buf.size() - offset < 3) {
                return std::unexpected(
                    ParseError::out_of_bounds(offset, "decode_mutf8: truncated 4-byte sequence"));
            }
            std::uint8_t b2 = buf[offset++];
            std::uint8_t b3 = buf[offset++];
            std::uint8_t b4 = buf[offset++];
            str += static_cast<char>(b1);
            str += static_cast<char>(b2);
            str += static_cast<char>(b3);
            str += static_cast<char>(b4);
        }
        else {
            return std::unexpected(ParseError{ParseError::Code::InvalidUtf8String,
                                              "decode_mutf8: invalid byte sequence", offset - 1});
        }
    }
}

} // namespace dexsplit::raw::parse_utils
