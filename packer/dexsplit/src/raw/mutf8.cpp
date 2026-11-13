#include "raw/mutf8.hpp"

#include <algorithm>

#include "raw/parsing_utils.hpp"

namespace dexsplit::raw::mutf8 {

namespace {

bool is_high_surrogate(uint32_t u) { return u >= 0xD800 && u <= 0xDBFF; }
bool is_low_surrogate(uint32_t u) { return u >= 0xDC00 && u <= 0xDFFF; }

// Append code point @p cp (or a lone surrogate) as UTF-8 / WTF-8.
void append_utf8(uint32_t cp, std::string &out)
{
    if (cp < 0x80) {
        out.push_back(static_cast<char>(cp));
    }
    else if (cp < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
    else if (cp < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
    else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

// Append one UTF-16 code unit as its MUTF-8 bytes (1 to 3 bytes; U+0000 is C0 80).
void append_unit(uint32_t unit, std::vector<uint8_t> &out)
{
    if (unit != 0 && unit < 0x80) {
        out.push_back(static_cast<uint8_t>(unit));
    }
    else if (unit < 0x800) {
        out.push_back(static_cast<uint8_t>(0xC0 | (unit >> 6)));
        out.push_back(static_cast<uint8_t>(0x80 | (unit & 0x3F)));
    }
    else {
        out.push_back(static_cast<uint8_t>(0xE0 | (unit >> 12)));
        out.push_back(static_cast<uint8_t>(0x80 | ((unit >> 6) & 0x3F)));
        out.push_back(static_cast<uint8_t>(0x80 | (unit & 0x3F)));
    }
}

// Length of the well-formed WTF-8 sequence starting at s[pos], or 0 if there
// is none.  Surrogate code points are accepted as 3-byte sequences.
std::size_t sequence_length(std::string_view s, std::size_t pos)
{
    auto byte = [&](std::size_t i) { return static_cast<uint8_t>(s[i]); };
    auto cont = [&](std::size_t i) { return i < s.size() && (byte(i) & 0xC0) == 0x80; };
    uint8_t b = byte(pos);
    if (b < 0x80)
        return 1;
    if (b >= 0xC2 && b <= 0xDF)
        return cont(pos + 1) ? 2 : 0;
    if (b >= 0xE0 && b <= 0xEF) {
        if (!cont(pos + 1) || !cont(pos + 2))
            return 0;
        if (b == 0xE0 && byte(pos + 1) < 0xA0) // overlong
            return 0;
        return 3;
    }
    if (b >= 0xF0 && b <= 0xF4) {
        if (!cont(pos + 1) || !cont(pos + 2) || !cont(pos + 3))
            return 0;
        if (b == 0xF0 && byte(pos + 1) < 0x90) // overlong
            return 0;
        if (b == 0xF4 && byte(pos + 1) > 0x8F) // above U+10FFFF
            return 0;
        return 4;
    }
    return 0;
}

// Yields the UTF-16 code units of valid WTF-8, one at a time.
class Utf16Units
{
  public:
    explicit Utf16Units(std::string_view s) : s_(s) {}

    bool next(uint32_t &unit)
    {
        if (pending_ != 0) {
            unit = pending_;
            pending_ = 0;
            return true;
        }
        if (pos_ >= s_.size())
            return false;
        uint32_t cp = next_code_point(s_, pos_);
        if (cp >= 0x10000) {
            cp -= 0x10000;
            unit = 0xD800 + (cp >> 10);
            pending_ = 0xDC00 + (cp & 0x3FF);
        }
        else {
            unit = cp;
        }
        return true;
    }

  private:
    std::string_view s_;
    std::size_t pos_ = 0;
    uint32_t pending_ = 0;
};

} // namespace

std::expected<std::string, ParseError> decode_string_data(std::span<const uint8_t> buf,
                                                          uint32_t offset)
{
    auto malformed = [](uint32_t at, const char *what) {
        return std::unexpected(ParseError{ParseError::Code::InvalidUtf8String, what, at});
    };

    uint32_t pos = offset;
    auto size = parse_utils::read_uleb128(buf, pos);
    if (!size)
        return std::unexpected(size.error());

    std::string out;
    // Each code unit takes at least one byte, so the buffer bounds the size.
    out.reserve(std::min<std::size_t>(*size, buf.size() - pos));
    uint32_t pending_high = 0;
    for (uint32_t i = 0; i < *size; ++i) {
        if (pos >= buf.size())
            return malformed(pos, "string data runs past the end of the file");
        uint8_t b = buf[pos++];
        uint32_t unit;
        switch (b >> 4) {
        case 0x0:
            if (b == 0)
                return malformed(pos - 1, "string data shorter than its declared length");
            [[fallthrough]];
        case 0x1:
        case 0x2:
        case 0x3:
        case 0x4:
        case 0x5:
        case 0x6:
        case 0x7:
            unit = b;
            break;
        case 0xC:
        case 0xD: {
            if (pos >= buf.size())
                return malformed(pos, "string data runs past the end of the file");
            uint8_t b2 = buf[pos++];
            if ((b2 & 0xC0) != 0x80)
                return malformed(pos - 1, "illegal continuation byte in string data");
            unit = ((b & 0x1Fu) << 6) | (b2 & 0x3Fu);
            if (unit != 0 && unit < 0x80)
                return malformed(pos - 2, "overlong encoding in string data");
            break;
        }
        case 0xE: {
            if (buf.size() - pos < 2)
                return malformed(pos, "string data runs past the end of the file");
            uint8_t b2 = buf[pos++];
            uint8_t b3 = buf[pos++];
            if ((b2 & 0xC0) != 0x80 || (b3 & 0xC0) != 0x80)
                return malformed(pos - 2, "illegal continuation byte in string data");
            unit = ((b & 0x0Fu) << 12) | ((b2 & 0x3Fu) << 6) | (b3 & 0x3Fu);
            if (unit < 0x800)
                return malformed(pos - 3, "overlong encoding in string data");
            break;
        }
        default:
            return malformed(pos - 1, "illegal start byte in string data");
        }

        if (pending_high != 0) {
            if (is_low_surrogate(unit)) {
                append_utf8(0x10000 + ((pending_high - 0xD800) << 10) + (unit - 0xDC00), out);
                pending_high = 0;
                continue;
            }
            append_utf8(pending_high, out);
            pending_high = 0;
        }
        if (is_high_surrogate(unit))
            pending_high = unit;
        else
            append_utf8(unit, out);
    }
    if (pending_high != 0)
        append_utf8(pending_high, out);

    if (pos >= buf.size() || buf[pos] != 0)
        return malformed(pos, "string data longer than its declared length");
    return out;
}

bool is_valid_wtf8(std::string_view s)
{
    std::size_t pos = 0;
    while (pos < s.size()) {
        std::size_t len = sequence_length(s, pos);
        if (len == 0)
            return false;
        pos += len;
    }
    return true;
}

uint32_t next_code_point(std::string_view s, std::size_t &pos)
{
    auto byte = [&](std::size_t i) { return static_cast<uint32_t>(static_cast<uint8_t>(s[i])); };
    uint32_t b = byte(pos);
    if (b < 0x80) {
        pos += 1;
        return b;
    }
    if (b < 0xE0) {
        uint32_t cp = ((b & 0x1F) << 6) | (byte(pos + 1) & 0x3F);
        pos += 2;
        return cp;
    }
    if (b < 0xF0) {
        uint32_t cp = ((b & 0x0F) << 12) | ((byte(pos + 1) & 0x3F) << 6) | (byte(pos + 2) & 0x3F);
        pos += 3;
        return cp;
    }
    uint32_t cp = ((b & 0x07) << 18) | ((byte(pos + 1) & 0x3F) << 12) |
                  ((byte(pos + 2) & 0x3F) << 6) | (byte(pos + 3) & 0x3F);
    pos += 4;
    return cp;
}

std::string canonical(std::string_view s)
{
    std::string out;
    out.reserve(s.size());
    std::size_t pos = 0;
    while (pos < s.size()) {
        std::size_t start = pos;
        uint32_t cp = next_code_point(s, pos);
        if (is_high_surrogate(cp) && pos < s.size()) {
            std::size_t after = pos;
            uint32_t lo = next_code_point(s, after);
            if (is_low_surrogate(lo)) {
                append_utf8(0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00), out);
                pos = after;
                continue;
            }
        }
        out.append(s.substr(start, pos - start));
    }
    return out;
}

bool is_canonical(std::string_view s)
{
    // A high surrogate is ED A0..AF xx; a low one ED B0..BF xx.
    for (std::size_t i = 0; i + 5 < s.size(); ++i) {
        if (static_cast<uint8_t>(s[i]) == 0xED && (static_cast<uint8_t>(s[i + 1]) & 0xF0) == 0xA0 &&
            static_cast<uint8_t>(s[i + 3]) == 0xED &&
            (static_cast<uint8_t>(s[i + 4]) & 0xF0) == 0xB0)
            return false;
    }
    return true;
}

uint32_t utf16_length(std::string_view s)
{
    uint32_t units = 0;
    std::size_t pos = 0;
    while (pos < s.size())
        units += next_code_point(s, pos) >= 0x10000 ? 2 : 1;
    return units;
}

void append_mutf8(std::string_view s, std::vector<uint8_t> &out)
{
    std::size_t pos = 0;
    while (pos < s.size()) {
        uint32_t cp = next_code_point(s, pos);
        if (cp >= 0x10000) {
            cp -= 0x10000;
            append_unit(0xD800 + (cp >> 10), out);
            append_unit(0xDC00 + (cp & 0x3FF), out);
        }
        else {
            append_unit(cp, out);
        }
    }
}

int compare_utf16(std::string_view a, std::string_view b)
{
    // UTF-8 byte order is code point order, which differs from UTF-16 order
    // only between a supplementary character and U+E000..U+FFFF.  So skip the
    // common prefix bytewise and compare code units from the code point where
    // the strings first differ.
    std::size_t n = std::min(a.size(), b.size());
    std::size_t i = 0;
    while (i < n && a[i] == b[i])
        ++i;
    if (i == n)
        return a.size() < b.size() ? -1 : (a.size() > b.size() ? 1 : 0);
    while (i > 0 && (static_cast<uint8_t>(a[i]) & 0xC0) == 0x80)
        --i; // back to the start of the code point (the same in both strings)
    a.remove_prefix(i);
    b.remove_prefix(i);
    Utf16Units ua(a);
    Utf16Units ub(b);
    while (true) {
        uint32_t x = 0;
        uint32_t y = 0;
        bool has_x = ua.next(x);
        bool has_y = ub.next(y);
        if (!has_x || !has_y)
            return has_x ? 1 : (has_y ? -1 : 0);
        if (x != y)
            return x < y ? -1 : 1;
    }
}

} // namespace dexsplit::raw::mutf8
