#include "common/budget.hpp"
#pragma once

#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "raw/error.hpp"

/** Lossless conversion between DEX string data (MUTF-8) and C++ strings.
 *
 *  DEX strings are sequences of UTF-16 code units, stored as MUTF-8: every
 *  code unit is encoded on its own (1 to 3 bytes), U+0000 is the two bytes
 *  C0 80, and a character above U+FFFF is a surrogate pair — two 3-byte
 *  sequences.  The format allows *unpaired* surrogates in string data.
 *
 *  These functions represent a DEX string as WTF-8: UTF-8, except that an
 *  unpaired surrogate is kept as its 3-byte sequence (ED A0..BF xx).  Every
 *  DEX string converts to exactly one canonical WTF-8 string and back:
 *  supplementary characters are 4-byte UTF-8 sequences, U+0000 is a plain
 *  0x00 byte.  Ordinary text is ordinary UTF-8.
 *
 *  (The analysis layer's `parse_utils::decode_mutf8` is different on purpose:
 *  it replaces unpaired surrogates with U+FFFD so its output is always valid
 *  UTF-8, which Python needs.) */
namespace dexsplit::raw::mutf8 {

/** Decode the string_data_item at @p offset: a uleb128 UTF-16 length, the
 *  MUTF-8 bytes, and a 0 terminator.  Validation follows ART's verifier: no
 *  4-byte sequences or stray continuation bytes, no overlong forms other than
 *  C0 80, correct continuation bytes, and exactly the declared number of
 *  UTF-16 code units before the terminator.  Returns canonical WTF-8. */
std::expected<budget::String, ParseError> decode_string_data(std::span<const uint8_t> buf, uint32_t offset);

/** True if @p s is well-formed WTF-8: valid UTF-8 sequences (shortest form, at
 *  most U+10FFFF), where the surrogate code points U+D800..U+DFFF are allowed
 *  as 3-byte sequences. */
bool is_valid_wtf8(std::string_view s);

/** The canonical form of valid WTF-8 @p s: a surrogate pair written as two
 *  3-byte sequences becomes one 4-byte sequence.  Two strings are the same DEX
 *  string exactly when their canonical forms are equal. */
budget::String canonical(std::string_view s);

/** True if valid WTF-8 @p s is already canonical: it has no surrogate pair
 *  written as two 3-byte sequences. */
bool is_canonical(std::string_view s);

/** Number of UTF-16 code units in valid WTF-8 @p s (the string_data_item's
 *  utf16_size). */
uint32_t utf16_length(std::string_view s);

/** Append the MUTF-8 bytes of valid WTF-8 @p s to @p out, without a terminator. */
void append_mutf8(std::string_view s, budget::Vector<uint8_t>& out);

/** Compare two valid WTF-8 strings by their UTF-16 code units — the order the
 *  DEX format requires for string_ids.  It differs from byte order: U+E000 ..
 *  U+FFFF sort after supplementary characters, whose surrogates start at
 *  0xD800.  Returns a negative, zero or positive value. */
int compare_utf16(std::string_view a, std::string_view b);

/** Decode one code point (or lone surrogate) from valid WTF-8 at @p pos and
 *  advance @p pos past it.  Precondition: pos < s.size() and s is valid. */
uint32_t next_code_point(std::string_view s, std::size_t& pos);

}  // namespace dexsplit::raw::mutf8
