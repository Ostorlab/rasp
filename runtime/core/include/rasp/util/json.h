/// JSON string writing.

#pragma once

#include <string>
#include <string_view>

namespace rasp::json {

/// Writes a text as a JSON string and appends it to `out`. The result is always valid JSON, whatever bytes the text
/// holds.
///
/// The text is put in double quotes. A double quote, a backslash, a newline, a carriage return and a tab are each
/// written as a backslash followed by one character: the quote, the backslash, `n`, `r` or `t`. Every other control
/// character, below 0x20, is written as a backslash, the letter `u` and four hex digits, for example `u0001` for the
/// character 1 and `u001f` for the character 0x1F.
///
/// Valid UTF-8 is copied as it is. The text is checked strictly: an overlong form (such as C0 80), a surrogate (ED A0
/// to ED BF), a code point above U+10FFFF, a sequence cut short by the end of the text, and a continuation byte that
/// doesn't follow a lead byte are all invalid. Each byte that doesn't start a valid sequence is replaced with U+FFFD,
/// the replacement character, written as its three UTF-8 bytes (EF BF BD), and the writing resumes at the next byte.
/// So an invalid sequence of several bytes gives one replacement character for each of its bytes.
///
/// @param out The string to append to. What it already holds is kept.
/// @param value The text to write.
void append_string(std::string& out, std::string_view value);

}  // namespace rasp::json
