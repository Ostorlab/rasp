/// serialise_observations and serialise_request: the reporting plugin's JSON writer.

#include "json.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "config.h"
#include "rasp/observation.h"

namespace rasp::plugins::reporting {

namespace {

/// The hexadecimal digits, in lowercase.
constexpr std::string_view kHexDigits = "0123456789abcdef";
/// The escape written for a byte that doesn't start a valid UTF-8 sequence: U+FFFD, the replacement character.
constexpr std::string_view kReplacement = "\\ufffd";

/// Whether a byte is a UTF-8 continuation byte within `low` and `high`.
///
/// @param byte The byte.
/// @param low The smallest byte accepted.
/// @param high The largest byte accepted.
/// @return `true` when `low <= byte <= high`.
[[nodiscard]] constexpr bool in_range(unsigned char byte, unsigned char low, unsigned char high) {
  return byte >= low && byte <= high;
}

/// The length of the valid UTF-8 sequence that starts `text`, a non-ASCII lead byte, by the well-formed byte sequences
/// of the Unicode standard: no overlong form, no surrogate and nothing above U+10FFFF.
///
/// @param text The bytes, starting at the lead byte.
/// @return 2, 3 or 4. 0 when `text` doesn't start with a valid sequence.
[[nodiscard]] std::size_t sequence_length(std::string_view text) {
  const auto byte = [&text](std::size_t index) { return static_cast<unsigned char>(text[index]); };
  const unsigned char lead = byte(0);
  std::size_t length = 0;
  unsigned char low = 0x80;
  unsigned char high = 0xBF;
  if (in_range(lead, 0xC2, 0xDF)) {
    length = 2;
  } else if (in_range(lead, 0xE0, 0xEF)) {
    length = 3;
    low = lead == 0xE0 ? 0xA0 : 0x80;
    high = lead == 0xED ? 0x9F : 0xBF;
  } else if (in_range(lead, 0xF0, 0xF4)) {
    length = 4;
    low = lead == 0xF0 ? 0x90 : 0x80;
    high = lead == 0xF4 ? 0x8F : 0xBF;
  } else {
    return 0;
  }
  if (text.size() < length || !in_range(byte(1), low, high)) {
    return 0;
  }
  for (std::size_t index = 2; index < length; ++index) {
    if (!in_range(byte(index), 0x80, 0xBF)) {
      return 0;
    }
  }
  return length;
}

/// Appends `text` to `out` as a JSON string, between quotes.
///
/// The quote, the backslash and the control characters are escaped, and so is DEL. Valid UTF-8 sequences are copied as
/// they are, and every other byte above 0x7F is written as U+FFFD.
///
/// @param out The JSON being written.
/// @param text The bytes of the string.
void append_string(std::string& out, std::string_view text) {
  out.push_back('"');
  std::size_t index = 0;
  while (index < text.size()) {
    const auto byte = static_cast<unsigned char>(text[index]);
    if (byte >= 0x80) {
      const std::size_t length = sequence_length(text.substr(index));
      if (length == 0) {
        out.append(kReplacement);
        ++index;
      } else {
        out.append(text.substr(index, length));
        index += length;
      }
      continue;
    }
    switch (byte) {
      case '"':
        out.append("\\\"");
        break;
      case '\\':
        out.append("\\\\");
        break;
      case '\b':
        out.append("\\b");
        break;
      case '\f':
        out.append("\\f");
        break;
      case '\n':
        out.append("\\n");
        break;
      case '\r':
        out.append("\\r");
        break;
      case '\t':
        out.append("\\t");
        break;
      default:
        if (byte < 0x20 || byte == 0x7F) {
          out.append("\\u00");
          out.push_back(kHexDigits[byte >> 4U]);
          out.push_back(kHexDigits[byte & 0x0FU]);
        } else {
          out.push_back(static_cast<char>(byte));
        }
    }
    ++index;
  }
  out.push_back('"');
}

/// Appends an integer to `out` in decimal.
///
/// @param out The JSON being written.
/// @param number The integer.
void append_integer(std::string& out, std::int64_t number) { out.append(std::to_string(number)); }

/// The GraphQL name of a status, a value of the `ObservationStatus` enum.
///
/// @param status The status.
/// @return `OK`, `UNSUPPORTED`, `ERROR` or `TIMEOUT`. Nothing for a value that is not a known status.
[[nodiscard]] std::optional<std::string_view> status_name(Status status) {
  switch (status) {
    case Status::kOk:
      return "OK";
    case Status::kUnsupported:
      return "UNSUPPORTED";
    case Status::kError:
      return "ERROR";
    case Status::kTimeout:
      return "TIMEOUT";
  }
  return std::nullopt;
}

/// Appends a list of strings to `out` as a JSON list.
///
/// @param out The JSON being written.
/// @param list The list.
/// @param limit The size `out` must stay within.
/// @return `true` when `out` stayed within `limit`.
[[nodiscard]] bool append_list(std::string& out, const std::vector<std::string>& list, std::size_t limit) {
  out.push_back('[');
  bool first = true;
  for (const std::string& item : list) {
    if (!first) {
      out.push_back(',');
    }
    first = false;
    append_string(out, item);
    if (out.size() > limit) {
      return false;
    }
  }
  out.push_back(']');
  return true;
}

/// Appends a value to `out` as JSON: null, or an `ObservationValueInput`, an object with one field that names the
/// value's type: `bool`, `long` (the integer as a decimal string), `string` or `strings`.
///
/// @param out The JSON being written.
/// @param value The value.
/// @param limit The size `out` must stay within.
/// @return `true` when `out` stayed within `limit`.
[[nodiscard]] bool append_value(std::string& out, const Value& value, std::size_t limit) {
  if (const auto* const flag = std::get_if<bool>(&value)) {
    out.append(*flag ? R"({"bool":true})" : R"({"bool":false})");
    return true;
  }
  if (const auto* const number = std::get_if<std::int64_t>(&value)) {
    out.append(R"({"long":")");
    append_integer(out, *number);
    out.append(R"("})");
    return true;
  }
  if (const auto* const text = std::get_if<std::string>(&value)) {
    out.append(R"({"string":)");
    append_string(out, *text);
    out.push_back('}');
    return out.size() <= limit;
  }
  if (const auto* const list = std::get_if<std::vector<std::string>>(&value)) {
    out.append(R"({"strings":)");
    if (!append_list(out, *list, limit)) {
      return false;
    }
    out.push_back('}');
    return out.size() <= limit;
  }
  out.append("null");
  return true;
}

/// Appends one observation to `out` as a JSON `ObservationInput` object.
///
/// @param out The JSON being written.
/// @param observation The observation.
/// @param status The JSON name of the observation's status.
/// @param limit The size `out` must stay within.
/// @return `true` when `out` stayed within `limit`.
[[nodiscard]] bool append_observation(std::string& out, const Observation& observation, std::string_view status,
                                      std::size_t limit) {
  out.append(R"({"signal":)");
  append_string(out, observation.signal);
  out.append(R"(,"source":)");
  append_string(out, observation.source);
  out.append(R"(,"status":")");
  out.append(status);
  out.append(R"(","value":)");
  if (out.size() > limit || !append_value(out, observation.value, limit)) {
    return false;
  }
  out.push_back('}');
  return out.size() <= limit;
}

}  // namespace

std::optional<std::string> serialise_observations(std::span<const Observation> observations, std::size_t limit) {
  std::string out = "[";
  for (const Observation& observation : observations) {
    const std::optional<std::string_view> status = status_name(observation.status);
    if (!status.has_value()) {
      continue;
    }
    if (out.size() > 1) {
      out.push_back(',');
    }
    if (!append_observation(out, observation, *status, limit)) {
      return std::nullopt;
    }
  }
  out.push_back(']');
  if (out.size() > limit) {
    return std::nullopt;
  }
  return out;
}

std::optional<std::string> serialise_request(const Config& config, std::string_view observations, std::size_t limit) {
  std::string out = R"({"query":)";
  append_string(out, kMutation);
  out.append(R"(,"variables":{"batch":{"installId":)");
  append_string(out, config.install_id.has_value() ? std::string_view{*config.install_id} : kZeroUuid);
  out.append(R"(,"sessionId":)");
  append_string(out, kZeroUuid);
  out.append(R"(,"buildId":)");
  append_string(out, config.build_id);
  out.append(R"(,"observations":)");
  constexpr std::string_view kEnd = "}}}";
  if (out.size() + observations.size() + kEnd.size() > limit) {
    return std::nullopt;
  }
  out.append(observations);
  out.append(kEnd);
  return out;
}

}  // namespace rasp::plugins::reporting
