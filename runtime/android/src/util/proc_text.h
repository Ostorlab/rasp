/// Bounded token and complete-table validation for the Android procfs probes.
#pragma once

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <memory>
#include <optional>
#include <ranges>
#include <string_view>
#include <system_error>

namespace rasp::android::util {

/// Whether a procfs task entry names a thread: a nonempty sequence of ASCII digits.
/// @param name The directory entry's file name.
/// @return True only for numeric thread names, before counting or reading their comm files.
[[nodiscard]] inline bool is_thread_id(std::string_view name) {
  return !name.empty() &&
         std::ranges::all_of(name, [](char character) { return character >= '0' && character <= '9'; });
}

/// Removes one space/tab-separated field and any following whitespace.
/// @param rest The remaining record, advanced past the returned field.
/// @return The next field, empty if the record has no field left.
[[nodiscard]] inline std::string_view take_proc_field(std::string_view& rest) {
  const std::size_t start = rest.find_first_not_of(" \t");
  rest.remove_prefix(std::min(start, rest.size()));
  const std::size_t end = std::min(rest.find_first_of(" \t"), rest.size());
  const std::string_view field = rest.substr(0, end);
  rest.remove_prefix(end);
  rest.remove_prefix(std::min(rest.find_first_not_of(" \t"), rest.size()));
  return field;
}

/// Parses an entire unsigned integer without allowing signs, whitespace or overflow.
/// @param text The integer's digits.
/// @param base The numeric base, ten or sixteen.
/// @return The value, or nothing if the entire field is not a representable unsigned integer.
[[nodiscard]] inline std::optional<std::uint64_t> proc_number(std::string_view text, int base) {
  if (text.empty()) {
    return std::nullopt;
  }
  std::uint64_t value = 0;
  const char* const end = std::to_address(text.end());
  const auto result = std::from_chars(std::to_address(text.begin()), end, value, base);
  if (result.ec != std::errc{} || result.ptr != end) {
    return std::nullopt;
  }
  return value;
}

/// Checks every complete record, including those beyond a probe's output cap.
/// @param table Bounded text read to EOF.
/// @param valid_line The record validator.
/// @return False for empty, truncated, control-byte, oversized-line or malformed data.
template <typename Validator>
[[nodiscard]] bool valid_proc_table(std::string_view table, Validator valid_line) {
  if (table.size() < 2 || !table.ends_with('\n')) {
    return false;
  }
  table.remove_suffix(1);
  for (const auto piece : std::views::split(table, '\n')) {
    const std::string_view line(piece.begin(), piece.end());
    if (line.empty() || line.size() > 8192 ||
        std::ranges::any_of(line, [](unsigned char byte) { return (byte < 32 && byte != '\t') || byte == 127; }) ||
        !valid_line(line)) {
      return false;
    }
  }
  return true;
}

}  // namespace rasp::android::util
