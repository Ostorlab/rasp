#include "util/memory_map.h"

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <memory>
#include <optional>
#include <ranges>
#include <span>
#include <string_view>
#include <system_error>
#include <vector>

namespace rasp::android::util {

namespace {

/// What the kernel adds after the pathname of a file deleted since it was mapped.
constexpr std::string_view kDeletedSuffix = " (deleted)";
/// The permissions field: read, write, execute and private-or-shared.
constexpr std::size_t kPermissionsSize = 4;
/// The position of the execute permission in the permissions field.
constexpr std::size_t kExecutePosition = 2;
/// The position of the private-or-shared flag in the permissions field.
constexpr std::size_t kSharingPosition = 3;

/// Takes the next space-separated field off the front of `rest`.
[[nodiscard]] std::string_view next_field(std::string_view& rest) {
  const std::size_t end = std::min(rest.find(' '), rest.size());
  const std::string_view field = rest.substr(0, end);
  rest.remove_prefix(end);
  rest.remove_prefix(std::min(rest.find_first_not_of(' '), rest.size()));
  return field;
}

/// Parses all of `text` as a number in `base`.
template <typename T>
[[nodiscard]] std::optional<T> parse_number(std::string_view text, int base) {
  T value{};
  const char* const last = std::to_address(text.end());
  const auto [stop, error] = std::from_chars(std::to_address(text.begin()), last, value, base);
  if (text.empty() || error != std::errc{} || stop != last) {
    return std::nullopt;
  }
  return value;
}

[[nodiscard]] std::optional<Mapping> parse_line(std::string_view line) {
  std::string_view rest = line;
  const std::string_view range = next_field(rest);
  const std::string_view permissions = next_field(rest);
  const std::string_view offset = next_field(rest);
  const std::string_view device = next_field(rest);
  const std::string_view inode = next_field(rest);
  const std::size_t dash = range.find('-');
  if (dash == std::string_view::npos || permissions.size() != kPermissionsSize || device.empty()) {
    return std::nullopt;
  }
  const auto start = parse_number<std::uintptr_t>(range.substr(0, dash), 16);
  const auto end = parse_number<std::uintptr_t>(range.substr(dash + 1), 16);
  const auto file_offset = parse_number<std::uint64_t>(offset, 16);
  const auto inode_number = parse_number<std::uint64_t>(inode, 10);
  if (!start || !end || *end <= *start || !file_offset || !inode_number) {
    return std::nullopt;
  }
  const bool deleted = rest.ends_with(kDeletedSuffix);
  if (deleted) {
    rest.remove_suffix(kDeletedSuffix.size());
  }
  return Mapping{
      .start = *start,
      .end = *end,
      .readable = permissions.front() == 'r',
      .executable = permissions[kExecutePosition] == 'x',
      .shared = permissions[kSharingPosition] == 's',
      .offset = *file_offset,
      .device = device,
      .inode = *inode_number,
      .pathname = rest,
      .deleted = deleted,
      .line = line,
  };
}

}  // namespace

std::vector<Mapping> parse_memory_map(std::string_view maps) {
  std::vector<Mapping> mappings;
  for (const auto piece : std::views::split(maps, '\n')) {
    const std::optional<Mapping> mapping = parse_line(std::string_view(piece.begin(), piece.end()));
    if (mapping) {
      mappings.push_back(*mapping);
    }
  }
  return mappings;
}

const Mapping* find_mapping(std::span<const Mapping> mappings, std::uintptr_t address) {
  const auto after = std::ranges::upper_bound(mappings, address, {}, &Mapping::start);
  if (after == mappings.begin()) {
    return nullptr;
  }
  const Mapping& candidate = *std::prev(after);
  return address < candidate.end ? &candidate : nullptr;
}

}  // namespace rasp::android::util
