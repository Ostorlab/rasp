/// parse_memory_map and find_mapping, over the text of `/proc/self/maps`.

#pragma once

#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace rasp::android::util {

/// One mapping of the memory map. Its text fields are views into the map text it was parsed from.
struct Mapping {
  /// The first address of the mapping.
  std::uintptr_t start = 0;
  /// The address just past the mapping.
  std::uintptr_t end = 0;
  bool readable = false;
  bool executable = false;
  /// Whether writes reach the backing object rather than a private copy.
  bool shared = false;
  /// The offset in the backing file or memfd where the mapping starts.
  std::uint64_t offset = 0;
  /// The device of the backing file, as `major:minor`.
  std::string_view device;
  std::uint64_t inode = 0;
  /// The pathname, without the ` (deleted)` the kernel adds after a file deleted since it was mapped. Empty for
  /// anonymous memory.
  std::string_view pathname;
  /// Whether the backing file was deleted after it was mapped.
  bool deleted = false;
  /// The whole line, without its line break.
  std::string_view line;
};

/// Parses the text of a memory map, in its address order; a line that doesn't parse is left out.
[[nodiscard]] std::vector<Mapping> parse_memory_map(std::string_view maps);

/// The mapping of `mappings` that holds `address`, or null.
///
/// @param mappings Mappings sorted by address, as parse_memory_map returns them.
[[nodiscard]] const Mapping* find_mapping(std::span<const Mapping> mappings, std::uintptr_t address);

}  // namespace rasp::android::util
