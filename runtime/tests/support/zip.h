/// A zip builder for the tests: makes an in-memory archive of stored (uncompressed) entries, the way the packer writes
/// the runtime's assets, so the runtime's APK reader parses it through the central directory.

#pragma once

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace rasp::test_support {

/// One stored entry to put in a test zip: its name and its bytes. The fields own their bytes: a view here would
/// dangle at the call sites, where the entries are built from temporary strings.
struct StoredEntry {
  /// The entry's full name in the archive, such as `assets/rasp/map.bin`, always a static literal at the call sites.
  std::string_view name;
  /// The entry's bytes, stored uncompressed. The field owns them: a view here would dangle at the call sites,
  /// where the entries are built from temporary strings.
  std::string content;
};

namespace zip_detail {

/// A little-endian field to append: a value and how many bytes wide it is. Grouping the two keeps callers from
/// swapping them.
struct Field {
  /// The value to append.
  std::uint64_t value = 0;
  /// The width in bytes, 1 to 8.
  std::size_t width = 0;
};

/// Appends a field to `out` as little-endian bytes.
///
/// @param out The bytes to append to.
/// @param field The value to append and its width in bytes.
inline void append_le(std::string& out, Field field) {
  for (std::size_t index = 0; index < field.width; ++index) {
    out.push_back(static_cast<char>((field.value >> (8U * index)) & 0xFFU));
  }
}

}  // namespace zip_detail

/// Builds a zip holding each entry in `entries`, stored (uncompressed), in order. The layout is one local file header
/// and the data per entry, then a central directory with one header per entry, then the End Of Central Directory
/// record.
///
/// @param entries The entries to store, in the order they are written.
/// @return The bytes of the archive.
[[nodiscard]] inline std::string zip_with_stored_entries(std::span<const StoredEntry> entries) {
  using zip_detail::append_le;

  std::string zip;
  std::vector<std::uint32_t> local_offsets;
  local_offsets.reserve(entries.size());

  for (const StoredEntry& entry : entries) {
    local_offsets.push_back(static_cast<std::uint32_t>(zip.size()));
    // Local file header.
    append_le(zip, {.value = 0x04034B50, .width = 4});            // signature
    append_le(zip, {.value = 20, .width = 2});                    // version needed
    append_le(zip, {.value = 0, .width = 2});                     // flags
    append_le(zip, {.value = 0, .width = 2});                     // method: stored
    append_le(zip, {.value = 0, .width = 2});                     // mod time
    append_le(zip, {.value = 0, .width = 2});                     // mod date
    append_le(zip, {.value = 0, .width = 4});                     // crc-32 (unchecked by the reader)
    append_le(zip, {.value = entry.content.size(), .width = 4});  // compressed size
    append_le(zip, {.value = entry.content.size(), .width = 4});  // uncompressed size
    append_le(zip, {.value = entry.name.size(), .width = 2});     // name length
    append_le(zip, {.value = 0, .width = 2});                     // extra length
    zip.append(entry.name);
    zip.append(entry.content);
  }

  const auto central_offset = static_cast<std::uint32_t>(zip.size());
  for (std::size_t index = 0; index < entries.size(); ++index) {
    const StoredEntry& entry = entries[index];
    // Central directory file header.
    append_le(zip, {.value = 0x02014B50, .width = 4});            // signature
    append_le(zip, {.value = 20, .width = 2});                    // version made by
    append_le(zip, {.value = 20, .width = 2});                    // version needed
    append_le(zip, {.value = 0, .width = 2});                     // flags
    append_le(zip, {.value = 0, .width = 2});                     // method: stored
    append_le(zip, {.value = 0, .width = 2});                     // mod time
    append_le(zip, {.value = 0, .width = 2});                     // mod date
    append_le(zip, {.value = 0, .width = 4});                     // crc-32
    append_le(zip, {.value = entry.content.size(), .width = 4});  // compressed size
    append_le(zip, {.value = entry.content.size(), .width = 4});  // uncompressed size
    append_le(zip, {.value = entry.name.size(), .width = 2});     // name length
    append_le(zip, {.value = 0, .width = 2});                     // extra length
    append_le(zip, {.value = 0, .width = 2});                     // comment length
    append_le(zip, {.value = 0, .width = 2});                     // disk number
    append_le(zip, {.value = 0, .width = 2});                     // internal attributes
    append_le(zip, {.value = 0, .width = 4});                     // external attributes
    append_le(zip, {.value = local_offsets[index], .width = 4});  // local header offset
    zip.append(entry.name);
  }

  const auto central_size = static_cast<std::uint32_t>(zip.size() - central_offset);
  // End Of Central Directory record.
  append_le(zip, {.value = 0x06054B50, .width = 4});      // signature
  append_le(zip, {.value = 0, .width = 2});               // disk number
  append_le(zip, {.value = 0, .width = 2});               // disk with central directory
  append_le(zip, {.value = entries.size(), .width = 2});  // entries on this disk
  append_le(zip, {.value = entries.size(), .width = 2});  // total entries
  append_le(zip, {.value = central_size, .width = 4});    // central directory size
  append_le(zip, {.value = central_offset, .width = 4});  // central directory offset
  append_le(zip, {.value = 0, .width = 2});               // comment length
  return zip;
}

/// Builds a zip holding one stored (uncompressed) entry named `name` with the bytes `content`.
///
/// @param name The entry's full name in the archive.
/// @param content The entry's bytes.
/// @return The bytes of the archive.
[[nodiscard]] inline std::string zip_with_stored_entry(std::string_view name, std::string_view content) {
  const StoredEntry entry{.name = name, .content = std::string(content)};
  return zip_with_stored_entries(std::span<const StoredEntry>(&entry, 1));
}

}  // namespace rasp::test_support
