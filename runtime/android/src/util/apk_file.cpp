/// read_library_file: reads a native library's bytes from a plain path or from an uncompressed entry inside an APK.

#include "util/apk_file.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "rasp/util/read_file.h"

namespace rasp::android::util {

namespace {

/// The separator the dynamic loader puts between an APK path and a zip entry path.
constexpr std::string_view kApkEntrySeparator = "!/";

/// The signature of a zip End Of Central Directory record.
constexpr std::uint32_t kEndOfCentralDirectorySignature = 0x06054B50;
/// The signature of a zip central directory file header.
constexpr std::uint32_t kCentralFileHeaderSignature = 0x02014B50;
/// The signature of a zip local file header.
constexpr std::uint32_t kLocalFileHeaderSignature = 0x04034B50;
/// The compression method of a stored (uncompressed) entry.
constexpr std::uint16_t kMethodStored = 0;

/// The fixed size of a zip End Of Central Directory record, before its comment.
constexpr std::size_t kEndOfCentralDirectorySize = 22;
/// The fixed size of a zip central directory file header, before its variable-length fields.
constexpr std::size_t kCentralFileHeaderSize = 46;
/// The fixed size of a zip local file header, before its variable-length fields.
constexpr std::size_t kLocalFileHeaderSize = 30;
/// The largest zip comment, which bounds how far back the End Of Central Directory record is searched for.
constexpr std::size_t kMaxComment = std::size_t{1} << 16U;

/// Whether `[offset, offset + length)` lies within `size`, checked without a sum that could overflow.
[[nodiscard]] constexpr bool range_fits(std::uint64_t offset, std::uint64_t length, std::uint64_t size) {
  return offset <= size && length <= size - offset;
}

/// Reads a little-endian unsigned integer of type `T` at `offset`, or nothing when `data` is too short.
template <typename T>
[[nodiscard]] std::optional<T> read_scalar(std::span<const std::uint8_t> data, std::size_t offset) {
  if (!range_fits(offset, sizeof(T), data.size())) {
    return std::nullopt;
  }
  T value = 0;
  std::memcpy(&value, data.subspan(offset, sizeof(T)).data(), sizeof(T));
  return value;
}

/// The fields of a zip central directory entry that this reader needs.
struct CentralEntry {
  /// The compression method; only kMethodStored is supported.
  std::uint16_t method = 0;
  /// The uncompressed size of the entry.
  std::uint32_t uncompressed_size = 0;
  /// The offset of the entry's local file header in the APK.
  std::uint32_t local_header_offset = 0;
};

/// An APK path and the zip entry wanted inside it, split from a `<apk>!/<entry>` loader path. Grouping the two keeps
/// callers from swapping them.
struct ApkEntryPath {
  /// The path of the APK file on disk.
  std::string_view apk_path;
  /// The name of the zip entry wanted inside the APK.
  std::string_view entry;
};

/// Whether the bytes `name` equal the entry name `wanted`, compared byte for byte.
[[nodiscard]] bool entry_named(std::span<const std::uint8_t> name, std::string_view wanted) {
  return std::ranges::equal(
      name, wanted, [](std::uint8_t byte, char character) { return byte == static_cast<std::uint8_t>(character); });
}

/// The offset of the central directory in `apk`, from its End Of Central Directory record, or nothing when the record
/// can't be found or read. The record is found by scanning back from the end for its signature, past any comment.
[[nodiscard]] std::optional<std::uint32_t> central_directory_offset(std::span<const std::uint8_t> apk) {
  if (apk.size() < kEndOfCentralDirectorySize) {
    return std::nullopt;
  }
  const std::size_t search_span = std::min(apk.size(), kEndOfCentralDirectorySize + kMaxComment);
  for (std::size_t back = kEndOfCentralDirectorySize; back <= search_span; ++back) {
    const std::size_t position = apk.size() - back;
    const std::optional<std::uint32_t> signature = read_scalar<std::uint32_t>(apk, position);
    if (signature == kEndOfCentralDirectorySignature) {
      return read_scalar<std::uint32_t>(apk, position + 16);
    }
  }
  return std::nullopt;
}

/// Whether the central directory entry at `position` in `apk` names `entry`, filling `out` when it does. `position` is
/// advanced to the next entry. Returns nothing when the header is malformed.
[[nodiscard]] std::optional<bool> match_central_entry(std::span<const std::uint8_t> apk, std::size_t& position,
                                                      std::string_view entry, CentralEntry& out) {
  const std::optional<std::uint32_t> signature = read_scalar<std::uint32_t>(apk, position);
  if (signature != kCentralFileHeaderSignature) {
    return std::nullopt;
  }
  const std::optional<std::uint16_t> method = read_scalar<std::uint16_t>(apk, position + 10);
  const std::optional<std::uint32_t> uncompressed_size = read_scalar<std::uint32_t>(apk, position + 24);
  const std::optional<std::uint16_t> name_length = read_scalar<std::uint16_t>(apk, position + 28);
  const std::optional<std::uint16_t> extra_length = read_scalar<std::uint16_t>(apk, position + 30);
  const std::optional<std::uint16_t> comment_length = read_scalar<std::uint16_t>(apk, position + 32);
  const std::optional<std::uint32_t> local_header_offset = read_scalar<std::uint32_t>(apk, position + 42);
  if (!method || !uncompressed_size || !name_length || !extra_length || !comment_length || !local_header_offset) {
    return std::nullopt;
  }
  if (!range_fits(position + kCentralFileHeaderSize, *name_length, apk.size())) {
    return std::nullopt;
  }
  const std::span<const std::uint8_t> name = apk.subspan(position + kCentralFileHeaderSize, *name_length);
  position += kCentralFileHeaderSize + *name_length + *extra_length + *comment_length;
  if (!entry_named(name, entry)) {
    return false;
  }
  out = CentralEntry{
      .method = *method,
      .uncompressed_size = *uncompressed_size,
      .local_header_offset = *local_header_offset,
  };
  return true;
}

/// The central directory entry named `entry` in `apk`, starting the walk at `directory_offset`, or nothing when no
/// entry matches or a header is malformed.
[[nodiscard]] std::optional<CentralEntry> find_central_entry(std::span<const std::uint8_t> apk,
                                                             std::uint32_t directory_offset, std::string_view entry) {
  std::size_t position = directory_offset;
  while (position < apk.size()) {
    CentralEntry found;
    const std::optional<bool> matched = match_central_entry(apk, position, entry, found);
    if (!matched) {
      return std::nullopt;
    }
    if (*matched) {
      return found;
    }
  }
  return std::nullopt;
}

/// The stored bytes of `entry` in `apk`, or nothing when the entry is compressed or its data lies outside the APK. The
/// data offset is read from the entry's own local header, whose name and extra fields can differ in length from the
/// central directory's.
[[nodiscard]] std::optional<std::span<const std::uint8_t>> stored_entry_bytes(std::span<const std::uint8_t> apk,
                                                                              const CentralEntry& entry) {
  if (entry.method != kMethodStored) {
    return std::nullopt;
  }
  const std::optional<std::uint32_t> signature = read_scalar<std::uint32_t>(apk, entry.local_header_offset);
  const std::optional<std::uint16_t> name_length = read_scalar<std::uint16_t>(apk, entry.local_header_offset + 26);
  const std::optional<std::uint16_t> extra_length = read_scalar<std::uint16_t>(apk, entry.local_header_offset + 28);
  if (signature != kLocalFileHeaderSignature || !name_length || !extra_length) {
    return std::nullopt;
  }
  const std::uint64_t data_offset =
      std::uint64_t{entry.local_header_offset} + kLocalFileHeaderSize + *name_length + *extra_length;
  if (!range_fits(data_offset, entry.uncompressed_size, apk.size())) {
    return std::nullopt;
  }
  return apk.subspan(static_cast<std::size_t>(data_offset), entry.uncompressed_size);
}

/// The largest APK file read. The `limit` a caller passes bounds the library entry wanted inside the APK, not the APK
/// that holds it: a real app's APK is far larger than the runtime library, so bounding the container read by the
/// library limit would reject the whole APK on any sizeable app. This caps the container read instead, large enough
/// for any shippable APK yet still bounding what a forged file would allocate.
constexpr std::size_t kMaxApkSize = std::size_t{2} << 30U;

/// Reads the entry named by `target` from its APK file, or nothing when it can't be read or found. `limit` bounds the
/// uncompressed entry returned, not the APK that holds it.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> read_apk_entry(const ApkEntryPath& target, std::size_t limit) {
  const std::optional<std::string> file = rasp::util::read_file(target.apk_path, kMaxApkSize);
  if (!file) {
    return std::nullopt;
  }
  const std::vector<std::uint8_t> apk(file->begin(), file->end());
  const std::optional<std::uint32_t> directory_offset = central_directory_offset(apk);
  if (!directory_offset) {
    return std::nullopt;
  }
  const std::optional<CentralEntry> central = find_central_entry(apk, *directory_offset, target.entry);
  if (!central) {
    return std::nullopt;
  }
  const std::optional<std::span<const std::uint8_t>> bytes = stored_entry_bytes(apk, *central);
  if (!bytes || bytes->size() > limit) {
    return std::nullopt;
  }
  return std::vector<std::uint8_t>(bytes->begin(), bytes->end());
}

}  // namespace

std::optional<std::vector<std::uint8_t>> read_library_file(std::string_view loader_path, std::size_t limit) {
  const std::size_t separator = loader_path.find(kApkEntrySeparator);
  if (separator == std::string_view::npos) {
    const std::optional<std::string> file = rasp::util::read_file(loader_path, limit);
    if (!file) {
      return std::nullopt;
    }
    return std::vector<std::uint8_t>(file->begin(), file->end());
  }
  const ApkEntryPath target{
      .apk_path = loader_path.substr(0, separator),
      .entry = loader_path.substr(separator + kApkEntrySeparator.size()),
  };
  return read_apk_entry(target, limit);
}

}  // namespace rasp::android::util
