/// Reading a stored APK entry: memory-map the file, walk the ZIP central directory, and copy the entry's bytes.

#include "apk/archive.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace rasp::android::apk {

namespace {

/// The signature of the end-of-central-directory record.
constexpr std::uint32_t kEndSignature = 0x06054b50;
/// The signature of a central-directory file header.
constexpr std::uint32_t kCentralSignature = 0x02014b50;
/// The signature of a local file header.
constexpr std::uint32_t kLocalSignature = 0x04034b50;
/// The size of the end-of-central-directory record, without a trailing comment.
constexpr std::size_t kEndSize = 22;
/// The size of a central-directory file header, without its variable-length name, extra field and comment.
constexpr std::size_t kCentralEntrySize = 46;
/// The size of a local file header, without its variable-length name and extra field.
constexpr std::size_t kLocalHeaderSize = 30;
/// The compression method of an entry stored without compression.
constexpr std::uint16_t kStored = 0;
/// The largest ZIP comment, which bounds how far back the end record is searched.
constexpr std::size_t kMaxComment = 65535;

/// Reads a little-endian 16-bit number from the start of `data`, which must hold at least two bytes.
[[nodiscard]] std::uint16_t read_u16(std::span<const std::uint8_t> data) {
  return static_cast<std::uint16_t>(static_cast<unsigned>(data[0]) | (static_cast<unsigned>(data[1]) << 8U));
}

/// Reads a little-endian 32-bit number from the start of `data`, which must hold at least four bytes.
[[nodiscard]] std::uint32_t read_u32(std::span<const std::uint8_t> data) {
  return static_cast<std::uint32_t>(data[0]) | (static_cast<std::uint32_t>(data[1]) << 8U) |
         (static_cast<std::uint32_t>(data[2]) << 16U) | (static_cast<std::uint32_t>(data[3]) << 24U);
}

/// Whether `bytes` holds the same characters as `text`.
[[nodiscard]] bool equals(std::span<const std::uint8_t> bytes, std::string_view text) {
  return bytes.size() == text.size() &&
         std::equal(bytes.begin(), bytes.end(), text.begin(),
                    [](std::uint8_t left, char right) { return left == static_cast<std::uint8_t>(right); });
}

/// The end-of-central-directory record, found by scanning back from the end of the file, or nothing when it is absent.
[[nodiscard]] std::optional<std::span<const std::uint8_t>> find_end_record(std::span<const std::uint8_t> file) {
  if (file.size() < kEndSize) {
    return std::nullopt;
  }
  const std::size_t window = std::min(file.size(), kEndSize + kMaxComment);
  const std::size_t lowest = file.size() - window;
  for (std::size_t offset = file.size() - kEndSize;; --offset) {
    if (read_u32(file.subspan(offset)) == kEndSignature) {
      return file.subspan(offset);
    }
    if (offset == lowest) {
      return std::nullopt;
    }
  }
}

/// The bytes of the entry whose local header starts at `local_offset` and whose stored size is `data_size`.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> read_local_data(std::span<const std::uint8_t> file,
                                                                       std::uint32_t local_offset,
                                                                       std::uint32_t data_size) {
  if (local_offset > file.size() || file.size() - local_offset < kLocalHeaderSize) {
    return std::nullopt;
  }
  const std::span<const std::uint8_t> header = file.subspan(local_offset);
  if (read_u32(header) != kLocalSignature) {
    return std::nullopt;
  }
  const std::size_t name_length = read_u16(header.subspan(26));
  const std::size_t extra_length = read_u16(header.subspan(28));
  const std::size_t start = static_cast<std::size_t>(local_offset) + kLocalHeaderSize + name_length + extra_length;
  if (start > file.size() || file.size() - start < data_size) {
    return std::nullopt;
  }
  const std::span<const std::uint8_t> data = file.subspan(start, data_size);
  return std::vector<std::uint8_t>(data.begin(), data.end());
}

/// The bytes of the stored entry named `name`, found by walking the archive's central directory.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> find_stored_entry(std::span<const std::uint8_t> file,
                                                                         std::string_view name) {
  const std::optional<std::span<const std::uint8_t>> record = find_end_record(file);
  if (!record.has_value()) {
    return std::nullopt;
  }
  const std::uint16_t count = read_u16(record->subspan(10));
  const std::uint32_t directory_size = read_u32(record->subspan(12));
  const std::uint32_t directory_offset = read_u32(record->subspan(16));
  if (directory_offset > file.size() || directory_size > file.size() - directory_offset) {
    return std::nullopt;
  }
  std::span<const std::uint8_t> rest = file.subspan(directory_offset, directory_size);
  for (std::uint16_t index = 0; index < count; ++index) {
    if (rest.size() < kCentralEntrySize || read_u32(rest) != kCentralSignature) {
      return std::nullopt;
    }
    const std::uint16_t method = read_u16(rest.subspan(10));
    const std::uint32_t stored_size = read_u32(rest.subspan(20));
    const std::size_t name_length = read_u16(rest.subspan(28));
    const std::size_t extra_length = read_u16(rest.subspan(30));
    const std::size_t comment_length = read_u16(rest.subspan(32));
    const std::uint32_t local_offset = read_u32(rest.subspan(42));
    if (rest.size() < kCentralEntrySize + name_length) {
      return std::nullopt;
    }
    if (equals(rest.subspan(kCentralEntrySize, name_length), name)) {
      if (method != kStored) {
        return std::nullopt;
      }
      return read_local_data(file, local_offset, stored_size);
    }
    const std::size_t entry_size = kCentralEntrySize + name_length + extra_length + comment_length;
    if (rest.size() < entry_size) {
      return std::nullopt;
    }
    rest = rest.subspan(entry_size);
  }
  return std::nullopt;
}

}  // namespace

std::optional<std::vector<std::uint8_t>> read_stored_entry(const std::string& apk_path, std::string_view name) {
  const int descriptor = open(apk_path.c_str(), O_RDONLY | O_CLOEXEC);
  if (descriptor < 0) {
    return std::nullopt;
  }
  struct stat status = {};
  if (fstat(descriptor, &status) != 0 || status.st_size <= 0) {
    close(descriptor);
    return std::nullopt;
  }
  const std::size_t size = static_cast<std::size_t>(status.st_size);
  void* const mapping = mmap(nullptr, size, PROT_READ, MAP_PRIVATE, descriptor, 0);
  close(descriptor);
  if (mapping == MAP_FAILED) {
    return std::nullopt;
  }
  const std::span<const std::uint8_t> file(static_cast<const std::uint8_t*>(mapping), size);
  const std::optional<std::vector<std::uint8_t>> data = find_stored_entry(file, name);
  munmap(mapping, size);
  return data;
}

}  // namespace rasp::android::apk
