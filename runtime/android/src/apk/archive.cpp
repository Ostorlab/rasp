/// Reading a stored APK entry: memory-map the file, walk the ZIP central directory, and copy the entry's bytes.

#include "apk/archive.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <map>
#include <optional>
#include <psa/crypto.h>
#include <span>
#include <string>
#include <string_view>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include "apk/location.h"

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

/// Where a stored entry's data sits: the offset of its local header in the file, and the entry's stored size.
struct LocalEntry {
  /// The offset of the local file header in the archive.
  std::uint32_t local_offset = 0;
  /// The stored size of the entry's data.
  std::uint32_t data_size = 0;
};

/// The bytes of the entry whose local header and stored size `entry` describes.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> read_local_data(std::span<const std::uint8_t> file,
                                                                       LocalEntry entry) {
  const std::uint32_t local_offset = entry.local_offset;
  const std::uint32_t data_size = entry.data_size;
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
      return read_local_data(file, LocalEntry{.local_offset = local_offset, .data_size = stored_size});
    }
    const std::size_t entry_size = kCentralEntrySize + name_length + extra_length + comment_length;
    if (rest.size() < entry_size) {
      return std::nullopt;
    }
    rest = rest.subspan(entry_size);
  }
  return std::nullopt;
}

/// Whether `name` matches `classes.dex` or `classesN.dex` (N ≥ 2), the APK's multidex entry names.
[[nodiscard]] bool is_classes_entry(std::string_view name) {
  if (!name.starts_with("classes") || !name.ends_with(".dex")) {
    return false;
  }
  const std::string_view digits = name.substr(7, name.size() - 11);
  if (digits.empty()) {
    return name == "classes.dex";
  }
  return std::ranges::all_of(digits, [](char character) { return character >= '0' && character <= '9'; });
}

/// The number in a `classesN.dex` name: 1 for `classes.dex`, N for `classesN.dex`. The packer names the stub
/// with the highest number, since it always adds it last.
[[nodiscard]] std::uint32_t classes_number(std::string_view name) {
  if (name == "classes.dex") {
    return 1;
  }
  const std::string_view digits = name.substr(7, name.size() - 11);
  std::uint32_t number = 0;
  for (const char digit : digits) {
    number = number * 10U + static_cast<std::uint32_t>(digit - '0');
  }
  return number;
}

/// Whether the entry name `name` is one the APK digest covers: not under `META-INF/` (the signing step adds those),
/// not under `assets/rasp/` or `assets/business/` (the fold's own outputs), and not the runtime's own libraries, named
/// by their filename — one name covers every ABI the pack ships (chain A already covers their bytes, and the packer
/// gathers its digest before it writes the fold's outputs into them). The runtime derives its own library's filename
/// from its load path; the legacy `librasp.so` name of older packs covers a runtime that cannot read its path.
///
/// @param name The entry name.
/// @param own_library The runtime library's filename, with its directory separator, or the legacy name.
/// @return Whether the digest covers the entry.
[[nodiscard]] bool is_digest_entry(std::string_view name, std::string_view own_library) {
  return !name.starts_with("META-INF/") && !name.starts_with("assets/rasp/") && !name.starts_with("assets/business/") &&
         !name.ends_with(own_library);
}

/// The entry-name suffix of this runtime's own library, as the digest's exclusion matches it.
///
/// The pack names the library per app, so the exclusion cannot name it: the runtime derives its own filename from
/// its load path, the way it derives its APK path, and excludes every ABI's copy of it — the pack ships one name for
/// every ABI. A load path that names no shared object (the host tests run the recovery from the test binary) or
/// cannot be read falls back to the legacy filename of older packs.
///
/// @return The suffix, a slash and the library's filename.
[[nodiscard]] std::string own_library_suffix() {
  constexpr std::string_view kLegacyLibrary = "/librasp.so";
  const std::optional<std::string> path = self_library_path();
  if (!path.has_value() || !path->ends_with(".so")) {
    return std::string(kLegacyLibrary);
  }
  const std::size_t separator = path->find_last_of('/');
  if (separator == std::string::npos) {
    return std::string(kLegacyLibrary);
  }
  return path->substr(separator);
}

/// Computes the digest over the APK's qualifying entries — every entry, stored or deflated — the core of
/// read_apk_digest. Walks the central directory and feeds each qualifying entry's name, compression method,
/// CRC-32, compressed size, uncompressed size, and — for a stored entry — its content into one SHA-256, sorted
/// by name, the way the packer does. A deflated entry contributes its metadata: an entry added, removed,
/// recompressed or whose content changed produces a different CRC-32 or size, and the digest changes.
///
/// @param file The APK's whole file bytes, memory-mapped.
/// @param own_library The runtime library's filename, with its directory separator, or the legacy name.
/// @return The 32-byte digest. Nothing when the archive is malformed or the hash fails.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> find_apk_digest(std::span<const std::uint8_t> file,
                                                                       std::string_view own_library) {
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

  // Collect each qualifying entry's hash contribution: name, metadata, and — for stored — the content.
  std::map<std::string, std::vector<std::uint8_t>> contributions;
  std::span<const std::uint8_t> rest = file.subspan(directory_offset, directory_size);
  for (std::uint16_t index = 0; index < count; ++index) {
    if (rest.size() < kCentralEntrySize || read_u32(rest) != kCentralSignature) {
      return std::nullopt;
    }
    const std::uint16_t method = read_u16(rest.subspan(10));
    const std::uint32_t crc32 = read_u32(rest.subspan(16));
    const std::uint32_t stored_size = read_u32(rest.subspan(20));
    const std::uint32_t uncompressed_size = read_u32(rest.subspan(24));
    const std::size_t name_length = read_u16(rest.subspan(28));
    const std::size_t extra_length = read_u16(rest.subspan(30));
    const std::size_t comment_length = read_u16(rest.subspan(32));
    const std::uint32_t local_offset = read_u32(rest.subspan(42));
    if (rest.size() < kCentralEntrySize + name_length) {
      return std::nullopt;
    }
    const std::string_view name(reinterpret_cast<const char*>(rest.data()) + kCentralEntrySize, name_length);
    if (is_digest_entry(name, own_library)) {
      // The entry's metadata contribution: method, CRC-32, compressed size, uncompressed size — little-endian.
      std::vector<std::uint8_t> blob;
      blob.reserve(name.size() + 16 + (method == kStored ? stored_size : 0));
      blob.insert(blob.end(), name.begin(), name.end());
      const auto push32 = [&blob](std::uint32_t value) {
        blob.push_back(static_cast<std::uint8_t>(value & 0xFFU));
        blob.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
        blob.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xFFU));
        blob.push_back(static_cast<std::uint8_t>((value >> 24U) & 0xFFU));
      };
      // The compressed size varies by zlib version and build tool, so the digest does not
      // bind it. The CRC-32 catches content changes and the uncompressed size catches
      // truncation; the compression detail adds no security.
      push32(method);
      push32(crc32);
      push32(uncompressed_size);
      if (method == kStored) {
        const std::optional<std::vector<std::uint8_t>> data =
            read_local_data(file, LocalEntry{.local_offset = local_offset, .data_size = stored_size});
        if (!data.has_value()) {
          return std::nullopt;
        }
        blob.insert(blob.end(), data->begin(), data->end());
      }
      contributions.emplace(std::string(name), std::move(blob));
    }
    const std::size_t entry_size = kCentralEntrySize + name_length + extra_length + comment_length;
    if (rest.size() < entry_size) {
      return std::nullopt;
    }
    rest = rest.subspan(entry_size);
  }

  // Hash the sorted contributions, the way the packer's apk_digest does.
  psa_crypto_init();
  psa_hash_operation_t operation = psa_hash_operation_init();
  if (psa_hash_setup(&operation, PSA_ALG_SHA_256) != PSA_SUCCESS) {
    return std::nullopt;
  }
  for (const auto& [name, blob] : contributions) {
    static_cast<void>(name);  // The name is already inside the blob.
    if (psa_hash_update(&operation, blob.data(), blob.size()) != PSA_SUCCESS) {
      psa_hash_abort(&operation);
      return std::nullopt;
    }
  }

  std::array<std::uint8_t, 32> digest{};
  std::size_t digest_size = 0;
  if (psa_hash_finish(&operation, digest.data(), digest.size(), &digest_size) != PSA_SUCCESS ||
      digest_size != digest.size()) {
    return std::nullopt;
  }
  return std::vector<std::uint8_t>(digest.begin(), digest.end());
}

}  // namespace

std::optional<std::vector<std::uint8_t>> read_stored_entry(const std::string& apk_path, std::string_view name) {
  // open is a libc variadic function, and its flags come from the included <fcntl.h>.
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,misc-include-cleaner)
  const int descriptor = open(apk_path.c_str(), O_RDONLY | O_CLOEXEC);
  if (descriptor < 0) {
    return std::nullopt;
  }
  struct stat status = {};
  if (fstat(descriptor, &status) != 0 || status.st_size <= 0 || !std::in_range<std::size_t>(status.st_size)) {
    close(descriptor);
    return std::nullopt;
  }
  const auto size = static_cast<std::size_t>(status.st_size);
  // NOLINTNEXTLINE(misc-include-cleaner): the mmap flags come from the included <sys/mman.h>.
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

std::optional<std::vector<std::uint8_t>> read_stub_entry(const std::string& apk_path) {
  // open is a libc variadic function, and its flags come from the included <fcntl.h>.
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,misc-include-cleaner)
  const int descriptor = open(apk_path.c_str(), O_RDONLY | O_CLOEXEC);
  if (descriptor < 0) {
    return std::nullopt;
  }
  struct stat status = {};
  if (fstat(descriptor, &status) != 0 || status.st_size <= 0 || !std::in_range<std::size_t>(status.st_size)) {
    close(descriptor);
    return std::nullopt;
  }
  const auto size = static_cast<std::size_t>(status.st_size);
  // NOLINTNEXTLINE(misc-include-cleaner): the mmap flags come from the included <sys/mman.h>.
  void* const mapping = mmap(nullptr, size, PROT_READ, MAP_PRIVATE, descriptor, 0);
  close(descriptor);
  if (mapping == MAP_FAILED) {
    return std::nullopt;
  }
  const std::span<const std::uint8_t> file(static_cast<const std::uint8_t*>(mapping), size);

  // Walk the central directory for the highest-numbered classesN.dex entry.
  const std::optional<std::span<const std::uint8_t>> record = find_end_record(file);
  if (!record.has_value()) {
    munmap(mapping, size);
    return std::nullopt;
  }
  const std::uint16_t count = read_u16(record->subspan(10));
  const std::uint32_t directory_size = read_u32(record->subspan(12));
  const std::uint32_t directory_offset = read_u32(record->subspan(16));
  if (directory_offset > file.size() || directory_size > file.size() - directory_offset) {
    munmap(mapping, size);
    return std::nullopt;
  }
  std::span<const std::uint8_t> rest = file.subspan(directory_offset, directory_size);
  std::uint32_t best_number = 0;
  std::optional<LocalEntry> best_entry;
  for (std::uint16_t index = 0; index < count; ++index) {
    if (rest.size() < kCentralEntrySize || read_u32(rest) != kCentralSignature) {
      munmap(mapping, size);
      return std::nullopt;
    }
    const std::uint16_t method = read_u16(rest.subspan(10));
    const std::uint32_t stored_size = read_u32(rest.subspan(20));
    const std::size_t name_length = read_u16(rest.subspan(28));
    const std::size_t extra_length = read_u16(rest.subspan(30));
    const std::size_t comment_length = read_u16(rest.subspan(32));
    const std::uint32_t local_offset = read_u32(rest.subspan(42));
    if (rest.size() < kCentralEntrySize + name_length) {
      munmap(mapping, size);
      return std::nullopt;
    }
    const std::string_view name(reinterpret_cast<const char*>(rest.data()) + kCentralEntrySize, name_length);
    if (method == kStored && is_classes_entry(name)) {
      const std::uint32_t number = classes_number(name);
      if (number > best_number) {
        best_number = number;
        best_entry = LocalEntry{.local_offset = local_offset, .data_size = stored_size};
      }
    }
    const std::size_t entry_size = kCentralEntrySize + name_length + extra_length + comment_length;
    if (rest.size() < entry_size) {
      munmap(mapping, size);
      return std::nullopt;
    }
    rest = rest.subspan(entry_size);
  }
  if (!best_entry.has_value()) {
    munmap(mapping, size);
    return std::nullopt;
  }
  const std::optional<std::vector<std::uint8_t>> data = read_local_data(file, *best_entry);
  munmap(mapping, size);
  return data;
}

std::optional<std::vector<std::uint8_t>> read_apk_digest(const std::string& apk_path) {
  // open is a libc variadic function, and its flags come from the included <fcntl.h>.
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,misc-include-cleaner)
  const int descriptor = open(apk_path.c_str(), O_RDONLY | O_CLOEXEC);
  if (descriptor < 0) {
    return std::nullopt;
  }
  struct stat status = {};
  if (fstat(descriptor, &status) != 0 || status.st_size <= 0 || !std::in_range<std::size_t>(status.st_size)) {
    close(descriptor);
    return std::nullopt;
  }
  const auto size = static_cast<std::size_t>(status.st_size);
  // NOLINTNEXTLINE(misc-include-cleaner): the mmap flags come from the included <sys/mman.h>.
  void* const mapping = mmap(nullptr, size, PROT_READ, MAP_PRIVATE, descriptor, 0);
  close(descriptor);
  if (mapping == MAP_FAILED) {
    return std::nullopt;
  }
  const std::span<const std::uint8_t> file(static_cast<const std::uint8_t*>(mapping), size);
  const std::optional<std::vector<std::uint8_t>> result = find_apk_digest(file, own_library_suffix());
  munmap(mapping, size);
  return result;
}

}  // namespace rasp::android::apk
