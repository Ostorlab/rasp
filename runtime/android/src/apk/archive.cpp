/// Reading an APK from its bytes: memory-map the file, then walk the ZIP central directory to copy a stored entry, or
/// the APK Signing Block before it to copy the signer's certificate.

#include "apk/archive.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <fcntl.h>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
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
/// The offset, in the end-of-central-directory record, of the central directory's offset in the file.
constexpr std::size_t kDirectoryOffsetField = 16;

/// The magic that ends the APK Signing Block.
constexpr std::string_view kSigningBlockMagic = "APK Sig Block 42";
/// The size of the APK Signing Block's footer: its size, then its magic.
constexpr std::size_t kSigningBlockFooterSize = 24;
/// The size of the APK Signing Block's header: its size, repeated.
constexpr std::size_t kSigningBlockHeaderSize = 8;
/// The id of the APK Signature Scheme v3.1 block, which holds the signers of a rotated key for newer Android versions.
constexpr std::uint32_t kV31SchemeId = 0x1b93ad61U;
/// The id of the APK Signature Scheme v3 block.
constexpr std::uint32_t kV3SchemeId = 0xf05368c0U;
/// The id of the APK Signature Scheme v2 block.
constexpr std::uint32_t kV2SchemeId = 0x7109871aU;
/// The signature schemes read, newest first, as Android verifies them: the certificate comes from the newest one that
/// has a signer for the device.
constexpr std::array<std::uint32_t, 3> kSchemeIds = {kV31SchemeId, kV3SchemeId, kV2SchemeId};
/// The size of the SDK range a v3 or v3.1 signer has after its signed data: its lowest and highest API levels.
constexpr std::size_t kSdkRangeSize = 8;
/// The largest certificate copied. A real one is about 1.5 KiB.
constexpr std::size_t kMaxCertificateSize = std::size_t{64} << 10U;

/// Reads a little-endian 16-bit number from the start of `data`, which must hold at least two bytes.
[[nodiscard]] std::uint16_t read_u16(std::span<const std::uint8_t> data) {
  return static_cast<std::uint16_t>(static_cast<unsigned>(data[0]) | (static_cast<unsigned>(data[1]) << 8U));
}

/// Reads a little-endian 32-bit number from the start of `data`, which must hold at least four bytes.
[[nodiscard]] std::uint32_t read_u32(std::span<const std::uint8_t> data) {
  return static_cast<std::uint32_t>(data[0]) | (static_cast<std::uint32_t>(data[1]) << 8U) |
         (static_cast<std::uint32_t>(data[2]) << 16U) | (static_cast<std::uint32_t>(data[3]) << 24U);
}

/// Reads a little-endian 64-bit number from the start of `data`, which must hold at least eight bytes.
[[nodiscard]] std::uint64_t read_u64(std::span<const std::uint8_t> data) {
  return static_cast<std::uint64_t>(read_u32(data)) | (static_cast<std::uint64_t>(read_u32(data.subspan(4))) << 32U);
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

/// The value of the 32-bit length-prefixed field at the start of `data`, which then starts after it, or nothing when
/// the length runs past the end of `data`.
[[nodiscard]] std::optional<std::span<const std::uint8_t>> take_length_prefixed(std::span<const std::uint8_t>& data) {
  if (data.size() < 4) {
    return std::nullopt;
  }
  const std::uint32_t length = read_u32(data);
  if (length > data.size() - 4) {
    return std::nullopt;
  }
  const std::span<const std::uint8_t> value = data.subspan(4, length);
  data = data.subspan(4 + static_cast<std::size_t>(length));
  return value;
}

/// The id-value pairs of the APK Signing Block that ends right before the central directory at `directory_offset`, or
/// nothing when there is no such block, as in an APK signed only with the JAR scheme, or its sizes don't match.
[[nodiscard]] std::optional<std::span<const std::uint8_t>> signing_block_pairs(std::span<const std::uint8_t> file,
                                                                               std::size_t directory_offset) {
  if (directory_offset > file.size() || directory_offset < kSigningBlockHeaderSize + kSigningBlockFooterSize) {
    return std::nullopt;
  }
  const std::span<const std::uint8_t> footer =
      file.subspan(directory_offset - kSigningBlockFooterSize, kSigningBlockFooterSize);
  if (!equals(footer.subspan(8), kSigningBlockMagic)) {
    return std::nullopt;
  }
  const std::uint64_t size = read_u64(footer);
  if (size < kSigningBlockFooterSize || size > directory_offset - kSigningBlockHeaderSize) {
    return std::nullopt;
  }
  const std::size_t start = directory_offset - static_cast<std::size_t>(size) - kSigningBlockHeaderSize;
  if (read_u64(file.subspan(start)) != size) {
    return std::nullopt;
  }
  return file.subspan(start + kSigningBlockHeaderSize, static_cast<std::size_t>(size) - kSigningBlockFooterSize);
}

/// The value of the pair whose id is `id` among the APK Signing Block's `pairs`, or nothing when there is none or a
/// pair's length runs past the block.
[[nodiscard]] std::optional<std::span<const std::uint8_t>> scheme_value(std::span<const std::uint8_t> pairs,
                                                                        std::uint32_t id) {
  while (!pairs.empty()) {
    if (pairs.size() < 12) {
      return std::nullopt;
    }
    const std::uint64_t length = read_u64(pairs);
    if (length < 4 || length > pairs.size() - 8) {
      return std::nullopt;
    }
    const std::span<const std::uint8_t> pair = pairs.subspan(8, static_cast<std::size_t>(length));
    if (read_u32(pair) == id) {
      return pair.subspan(4);
    }
    pairs = pairs.subspan(8 + static_cast<std::size_t>(length));
  }
  return std::nullopt;
}

/// The first certificate in a signer's `signed_data`: past its digests, then its certificates, both length-prefixed.
/// Nothing when a length runs past its parent.
[[nodiscard]] std::optional<std::span<const std::uint8_t>> first_certificate(
    std::span<const std::uint8_t> signed_data) {
  if (!take_length_prefixed(signed_data)) {
    return std::nullopt;
  }
  std::optional<std::span<const std::uint8_t>> certificates = take_length_prefixed(signed_data);
  if (!certificates) {
    return std::nullopt;
  }
  return take_length_prefixed(*certificates);
}

/// A signature scheme block whose lengths don't fit what holds them.
struct MalformedScheme {};

/// The certificate of the signer that Android uses from `scheme`, the value of the block whose id is `scheme_id`, on a
/// device at `api_level`. A v2 block's first signer applies to every device. A v3 or v3.1 signer gives the range of API
/// levels it applies to after its signed data, and the first signer whose range holds `api_level` is used.
///
/// @return The certificate, nothing when no signer of the block applies to the device, or MalformedScheme when a length
/// runs past what holds it.
[[nodiscard]] std::expected<std::optional<std::span<const std::uint8_t>>, MalformedScheme> scheme_certificate(
    std::span<const std::uint8_t> scheme, std::uint32_t scheme_id, std::uint32_t api_level) {
  std::optional<std::span<const std::uint8_t>> signers = take_length_prefixed(scheme);
  if (!signers) {
    return std::unexpected(MalformedScheme{});
  }
  while (!signers->empty()) {
    std::optional<std::span<const std::uint8_t>> signer = take_length_prefixed(*signers);
    if (!signer) {
      return std::unexpected(MalformedScheme{});
    }
    const std::optional<std::span<const std::uint8_t>> signed_data = take_length_prefixed(*signer);
    if (!signed_data || (scheme_id != kV2SchemeId && signer->size() < kSdkRangeSize)) {
      return std::unexpected(MalformedScheme{});
    }
    const bool applies =
        scheme_id == kV2SchemeId || (read_u32(*signer) <= api_level && api_level <= read_u32(signer->subspan(4)));
    if (!applies) {
      continue;
    }
    const std::optional<std::span<const std::uint8_t>> certificate = first_certificate(*signed_data);
    if (!certificate) {
      return std::unexpected(MalformedScheme{});
    }
    return certificate;
  }
  return std::nullopt;
}

/// The result of `read` over the whole file at `apk_path`, memory-mapped read-only for the call, or nothing when the
/// file can't be opened, is empty, or can't be mapped.
template <typename Read>
[[nodiscard]] std::optional<std::vector<std::uint8_t>> read_mapped(const std::string& apk_path, Read read) {
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
  std::optional<std::vector<std::uint8_t>> data = read(file);
  munmap(mapping, size);
  return data;
}

}  // namespace

std::optional<std::vector<std::uint8_t>> read_stored_entry(const std::string& apk_path, std::string_view name) {
  return read_mapped(apk_path, [name](std::span<const std::uint8_t> file) { return find_stored_entry(file, name); });
}

std::optional<std::vector<std::uint8_t>> find_signing_certificate(std::span<const std::uint8_t> apk,
                                                                  std::uint32_t api_level) {
  const std::optional<std::span<const std::uint8_t>> record = find_end_record(apk);
  if (!record) {
    return std::nullopt;
  }
  const std::optional<std::span<const std::uint8_t>> pairs =
      signing_block_pairs(apk, read_u32(record->subspan(kDirectoryOffsetField)));
  if (!pairs) {
    return std::nullopt;
  }
  for (const std::uint32_t id : kSchemeIds) {
    const std::optional<std::span<const std::uint8_t>> scheme = scheme_value(*pairs, id);
    if (!scheme) {
      continue;
    }
    const std::expected<std::optional<std::span<const std::uint8_t>>, MalformedScheme> found =
        scheme_certificate(*scheme, id, api_level);
    if (!found) {
      return std::nullopt;
    }
    if (!*found) {
      continue;
    }
    const std::span<const std::uint8_t> certificate = **found;
    if (certificate.empty() || certificate.size() > kMaxCertificateSize) {
      return std::nullopt;
    }
    return std::vector<std::uint8_t>(certificate.begin(), certificate.end());
  }
  return std::nullopt;
}

std::optional<std::vector<std::uint8_t>> read_signing_certificate(const std::string& apk_path,
                                                                  std::uint32_t api_level) {
  return read_mapped(
      apk_path, [api_level](std::span<const std::uint8_t> file) { return find_signing_certificate(file, api_level); });
}

}  // namespace rasp::android::apk
