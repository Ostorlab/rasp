/// Reading an APK from its bytes: memory-map the file, then walk the ZIP central directory to copy a stored entry, or
/// the APK Signing Block before it to copy the signer's certificate.

#include "apk/archive.h"

#ifdef __ANDROID__
#include <linux/stat.h>
#endif

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

#include "util/signing_certificates.h"

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
/// The lowest API level whose platform honors the v3.1 block, Android 13. Below it, Android's verifier skips the v3.1
/// pair as an unknown id and uses the v3 block, so the certificate the device trusts there comes from v3.
constexpr std::uint32_t kMinApiLevelForV31 = 33;
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

/// A signature scheme block, or an id-value pair of the APK Signing Block, whose lengths don't fit what holds them.
struct MalformedScheme {};

/// The value of the pair whose id is `id` among the APK Signing Block's `pairs`: the value when a pair has the id,
/// nothing when the pairs are walked to the end without it, or MalformedScheme when a pair's length runs past the
/// block, so a malformed block is refused whatever the order of its pairs.
[[nodiscard]] std::expected<std::optional<std::span<const std::uint8_t>>, MalformedScheme> scheme_value(
    std::span<const std::uint8_t> pairs, std::uint32_t id) {
  while (!pairs.empty()) {
    if (pairs.size() < 12) {
      return std::unexpected(MalformedScheme{});
    }
    const std::uint64_t length = read_u64(pairs);
    if (length < 4 || length > pairs.size() - 8) {
      return std::unexpected(MalformedScheme{});
    }
    const std::span<const std::uint8_t> pair = pairs.subspan(8, static_cast<std::size_t>(length));
    if (read_u32(pair) == id) {
      return std::optional<std::span<const std::uint8_t>>(pair.subspan(4));
    }
    pairs = pairs.subspan(8 + static_cast<std::size_t>(length));
  }
  return std::optional<std::span<const std::uint8_t>>(std::nullopt);
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

/// Reads a regular archive through the legacy mapping path, preserving its singular signer and stored-entry parsers.
/// Invalid paths/nonregular files fail before mapping. Concurrent truncation of a mapped regular file can still fault.
template <typename Read>
[[nodiscard]] std::optional<std::vector<std::uint8_t>> read_mapped(const std::string& apk_path, Read read) {
  if (apk_path.empty() || apk_path.contains('\0') || apk_path.size() > 4096) {
    return std::nullopt;
  }
  // open is a libc variadic function, and its flags come from the included <fcntl.h>.
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,misc-include-cleaner)
  const int descriptor = open(apk_path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
  if (descriptor < 0) {
    return std::nullopt;
  }
  std::optional<std::vector<std::uint8_t>> data;
  struct stat status = {};
  if (fstat(descriptor, &status) == 0 && S_ISREG(status.st_mode) && status.st_size > 0 &&
      std::in_range<std::size_t>(status.st_size)) {
    const auto size = static_cast<std::size_t>(status.st_size);
    // NOLINTNEXTLINE(misc-include-cleaner): the mmap flags come from the included <sys/mman.h>.
    void* const mapping = mmap(nullptr, size, PROT_READ, MAP_PRIVATE, descriptor, 0);
    if (mapping != MAP_FAILED) {
      const std::span<const std::uint8_t> file(static_cast<const std::uint8_t*>(mapping), size);
      data = read(file);
      if (munmap(mapping, size) != 0) {
        data.reset();
      }
    }
  }
  if (close(descriptor) != 0) {
    return std::nullopt;
  }
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
    if (id == kV31SchemeId && api_level < kMinApiLevelForV31) {
      continue;
    }
    const std::expected<std::optional<std::span<const std::uint8_t>>, MalformedScheme> scheme =
        scheme_value(*pairs, id);
    if (!scheme) {
      return std::nullopt;
    }
    if (!*scheme) {
      continue;
    }
    const std::expected<std::optional<std::span<const std::uint8_t>>, MalformedScheme> found =
        scheme_certificate(**scheme, id, api_level);
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

namespace {

/// Bound all new-path archive work, including unknown signing block entries.
constexpr std::size_t kMaxSigningBlockBytes = 1048576;
/// ZIP32 APKs above this limit are explicitly unavailable, including on 32-bit builds.
constexpr std::size_t kMaxApkBytes = 2147483647;
/// Limits raw signer records even when their SDK ranges do not apply.
constexpr std::size_t kMaxSignerRecords = 32;
/// AOSP Android14's maximum v2 concurrent signers.
constexpr std::size_t kMaxV2Signers = 10;
/// Rotation minimum SDK stripping-protection attribute in v3.
constexpr std::uint32_t kRotationMinSdkAttribute = 0x559f8b02U;
/// Developer-release selection also depends on Build.VERSION.CODENAME; this source explicitly declines it.
constexpr std::uint32_t kDevelopmentRotationAttribute = 0xc2a6b3baU;
/// v2 stripping protection is declined when newer signatures are unavailable rather than guessed.
constexpr std::uint32_t kV2StrippingAttribute = 0xbeeff00dU;

/// One structurally parsed scheme and the SDK targeting metadata needed to select its leaves.
struct CompleteScheme {
  util::Certificates certificates;
  std::optional<std::uint32_t> minimum_sdk;
  std::optional<std::uint32_t> rotation_minimum_sdk;
};

/// Strict ZIP32 envelope, including exact comment length, one disk, and a directory adjacent to the end record.
[[nodiscard]] bool complete_end_record(std::span<const std::uint8_t> record, std::size_t end_offset) {
  return record.size() >= kEndSize && read_u32(record) == kEndSignature &&
         read_u16(record.subspan(20)) == record.size() - kEndSize && read_u16(record.subspan(4)) == 0 &&
         read_u16(record.subspan(6)) == 0 && read_u16(record.subspan(8)) == read_u16(record.subspan(10)) &&
         read_u16(record.subspan(10)) != 65535 && read_u32(record.subspan(12)) <= end_offset &&
         read_u32(record.subspan(16)) == end_offset - read_u32(record.subspan(12));
}

/// Locates a valid terminal ZIP record while ignoring false signatures within its comment.
[[nodiscard]] std::optional<std::size_t> complete_end_offset(std::span<const std::uint8_t> tail,
                                                             std::size_t tail_offset) {
  if (tail.size() < kEndSize) {
    return std::nullopt;
  }
  const std::size_t lowest = tail.size() > kEndSize + kMaxComment ? tail.size() - kEndSize - kMaxComment : 0;
  for (std::size_t offset = tail.size() - kEndSize;; --offset) {
    if (complete_end_record(tail.subspan(offset), tail_offset + offset)) {
      return offset;
    }
    if (offset == lowest) {
      return std::nullopt;
    }
  }
}

/// Checks every pair before selection, rejecting duplicate schemes and malformed trailing pairs.
[[nodiscard]] std::optional<std::array<std::span<const std::uint8_t>, 3>> complete_schemes(
    std::span<const std::uint8_t> pairs) {
  if (pairs.size() > kMaxSigningBlockBytes) {
    return std::nullopt;
  }
  std::array<std::span<const std::uint8_t>, 3> schemes{};
  std::array<bool, 3> seen{};
  const std::span scheme_ids(kSchemeIds);
  const std::span seen_flags(seen);
  const std::span scheme_values(schemes);
  std::size_t count = 0;
  while (!pairs.empty()) {
    if (++count > 256 || pairs.size() < 12) {
      return std::nullopt;
    }
    const std::uint64_t length = read_u64(pairs);
    if (length < 4 || length > pairs.size() - 8) {
      return std::nullopt;
    }
    const auto pair = pairs.subspan(8, static_cast<std::size_t>(length));
    for (std::size_t index = 0; index < kSchemeIds.size(); ++index) {
      if (read_u32(pair) == scheme_ids[index]) {
        if (seen_flags[index] || pair.size() == 4) {
          return std::nullopt;
        }
        seen_flags[index] = true;
        scheme_values[index] = pair.subspan(4);
      }
    }
    pairs = pairs.subspan(8 + static_cast<std::size_t>(length));
  }
  return schemes;
}

/// Checks bounded digest/signature records structurally, without evaluating their algorithms or signatures.
[[nodiscard]] bool algorithm_records(std::span<const std::uint8_t> records) {
  std::size_t count = 0;
  while (!records.empty()) {
    auto record = take_length_prefixed(records);
    if (++count > 64 || !record.has_value() || record->size() < 8) {
      return false;
    }
    auto data = record->subspan(4);
    const auto value = take_length_prefixed(data);
    if (!value.has_value() || value->empty() || !data.empty()) {
      return false;
    }
  }
  return count != 0;
}

/// Returns only the chain's leaf, while validating and bounding all chain entries before accepting the signer.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> complete_chain(std::span<const std::uint8_t> chain,
                                                                      std::size_t& total) {
  std::vector<std::uint8_t> leaf;
  std::size_t count = 0;
  while (!chain.empty()) {
    const auto certificate = take_length_prefixed(chain);
    if (++count > util::kMaxCertificates || !certificate.has_value() ||
        certificate->size() > util::kMaxCertificateTotalBytes - total || !util::certificate_envelope(*certificate)) {
      return std::nullopt;
    }
    total += certificate->size();
    if (count == 1) {
      leaf.assign(certificate->begin(), certificate->end());
    }
  }
  return leaf.empty() ? std::nullopt : std::optional(std::move(leaf));
}

/// Checks bounded attribute framing and extracts selection metadata, without interpreting proof-of-rotation payloads.
[[nodiscard]] std::expected<std::optional<std::uint32_t>, SignerReadError> complete_attributes(
    std::span<const std::uint8_t> attributes, std::uint32_t scheme_id) {
  std::optional<std::uint32_t> rotation_minimum;
  std::size_t count = 0;
  while (!attributes.empty()) {
    const auto attribute = take_length_prefixed(attributes);
    if (++count > 64 || !attribute.has_value() || attribute->size() < 4) {
      return std::unexpected(SignerReadError::kError);
    }
    const auto attribute_id = read_u32(*attribute);
    if ((attribute_id == kDevelopmentRotationAttribute && scheme_id == kV31SchemeId) ||
        (attribute_id == kV2StrippingAttribute && scheme_id == kV2SchemeId)) {
      return std::unexpected(SignerReadError::kUnsupported);
    }
    if (attribute_id == kRotationMinSdkAttribute && scheme_id != kV2SchemeId) {
      if (attribute->size() != 8 || rotation_minimum.has_value()) {
        return std::unexpected(SignerReadError::kError);
      }
      rotation_minimum = read_u32(attribute->subspan(4));
    }
  }
  return rotation_minimum;
}

/// Explicit scheme/device roles prevent accidentally swapping two SDK-related integer parameters.
struct SchemeSelection {
  std::uint32_t scheme_id;
  std::uint32_t api_level;
};

/// One parsed signer leaf and its targeting metadata, before scheme-wide cardinality validation.
struct CompleteSigner {
  std::vector<std::uint8_t> certificate;
  std::uint32_t minimum = 0;
  std::uint32_t maximum = 0x7fffffffU;
  std::optional<std::uint32_t> rotation_minimum;
};

/// Reads an unsigned SDK range; v2 has no range bytes and applies to all supported devices.
[[nodiscard]] bool unsigned_sdk_range(std::span<const std::uint8_t>& signer, std::uint32_t scheme_id,
                                      CompleteSigner& result) {
  if (scheme_id == kV2SchemeId) {
    return true;
  }
  if (signer.size() < kSdkRangeSize) {
    return false;
  }
  result.minimum = read_u32(signer);
  result.maximum = read_u32(signer.subspan(4));
  signer = signer.subspan(kSdkRangeSize);
  return result.minimum <= result.maximum && result.maximum <= 0x7fffffffU;
}

/// Checks the signed-data range matches its unsigned selection fields before consuming the attributes.
[[nodiscard]] bool signed_sdk_range(std::span<const std::uint8_t>& data, std::uint32_t scheme_id,
                                    const CompleteSigner& signer) {
  if (scheme_id == kV2SchemeId) {
    return true;
  }
  if (data.size() < kSdkRangeSize || read_u32(data) != signer.minimum || read_u32(data.subspan(4)) != signer.maximum) {
    return false;
  }
  data = data.subspan(kSdkRangeSize);
  return true;
}

/// Parses one complete signer, bounding every certificate in its chain without verifying signatures or lineage.
[[nodiscard]] std::expected<CompleteSigner, SignerReadError> complete_signer(std::span<const std::uint8_t> signer,
                                                                             std::uint32_t scheme_id,
                                                                             std::size_t& total) {
  auto data = take_length_prefixed(signer);
  CompleteSigner result;
  if (!data.has_value() || !unsigned_sdk_range(signer, scheme_id, result)) {
    return std::unexpected(SignerReadError::kError);
  }
  const auto signatures = take_length_prefixed(signer);
  const auto key = take_length_prefixed(signer);
  const auto digests = take_length_prefixed(*data);
  const auto chain = take_length_prefixed(*data);
  if (!signatures.has_value() || !algorithm_records(*signatures) || !key.has_value() || key->empty() ||
      key->size() > util::kMaxCertificateBytes || !signer.empty() || !digests.has_value() ||
      !algorithm_records(*digests) || !chain.has_value()) {
    return std::unexpected(SignerReadError::kError);
  }
  auto leaf = complete_chain(*chain, total);
  if (!leaf.has_value() || !signed_sdk_range(*data, scheme_id, result)) {
    return std::unexpected(SignerReadError::kError);
  }
  const auto attributes = take_length_prefixed(*data);
  if (!attributes.has_value() || !data->empty()) {
    return std::unexpected(SignerReadError::kError);
  }
  const auto selection = complete_attributes(*attributes, scheme_id);
  if (!selection.has_value()) {
    return std::unexpected(selection.error());
  }
  result.certificate = std::move(*leaf);
  result.rotation_minimum = *selection;
  return result;
}

/// Parses every signer record in one scheme and retains leaves only for the applicable SDK range.
[[nodiscard]] std::expected<CompleteScheme, SignerReadError> complete_scheme(std::span<const std::uint8_t> scheme,
                                                                             SchemeSelection selection) {
  auto signers = take_length_prefixed(scheme);
  if (!signers.has_value() || !scheme.empty() || signers->empty()) {
    return std::unexpected(SignerReadError::kError);
  }
  CompleteScheme result;
  std::size_t count = 0;
  std::size_t total = 0;
  while (!signers->empty()) {
    const auto record = take_length_prefixed(*signers);
    if (++count > kMaxSignerRecords || !record.has_value()) {
      return std::unexpected(SignerReadError::kError);
    }
    auto signer = complete_signer(*record, selection.scheme_id, total);
    if (!signer.has_value()) {
      return std::unexpected(signer.error());
    }
    if (!result.minimum_sdk.has_value() || signer->minimum < *result.minimum_sdk) {
      result.minimum_sdk = signer->minimum;
    }
    if (signer->minimum <= selection.api_level && selection.api_level <= signer->maximum) {
      result.rotation_minimum_sdk = signer->rotation_minimum;
      result.certificates.push_back(std::move(signer->certificate));
      if (result.certificates.size() > (selection.scheme_id == kV2SchemeId ? kMaxV2Signers : 1)) {
        return std::unexpected(SignerReadError::kError);
      }
    }
  }
  return result;
}

/// Chooses one complete scheme: v3.1 from API33, v3 otherwise, and v2 only when v3 is absent.
[[nodiscard]] SignerCertificates complete_signers(std::span<const std::uint8_t> pairs, std::uint32_t api_level) {
  const auto schemes = complete_schemes(pairs);
  if (!schemes.has_value()) {
    return std::unexpected(SignerReadError::kError);
  }
  std::optional<std::uint32_t> rotation_minimum;
  if (api_level >= kMinApiLevelForV31 && !(*schemes)[0].empty()) {
    auto rotated = complete_scheme((*schemes)[0], {.scheme_id = kV31SchemeId, .api_level = api_level});
    if (!rotated.has_value()) {
      return std::unexpected(rotated.error());
    }
    if (!rotated->certificates.empty()) {
      return std::move(rotated->certificates);
    }
    rotation_minimum = rotated->minimum_sdk;
  }
  if (!(*schemes)[1].empty()) {
    auto v3 = complete_scheme((*schemes)[1], {.scheme_id = kV3SchemeId, .api_level = api_level});
    if (!v3.has_value()) {
      return std::unexpected(v3.error());
    }
    if (v3->certificates.empty() || (api_level >= kMinApiLevelForV31 && v3->rotation_minimum_sdk.has_value() &&
                                     v3->rotation_minimum_sdk != rotation_minimum)) {
      return std::unexpected(SignerReadError::kError);
    }
    return std::move(v3->certificates);
  }
  if ((*schemes)[2].empty() || (api_level >= kMinApiLevelForV31 && !(*schemes)[0].empty())) {
    return std::unexpected(SignerReadError::kError);
  }
  auto v2 = complete_scheme((*schemes)[2], {.scheme_id = kV2SchemeId, .api_level = api_level});
  if (!v2.has_value()) {
    return std::unexpected(v2.error());
  }
  if (v2->certificates.empty()) {
    return std::unexpected(SignerReadError::kError);
  }
  return std::move(v2->certificates);
}

/// Copies one bounded region with pread; short, interrupted or concurrently truncated reads fail without mapping
/// faults.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> file_region(int descriptor, std::size_t offset,
                                                                   std::size_t size) {
  if (size > kMaxSigningBlockBytes || offset > kMaxApkBytes) {
    return std::nullopt;
  }
  std::vector<std::uint8_t> bytes(size);
  if (pread(descriptor, bytes.data(), size, static_cast<off_t>(offset)) != static_cast<ssize_t>(size)) {
    return std::nullopt;
  }
  return bytes;
}

/// Checks descriptor identity, sizes and modification/change timestamps around the independent reads.
[[nodiscard]] bool unchanged_archive(const struct stat& before, const struct stat& after) {
  const bool same = before.st_dev == after.st_dev && before.st_ino == after.st_ino && before.st_mode == after.st_mode &&
                    before.st_size == after.st_size && before.st_mtime == after.st_mtime &&
                    before.st_ctime == after.st_ctime;
#ifdef __APPLE__
  return same && before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec &&
         before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec;
#else
  return same && before.st_mtim.tv_nsec == after.st_mtim.tv_nsec && before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
#endif
}

/// Collects only ZIP tail, footer and a bounded signing block from a regular file.
[[nodiscard]] SignerCertificates complete_file(int descriptor, const struct stat& status, std::uint32_t api_level) {
  const auto size = static_cast<std::size_t>(status.st_size);
  const auto tail_size = std::min(size, kEndSize + kMaxComment);
  const auto tail = file_region(descriptor, size - tail_size, tail_size);
  if (!tail.has_value()) {
    return std::unexpected(SignerReadError::kError);
  }
  const auto end_offset = complete_end_offset(*tail, size - tail_size);
  if (!end_offset.has_value()) {
    return std::unexpected(SignerReadError::kError);
  }
  const auto directory = read_u32(std::span(*tail).subspan(*end_offset + kDirectoryOffsetField));
  if (directory < kSigningBlockHeaderSize + kSigningBlockFooterSize) {
    return std::unexpected(SignerReadError::kError);
  }
  const auto footer = file_region(descriptor, directory - kSigningBlockFooterSize, kSigningBlockFooterSize);
  if (!footer.has_value()) {
    return std::unexpected(SignerReadError::kError);
  }
  const std::uint64_t block_size = read_u64(*footer);
  if (block_size < kSigningBlockFooterSize || block_size > kMaxSigningBlockBytes - kSigningBlockHeaderSize ||
      block_size > directory - kSigningBlockHeaderSize) {
    return std::unexpected(SignerReadError::kError);
  }
  const auto full_size = static_cast<std::size_t>(block_size) + kSigningBlockHeaderSize;
  const auto block = file_region(descriptor, directory - full_size, full_size);
  if (!block.has_value()) {
    return std::unexpected(SignerReadError::kError);
  }
  const auto pairs = signing_block_pairs(*block, block->size());
  return pairs.has_value() ? complete_signers(*pairs, api_level) : std::unexpected(SignerReadError::kError);
}

}  // namespace

SignerCertificates find_signing_certificates(std::span<const std::uint8_t> apk, std::uint32_t api_level) {
  if (api_level < 31) {
    return std::unexpected(SignerReadError::kUnsupported);
  }
  if (apk.size() > kMaxApkBytes) {
    return std::unexpected(SignerReadError::kError);
  }
  const auto end_offset = complete_end_offset(apk, 0);
  if (!end_offset.has_value()) {
    return std::unexpected(SignerReadError::kError);
  }
  const auto pairs = signing_block_pairs(apk, read_u32(apk.subspan(*end_offset + kDirectoryOffsetField)));
  if (!pairs.has_value() || pairs->size() > kMaxSigningBlockBytes - kSigningBlockHeaderSize - kSigningBlockFooterSize) {
    return std::unexpected(SignerReadError::kError);
  }
  return complete_signers(*pairs, api_level);
}

SignerCertificates read_signing_certificates(const std::string& apk_path, std::uint32_t api_level) {
  if (api_level < 31) {
    return std::unexpected(SignerReadError::kUnsupported);
  }
  if (apk_path.empty() || apk_path.contains('\0') || apk_path.size() > 4096) {
    return std::unexpected(SignerReadError::kError);
  }
  /// POSIX open's fixed flag argument uses the required variadic libc boundary.
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,misc-include-cleaner)
  const int descriptor = open(apk_path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
  if (descriptor < 0) {
    return std::unexpected(SignerReadError::kError);
  }
  struct stat before = {};
  SignerCertificates result = std::unexpected(SignerReadError::kError);
  if (fstat(descriptor, &before) == 0 && S_ISREG(before.st_mode) && !std::cmp_less(before.st_size, kEndSize) &&
      !std::cmp_greater(before.st_size, kMaxApkBytes)) {
    result = complete_file(descriptor, before, api_level);
    struct stat after = {};
    if (fstat(descriptor, &after) != 0 || !unchanged_archive(before, after)) {
      result = std::unexpected(SignerReadError::kError);
    }
  }
  if (close(descriptor) != 0) {
    return std::unexpected(SignerReadError::kError);
  }
  return result;
}

}  // namespace rasp::android::apk
