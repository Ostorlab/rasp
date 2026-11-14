/// Reading a stored APK entry: memory-map the file, walk the ZIP central directory, and copy the entry's bytes.

#include "apk/archive.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <dirent.h>
#include <expected>
#include <fcntl.h>
#include <map>
#include <optional>
#include <psa/crypto.h>
#include <span>
#include <string>
#include <string_view>
#include <sys/mman.h>
#include <sys/stat.h>
#include <type_traits>
#include <unistd.h>
#include <utility>
#include <vector>

#include "apk/location.h"
#include "checks/integrity.h"

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

/// Reads a little-endian 64-bit value, when at least eight bytes remain.
///
/// @param data The bytes to read from.
/// @return The value.
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

/// The binary-XML chunk types the manifest reader walks: the string pool, the resource map, and start elements.
constexpr std::uint16_t kAxmlStringPoolType = 0x0001;
constexpr std::uint16_t kAxmlStartElementType = 0x0102;
/// The string-pool chunk's own header: counts, flags, and the string data's offset from the chunk's start.
constexpr std::size_t kAxmlPoolHeaderSize = 28;
/// The UTF-8 string-pool flag; without it the strings are UTF-16.
constexpr std::uint32_t kAxmlPoolUtf8 = 0x100;
/// The end of a ZIP file's last entry, where an appended signing block or central directory begins.
constexpr std::uint32_t kZipEndRecordSignature = 0x06054b50;
/// The APK signing block's trailing magic, 16 bytes before the central directory.
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

constexpr std::string_view kApkSigningBlockMagic = "APK Sig Block 42";
/// The APK signature scheme v3 and v2 pair ids, in the order the runtime prefers them.
constexpr std::uint32_t kApkSignatureSchemeV3 = 0xF05368C0;
constexpr std::uint32_t kApkSignatureSchemeV2 = 0x7109871A;
/// The attribute value types the manifest reader canonicalises: a string, a reference, and a boolean.
constexpr std::uint8_t kAxmlTypeString = 0x03;
constexpr std::uint8_t kAxmlTypeBoolean = 0x12;

/// Reads one length-prefixed field from a sequence of them: the prefix is a 32-bit little-endian length.
///
/// @param span The bytes holding the sequence, at the position of the next prefix.
/// @return The field's bytes, or nothing when the prefix or the field does not fit.
[[nodiscard]] std::optional<std::span<const std::uint8_t>> take_length_prefixed(std::span<const std::uint8_t>& span) {
  if (span.size() < 4) {
    return std::nullopt;
  }
  const std::uint32_t length = read_u32(span);
  if (span.size() < 4 + static_cast<std::size_t>(length)) {
    return std::nullopt;
  }
  const std::span<const std::uint8_t> field = span.subspan(4, length);
  span = span.subspan(4 + length);
  return field;
}

/// The string pool of one binary XML document, held with the offsets the reader needs.
struct StringPool {
  /// The pool chunk's bytes, from its chunk header to the end its own size gives. Every string is read from inside it.
  std::span<const std::uint8_t> chunk;
  /// The pool chunk's own size, header included.
  std::uint32_t chunk_size = 0;
  /// The count of strings the pool holds.
  std::uint32_t count = 0;
  /// The flags word, carrying the encoding.
  std::uint32_t flags = 0;
  /// The string data's offset from the chunk's start.
  std::uint32_t data_start = 0;
};

/// Reads the string pool chunk at the start of a binary XML document.
///
/// @param document The document's bytes.
/// @return The pool, or nothing when the document is too short or its first chunk is not the pool.
[[nodiscard]] std::optional<StringPool> read_string_pool(std::span<const std::uint8_t> document) {
  if (document.size() < 8 + kAxmlPoolHeaderSize) {
    return std::nullopt;
  }
  const std::uint16_t chunk_type = read_u16(document.subspan(8));
  if (chunk_type != kAxmlStringPoolType) {
    return std::nullopt;
  }
  // The document's first chunk is the XML file header, eight bytes; the string pool follows it.
  const std::span<const std::uint8_t> pool_chunk = document.subspan(8);
  StringPool pool;
  pool.chunk_size = read_u32(pool_chunk.subspan(4));
  pool.count = read_u32(pool_chunk.subspan(8));
  pool.flags = read_u32(pool_chunk.subspan(16));
  pool.data_start = read_u32(pool_chunk.subspan(20));
  if (pool.chunk_size < kAxmlPoolHeaderSize || pool.chunk_size > pool_chunk.size()) {
    return std::nullopt;
  }
  // The offsets table and the string data both lie inside the pool's own chunk, so the strings start inside it too.
  if (pool.data_start < kAxmlPoolHeaderSize || pool.data_start > pool.chunk_size) {
    return std::nullopt;
  }
  if (kAxmlPoolHeaderSize + 4ULL * pool.count > pool.data_start) {
    return std::nullopt;
  }
  // Bounding the pool by its own size, not by the rest of the document, keeps every string read inside the pool.
  pool.chunk = pool_chunk.first(pool.chunk_size);
  return pool;
}

/// Reads one UTF-8 string of a pool: two lengths, the string's length in UTF-16 units and then in bytes, each one byte
/// or two (a set high bit marks the two-byte form), then the bytes and a null.
///
/// @param at The string's bytes, up to the end of the pool's chunk.
/// @return The string's bytes. Nothing when a length or the bytes run past the pool's chunk.
[[nodiscard]] std::optional<std::string> utf8_pool_string(std::span<const std::uint8_t> at) {
  std::size_t used = 0;
  // Reads the length at `used`, checking that each of its bytes is there before reading it.
  const auto take_length = [&at, &used]() -> std::optional<std::uint32_t> {
    if (used >= at.size()) {
      return std::nullopt;
    }
    std::uint32_t length = at[used++];
    if ((length & 0x80U) != 0) {
      if (used >= at.size()) {
        return std::nullopt;
      }
      length = ((length & 0x7FU) << 8U) | at[used++];
    }
    return length;
  };
  // The first length counts UTF-16 units. The second, the byte count, is the one that bounds the bytes.
  if (!take_length().has_value()) {
    return std::nullopt;
  }
  const std::optional<std::uint32_t> length = take_length();
  if (!length.has_value() || at.size() - used < std::size_t{*length} + 1) {
    return std::nullopt;
  }
  return std::string(reinterpret_cast<const char*>(at.data()) + used, *length);
}

/// Appends `code_point` to `out`, encoded as UTF-8.
void append_utf8(std::string& out, std::uint32_t code_point) {
  if (code_point < 0x80U) {
    out.push_back(static_cast<char>(code_point));
  } else if (code_point < 0x800U) {
    out.push_back(static_cast<char>(0xC0U | (code_point >> 6U)));
    out.push_back(static_cast<char>(0x80U | (code_point & 0x3FU)));
  } else if (code_point < 0x10000U) {
    out.push_back(static_cast<char>(0xE0U | (code_point >> 12U)));
    out.push_back(static_cast<char>(0x80U | ((code_point >> 6U) & 0x3FU)));
    out.push_back(static_cast<char>(0x80U | (code_point & 0x3FU)));
  } else {
    out.push_back(static_cast<char>(0xF0U | (code_point >> 18U)));
    out.push_back(static_cast<char>(0x80U | ((code_point >> 12U) & 0x3FU)));
    out.push_back(static_cast<char>(0x80U | ((code_point >> 6U) & 0x3FU)));
    out.push_back(static_cast<char>(0x80U | (code_point & 0x3FU)));
  }
}

/// Reads one UTF-16 string of a pool: its length in UTF-16 units, one unit or two (a set high bit marks the two-unit
/// form), then the units and a null unit. The string comes back in UTF-8, the encoding the packer hashes the
/// manifest's strings in, so a string beyond ASCII gives the same bytes on both sides.
///
/// @param at The string's bytes, up to the end of the pool's chunk; at least two.
/// @return The string in UTF-8. Nothing when the units run past the pool's chunk, or hold a surrogate without its
/// pair, which no string the packer wrote can hold.
[[nodiscard]] std::optional<std::string> utf16_pool_string(std::span<const std::uint8_t> at) {
  std::uint32_t length = read_u16(at);
  std::size_t used = 2;
  if ((length & 0x8000U) != 0) {
    if (at.size() < 4) {
      return std::nullopt;
    }
    length = ((length & 0x7FFFU) << 16U) | read_u16(at.subspan(2));
    used = 4;
  }
  if (at.size() - used < 2ULL * length + 2) {
    return std::nullopt;
  }
  const std::span<const std::uint8_t> units = at.subspan(used, 2ULL * length);
  std::string out;
  out.reserve(length);
  std::size_t unit = 0;
  while (unit < length) {
    const std::uint32_t first = read_u16(units.subspan(2 * unit));
    unit++;
    if (first < 0xD800U || first > 0xDFFFU) {
      append_utf8(out, first);
      continue;
    }
    // A high surrogate followed by a low one encodes a code point above U+FFFF.
    if (first > 0xDBFFU || unit == length) {
      return std::nullopt;
    }
    const std::uint32_t second = read_u16(units.subspan(2 * unit));
    unit++;
    if (second < 0xDC00U || second > 0xDFFFU) {
      return std::nullopt;
    }
    append_utf8(out, 0x10000U + ((first - 0xD800U) << 10U) + (second - 0xDC00U));
  }
  return out;
}

/// Reads one string of the pool by its index.
///
/// @param pool The pool.
/// @param index The string's index.
/// @return The string in UTF-8, without its terminator. Nothing when the index is out of bounds, or the string does not
/// fit the pool's chunk or does not decode.
[[nodiscard]] std::optional<std::string> pool_string(const StringPool& pool, std::uint32_t index) {
  if (index >= pool.count) {
    return std::nullopt;
  }
  const std::uint32_t offset = read_u32(pool.chunk.subspan(kAxmlPoolHeaderSize + 4ULL * index));
  // Both numbers come from the file and are 32-bit. They are added in 64-bit arithmetic, where a large offset cannot
  // wrap the sum back to a small value that looks in bounds.
  const std::uint64_t start = std::uint64_t{pool.data_start} + offset;
  if (start > pool.chunk.size() || pool.chunk.size() - start < 2) {
    return std::nullopt;
  }
  const std::span<const std::uint8_t> at = pool.chunk.subspan(static_cast<std::size_t>(start));
  if ((pool.flags & kAxmlPoolUtf8) != 0) {
    return utf8_pool_string(at);
  }
  return utf16_pool_string(at);
}

/// The names of the attributes the build and store toolchains stamp on their own: aapt2 records the compile SDK
/// the build ran with, and bundletool marks the base module's split requirement. Their values are neither the
/// packer's to predict nor the runtime's to verify; every other attribute of the two sealed elements is bound.
[[nodiscard]] bool is_volatile_manifest_attribute(std::string_view name) {
  return name == "compileSdkVersion" || name == "compileSdkVersionCodename" || name == "platformBuildVersionCode" ||
         name == "platformBuildVersionName" || name == "isSplitRequired";
}

/// Canonicalises one binary attribute's value the way the packer canonicalises the proto's.
///
/// @param pool The document's string pool.
/// @param raw_value The attribute's raw value, a string index or absent.
/// @param type The attribute value's type.
/// @param data The attribute value's data.
/// @return The canonical bytes, or nothing when a string does not resolve.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> canonical_attribute_value(const StringPool& pool,
                                                                                 std::uint32_t raw_value,
                                                                                 std::uint8_t type,
                                                                                 std::uint32_t data) {
  std::vector<std::uint8_t> out;
  if (type == kAxmlTypeString) {
    const std::uint32_t index = raw_value != 0xFFFFFFFFU ? raw_value : data;
    const std::optional<std::string> text = pool_string(pool, index);
    if (!text.has_value()) {
      return std::nullopt;
    }
    out.insert(out.end(), {'s', 't', 'r'});
    out.insert(out.end(), text->begin(), text->end());
    out.push_back('\0');
    return out;
  }
  if (type == kAxmlTypeBoolean) {
    out.insert(out.end(), {'b', 'o', 'o', 'l'});
    out.push_back(data != 0 ? 1 : 0);
    return out;
  }
  // References and integers both fold to the raw 32-bit data, which the packer reads from the proto's compiled item.
  out.insert(out.end(), {'u', '3', '2'});
  out.push_back(static_cast<std::uint8_t>(data & 0xFF));
  out.push_back(static_cast<std::uint8_t>((data >> 8) & 0xFF));
  out.push_back(static_cast<std::uint8_t>((data >> 16) & 0xFF));
  out.push_back(static_cast<std::uint8_t>((data >> 24) & 0xFF));
  return out;
}

/// Computes the semantic digest of a binary AndroidManifest.xml — the core of read_manifest_semantics. Walks the
/// document's start elements, and for the `<manifest>` and `<application>` elements canonicalises every attribute
/// except the volatile build-stamped names, sorted by element and attribute name: the same digest the packer
/// computes over the protobuf manifest it wrote.
///
/// @param document The manifest's bytes.
/// @return The 32-byte digest. Nothing when the document is malformed or a bound attribute does not resolve.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> find_manifest_semantics(std::span<const std::uint8_t> document) {
  const std::optional<StringPool> pool = read_string_pool(document);
  if (!pool.has_value()) {
    return std::nullopt;
  }
  std::vector<std::vector<std::uint8_t>> entries;
  std::size_t position = 8 + pool->chunk_size;
  while (position + 8 <= document.size()) {
    const std::uint16_t chunk_type = read_u16(document.subspan(position));
    const std::uint32_t chunk_size = read_u32(document.subspan(position + 4));
    if (chunk_size < 8 || position + chunk_size > document.size()) {
      return std::nullopt;
    }
    if (chunk_type == kAxmlStartElementType && chunk_size >= 36) {
      const std::uint32_t element_name_index = read_u32(document.subspan(position + 16 + 4));
      const std::uint16_t attribute_start = read_u16(document.subspan(position + 16 + 8));
      const std::uint16_t attribute_count = read_u16(document.subspan(position + 16 + 12));
      const std::optional<std::string> element_name = pool_string(*pool, element_name_index);
      const bool sealed = element_name.has_value() && (*element_name == "manifest" || *element_name == "application");
      if (!sealed || attribute_count > 64) {
        position += chunk_size;
        continue;
      }
      if (16 + attribute_start + 20ULL * attribute_count > chunk_size) {
        return std::nullopt;
      }
      const std::size_t attributes = position + 16 + attribute_start;
      for (std::uint16_t attribute = 0; attribute < attribute_count; attribute++) {
        const std::size_t at = attributes + 20ULL * attribute;
        const std::uint32_t name_index = read_u32(document.subspan(at + 4));
        const std::uint32_t raw_value = read_u32(document.subspan(at + 8));
        const std::uint8_t type = document[at + 15];
        const std::uint32_t data = read_u32(document.subspan(at + 16));
        const std::optional<std::string> name = pool_string(*pool, name_index);
        if (!name.has_value() || is_volatile_manifest_attribute(*name)) {
          continue;
        }
        const std::optional<std::vector<std::uint8_t>> value = canonical_attribute_value(*pool, raw_value, type, data);
        if (!value.has_value()) {
          return std::nullopt;
        }
        std::vector<std::uint8_t> entry;
        entry.insert(entry.end(), element_name->begin(), element_name->end());
        entry.push_back('\0');
        entry.insert(entry.end(), name->begin(), name->end());
        entry.push_back('\0');
        entry.insert(entry.end(), value->begin(), value->end());
        entries.push_back(std::move(entry));
      }
    }
    position += chunk_size;
  }
  std::ranges::sort(entries);
  std::vector<std::uint8_t> all;
  for (const std::vector<std::uint8_t>& entry : entries) {
    all.insert(all.end(), entry.begin(), entry.end());
  }
  const std::optional<std::array<std::uint8_t, checks::kDigestSize>> digest = checks::sha256(all);
  if (!digest.has_value()) {
    return std::nullopt;
  }
  return std::vector<std::uint8_t>(digest->begin(), digest->end());
}

/// Extracts the DER certificates of the APK's first v3 or v2 signer and concatenates them in order — the core of
/// read_signer_digest.
///

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

/// The result of `read` over the whole file at `apk_path`, memory-mapped read-only for the call, or nothing when the
/// file can't be opened, is empty, or can't be mapped. `read` returns an optional, and this returns it as it is. Every
/// reader of an APK file goes through here, so the mapping and its cleanup on each path live in one place.
template <typename Read>
[[nodiscard]] std::invoke_result_t<Read, std::span<const std::uint8_t>> read_mapped(const std::string& apk_path,
                                                                                    Read read) {
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
  std::invoke_result_t<Read, std::span<const std::uint8_t>> data = read(file);
  munmap(mapping, size);
  return data;
}

/// @param scheme_value The signing block pair's value for the scheme.
/// @return The concatenated certificates. Nothing when the scheme's structure does not parse.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> signer_certificates(std::span<const std::uint8_t> scheme_value) {
  std::span<const std::uint8_t> signers = scheme_value;
  const std::optional<std::span<const std::uint8_t>> signer_sequence = take_length_prefixed(signers);
  if (!signer_sequence.has_value()) {
    return std::nullopt;
  }
  std::span<const std::uint8_t> sequence = *signer_sequence;
  const std::optional<std::span<const std::uint8_t>> signer = take_length_prefixed(sequence);
  if (!signer.has_value()) {
    return std::nullopt;
  }
  std::span<const std::uint8_t> fields = *signer;
  const std::optional<std::span<const std::uint8_t>> signed_data = take_length_prefixed(fields);
  if (!signed_data.has_value()) {
    return std::nullopt;
  }
  std::span<const std::uint8_t> data = *signed_data;
  const std::optional<std::span<const std::uint8_t>> digests = take_length_prefixed(data);
  if (!digests.has_value()) {
    return std::nullopt;
  }
  const std::optional<std::span<const std::uint8_t>> certificates = take_length_prefixed(data);
  if (!certificates.has_value()) {
    return std::nullopt;
  }
  std::vector<std::uint8_t> out;
  std::span<const std::uint8_t> rest = *certificates;
  while (!rest.empty()) {
    const std::optional<std::span<const std::uint8_t>> certificate = take_length_prefixed(rest);
    if (!certificate.has_value()) {
      return std::nullopt;
    }
    out.insert(out.end(), certificate->begin(), certificate->end());
  }
  return out;
}

/// Computes the digest over the APK's class dexes — the core of read_dex_digest. Walks the central
/// directory and feeds every `classes.dex` / `classesN.dex` entry's name and uncompressed content into one
/// SHA-256, sorted by name, the way the packer does over the base module's dexes.
///
/// @param file The APK's whole file bytes, memory-mapped.
/// @return The 32-byte digest. Nothing when the archive is malformed, a class dex is compressed (a store
/// install ships dexes uncompressed, so a compressed one is not a shape the packer predicted), or the hash fails.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> find_dex_digest(std::span<const std::uint8_t> file) {
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

  // Collect each class dex's contribution: its name, a null, and the SHA-256 of its content.
  std::map<std::string, std::vector<std::uint8_t>> contributions;
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
    const std::string_view name(reinterpret_cast<const char*>(rest.data()) + kCentralEntrySize, name_length);
    if (is_classes_entry(name)) {
      if (method != kStored) {
        return std::nullopt;
      }
      const std::optional<std::vector<std::uint8_t>> data =
          read_local_data(file, LocalEntry{.local_offset = local_offset, .data_size = stored_size});
      if (!data.has_value()) {
        return std::nullopt;
      }
      const std::optional<std::array<std::uint8_t, checks::kDigestSize>> content = checks::sha256(*data);
      if (!content.has_value()) {
        return std::nullopt;
      }
      std::vector<std::uint8_t> blob(name.begin(), name.end());
      blob.push_back('\0');
      blob.insert(blob.end(), content->begin(), content->end());
      contributions.emplace(std::string(name), std::move(blob));
    }
    const std::size_t entry_size = kCentralEntrySize + name_length + extra_length + comment_length;
    if (rest.size() < entry_size) {
      return std::nullopt;
    }
    rest = rest.subspan(entry_size);
  }

  std::vector<std::uint8_t> all;
  for (const auto& [name, blob] : contributions) {
    all.insert(all.end(), blob.begin(), blob.end());
  }
  const std::optional<std::array<std::uint8_t, checks::kDigestSize>> digest = checks::sha256(all);
  if (!digest.has_value()) {
    return std::nullopt;
  }
  return std::vector<std::uint8_t>(digest->begin(), digest->end());
}

/// Whether the APK at `path` holds an entry the launch of an installed app would execute or load, by a walk of its
/// central directory: a class dex (the store's config splits never hold one), or the native launch wrapper the
/// platform honours for a debuggable app (no installed app needs one). `count_dexes` turns the class-dex check off
/// for the base APK, whose class dexes are content the packer binds.
///
/// @param path The APK to inspect.
/// @param count_dexes Whether a class dex counts as a hit; a launch wrapper always does.
/// @return Whether the APK holds such an entry. Nothing when the file can't be mapped or the archive is malformed.
[[nodiscard]] std::optional<bool> split_holds_code(const std::string& path, bool count_dexes) {
  return read_mapped(path, [count_dexes](std::span<const std::uint8_t> file) -> std::optional<bool> {
    const std::optional<std::span<const std::uint8_t>> record = find_end_record(file);
    if (!record.has_value()) {
      return std::nullopt;
    }
    const std::uint16_t count = read_u16(record->subspan(10));
    const std::uint32_t directory_size = read_u32(record->subspan(12));
    const std::uint32_t directory_offset = read_u32(record->subspan(16));
    bool holds_code = false;
    if (directory_offset <= file.size() && directory_size <= file.size() - directory_offset) {
      std::span<const std::uint8_t> rest = file.subspan(directory_offset, directory_size);
      for (std::uint16_t index = 0; index < count && !holds_code; ++index) {
        if (rest.size() < kCentralEntrySize || read_u32(rest) != kCentralSignature) {
          break;
        }
        const std::size_t name_length = read_u16(rest.subspan(28));
        const std::size_t extra_length = read_u16(rest.subspan(30));
        const std::size_t comment_length = read_u16(rest.subspan(32));
        if (rest.size() < kCentralEntrySize + name_length) {
          break;
        }
        const std::string_view name(reinterpret_cast<const char*>(rest.data()) + kCentralEntrySize, name_length);
        holds_code = (count_dexes && is_classes_entry(name)) || name.ends_with("wrap.sh");
        const std::size_t entry_size = kCentralEntrySize + name_length + extra_length + comment_length;
        if (rest.size() < entry_size) {
          break;
        }
        rest = rest.subspan(entry_size);
      }
    }
    return holds_code;
  });
}

/// Computes the digest over the APK's qualifying entries — every entry, stored or deflated — the core of
/// read_apk_digest. Walks the central directory and feeds each qualifying entry's name, compression method, CRC-32,
/// uncompressed size, and — for a stored entry — its content into one SHA-256, sorted by name, the way the packer
/// does. A deflated entry contributes its metadata: an entry added, removed, switched between stored and deflated, or
/// whose content changed changes the digest. The compressed size is not bound, because it varies by zlib version and
/// build tool.
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
      // The entry's metadata contribution: method, CRC-32 and uncompressed size, little-endian. Only the name and the
      // three fields are reserved: a stored entry's content is appended once read_local_data has checked its size
      // against the file, so a forged size in the central directory never drives an allocation.
      std::vector<std::uint8_t> blob;
      blob.reserve(name.size() + 12);
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

/// Finds the stub dex in an APK's bytes, the core of read_stub_entry: the highest-numbered `classesN.dex` entry, which
/// the packer always adds last and stored.
///
/// @param file The APK's whole file bytes, memory-mapped.
/// @return The stub dex's bytes. Nothing when the archive is malformed, it holds no class dex, or its highest-numbered
/// class dex is compressed. A compressed stub is refused, never replaced by the next stored dex down, which would be
/// the app's own dex.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> find_stub_entry(std::span<const std::uint8_t> file) {
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
  std::uint32_t best_number = 0;
  bool best_stored = false;
  std::optional<LocalEntry> best_entry;
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
    const std::string_view name(reinterpret_cast<const char*>(rest.data()) + kCentralEntrySize, name_length);
    // Every class dex takes part, stored or compressed, so the highest number is found whatever its method.
    if (is_classes_entry(name)) {
      const std::uint32_t number = classes_number(name);
      if (number > best_number) {
        best_number = number;
        best_stored = method == kStored;
        best_entry = LocalEntry{.local_offset = local_offset, .data_size = stored_size};
      }
    }
    const std::size_t entry_size = kCentralEntrySize + name_length + extra_length + comment_length;
    if (rest.size() < entry_size) {
      return std::nullopt;
    }
    rest = rest.subspan(entry_size);
  }
  if (!best_entry.has_value() || !best_stored) {
    return std::nullopt;
  }
  return read_local_data(file, *best_entry);
}

/// Finds the digest over an APK's signing certificates in its bytes, the core of read_signer_digest: the concatenated
/// DER certificates of the first v3 or v2 scheme pair of the APK Signing Block, hashed once.
///
/// @param file The APK's whole file bytes, memory-mapped.
/// @return The 32-byte digest. Nothing when the APK has no signing block, no v3 or v2 pair, or a pair's length runs
/// past the block.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> find_signer_digest(std::span<const std::uint8_t> file) {
  // The end record's central-directory offset: the APK signing block, when present, ends there, with
  // its trailing size and magic filling the 24 bytes before it.
  std::optional<std::vector<std::uint8_t>> result;
  std::size_t end_scan = file.size() >= 0xFFFF + 22 ? file.size() - 22 - 0xFFFF : 0;
  for (std::size_t position = file.size() >= 22 ? file.size() - 22 : 0; position >= end_scan && position > 0;
       position--) {
    if (read_u32(file.subspan(position)) != kZipEndRecordSignature) {
      continue;
    }
    const std::uint32_t directory_offset = read_u32(file.subspan(position + 16));
    if (directory_offset >= 24 && directory_offset <= file.size() &&
        std::string_view(reinterpret_cast<const char*>(file.data()) + directory_offset - 16, 16) ==
            kApkSigningBlockMagic) {
      // The block's size field counts the pairs and the trailing size and magic, so the pairs start
      // at the offset the size field names before the central directory's end.
      const std::uint64_t block_size = read_u64(file.subspan(directory_offset - 24));
      // The block spans its leading size field, the pairs, and the trailing size and magic, so its
      // named size can reach the central directory's offset less the leading field.
      if (block_size > directory_offset - 8 || block_size < 24) {
        break;
      }
      const std::size_t pairs_start = directory_offset - static_cast<std::size_t>(block_size);
      std::size_t pair = pairs_start;
      while (pair + 12 <= directory_offset - 24) {
        const std::uint64_t pair_size = read_u64(file.subspan(pair));
        // The room left after the pair's own length field, found by subtraction: the loop's condition keeps it
        // positive, and a size near 2^64 read from the file cannot wrap a sum back to a small, in-bounds value.
        if (pair_size < 4 || pair_size > (directory_offset - 24) - pair - 8) {
          break;
        }
        const std::uint32_t scheme = read_u32(file.subspan(pair + 8));
        if (scheme == kApkSignatureSchemeV3 || scheme == kApkSignatureSchemeV2) {
          const std::span<const std::uint8_t> value = file.subspan(pair + 12, static_cast<std::size_t>(pair_size) - 4);
          const std::optional<std::vector<std::uint8_t>> certificates = signer_certificates(value);
          if (certificates.has_value()) {
            const std::optional<std::array<std::uint8_t, checks::kDigestSize>> digest = checks::sha256(*certificates);
            if (digest.has_value()) {
              result = std::vector<std::uint8_t>(digest->begin(), digest->end());
              break;
            }
          }
        }
        pair += 8 + static_cast<std::size_t>(pair_size);
      }
    }
    break;
  }
  return result;
}

}  // namespace

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
std::optional<std::vector<std::uint8_t>> read_stored_entry(const std::string& apk_path, std::string_view name) {
  return read_mapped(apk_path, [name](std::span<const std::uint8_t> file) { return find_stored_entry(file, name); });
}

std::optional<std::vector<std::uint8_t>> read_stub_entry(const std::string& apk_path) {
  return read_mapped(apk_path, find_stub_entry);
}

std::optional<std::vector<std::uint8_t>> read_apk_digest(const std::string& apk_path) {
  const std::string own_library = own_library_suffix();
  return read_mapped(apk_path,
                     [&own_library](std::span<const std::uint8_t> file) { return find_apk_digest(file, own_library); });
}

std::optional<std::vector<std::uint8_t>> read_split_digest(const std::string& apk_path) {
  const std::optional<std::vector<std::string>> splits = list_split_apks(apk_path);
  if (!splits.has_value()) {
    return std::nullopt;
  }
  std::vector<std::uint8_t> names;
  for (const std::string& split : *splits) {
    names.insert(names.end(), split.begin(), split.end());
    names.push_back('\0');
  }
  const std::optional<std::array<std::uint8_t, checks::kDigestSize>> digest = checks::sha256(names);
  if (!digest.has_value()) {
    return std::nullopt;
  }
  return std::vector<std::uint8_t>(digest->begin(), digest->end());
}

std::optional<std::vector<std::string>> list_split_apks(const std::string& apk_path) {
  const std::size_t separator = apk_path.find_last_of('/');
  if (separator == std::string::npos || separator == 0) {
    return std::nullopt;
  }
  const std::string directory = apk_path.substr(0, separator);
  const std::string base = apk_path.substr(separator + 1);
  DIR* const handle = opendir(directory.c_str());
  if (handle == nullptr) {
    return std::nullopt;
  }
  std::vector<std::string> splits;
  while (const dirent* const entry = readdir(handle)) {
    const std::string_view name(entry->d_name);
    if (!name.ends_with(".apk") || name == base) {
      continue;
    }
    splits.emplace_back(name);
  }
  closedir(handle);
  std::ranges::sort(splits);
  return splits;
}

std::optional<std::vector<std::uint8_t>> read_dex_digest(const std::string& apk_path) {
  return read_mapped(apk_path, find_dex_digest);
}

std::optional<std::vector<std::uint8_t>> read_split_dex_flag(const std::string& apk_path) {
  const std::optional<std::vector<std::string>> splits = list_split_apks(apk_path);
  if (!splits.has_value()) {
    return std::nullopt;
  }
  std::vector<std::uint8_t> block(checks::kDigestSize, 0);
  block[0] = 1U;
  const std::size_t separator = apk_path.find_last_of('/');
  if (separator == std::string::npos) {
    return std::nullopt;
  }
  const std::string directory = apk_path.substr(0, separator + 1);
  // The base's own wrapper would flip the fact too, the way a split's does: a launch wrapper is a
  // code-loading hook wherever it sits. The base's class dexes are content the packer binds, so only
  // the wrapper counts here.
  const std::optional<bool> base_wrapper = split_holds_code(apk_path, false);
  if (!base_wrapper.has_value() || *base_wrapper) {
    block[0] = 0U;
    return block;
  }
  for (const std::string& split : *splits) {
    // A split that cannot be read counts as one that carries code: the observation fails closed.
    if (split_holds_code(directory + split, true).value_or(true)) {
      block[0] = 0U;
      break;
    }
  }
  return block;
}

std::optional<std::vector<std::uint8_t>> read_manifest_semantics(const std::string& apk_path) {
  const std::optional<std::vector<std::uint8_t>> manifest = read_stored_entry(apk_path, "AndroidManifest.xml");
  if (!manifest.has_value()) {
    return std::nullopt;
  }
  return find_manifest_semantics(std::span<const std::uint8_t>(*manifest));
}

std::optional<std::vector<std::uint8_t>> read_signer_digest(const std::string& apk_path) {
  return read_mapped(apk_path, find_signer_digest);
}

}  // namespace rasp::android::apk
