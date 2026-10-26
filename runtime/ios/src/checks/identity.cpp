/// The iOS app-identity self-check: the bundle-identifier probes through CFBundle and through the main bundle's
/// Info.plist file, the Team ID and cdhash probe that reads the code signature of the main executable, with its
/// code-signature reader, and their unsupported result off a physical device. The Mach-O file is read through
/// util/macho.h; the code-signature reader draws only on the code-signature layout of xnu's `osfmk/kern/cs_blobs.h`.

#include "checks/identity.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <iterator>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unistd.h>
#include <utility>
#include <vector>

#include "rasp/observation.h"
#include "util/macho.h"
#include "util/sha256.h"

#ifdef __APPLE__
#include <CoreFoundation/CFBase.h>
#include <CoreFoundation/CFBundle.h>
#include <CoreFoundation/CFData.h>
#include <CoreFoundation/CFDictionary.h>
#include <CoreFoundation/CFPropertyList.h>
#include <CoreFoundation/CFString.h>
#include <CoreFoundation/CFURL.h>
#include <TargetConditionals.h>
#include <mach-o/dyld.h>
#include <sys/stat.h>
#include <sys/syslimits.h>
#endif

namespace rasp::ios::checks {

namespace {

#if defined(__APPLE__) && TARGET_OS_IOS && !TARGET_OS_SIMULATOR
/// Whether this build runs on a physical iOS device, the only place the probes mean anything.
constexpr bool kPhysicalDevice = true;
#else
/// Whether this build runs on a physical iOS device, the only place the probes mean anything.
constexpr bool kPhysicalDevice = false;
#endif

/// The signal of the bundle-identifier probes.
constexpr std::string_view kBundleIdSignal = "id.bundle_id";
/// The source of the bundle-identifier probe that asks CoreFoundation, through CFBundleGetIdentifier.
constexpr std::string_view kBundleSource = "CFBundle";
/// The source of the bundle-identifier probe that reads the main bundle's Info.plist file itself.
constexpr std::string_view kInfoPlistSource = "Info.plist";

/// The signal of the Team ID in the main executable's code signature.
constexpr std::string_view kTeamIdSignal = "id.team_id";
/// The signal of the cdhash of the main executable's code signature.
constexpr std::string_view kCdhashSignal = "id.cdhash";
/// The source of the probe that reads the code signature from the main executable's file itself.
constexpr std::string_view kCodeSignatureSource = "code_signature";

/// `LC_CODE_SIGNATURE`, the load command that points to the embedded code signature.
constexpr std::uint32_t kCodeSignatureCommand = 0x1D;
/// The size of a `linkedit_data_command`, the layout of LC_CODE_SIGNATURE, in bytes.
constexpr std::size_t kLinkeditDataCommandSize = 16;
/// The offset of the signature's offset in the file, `dataoff`, in a `linkedit_data_command`.
constexpr std::size_t kDataOffsetOffset = 8;
/// The offset of the signature's size, `datasize`, in a `linkedit_data_command`.
constexpr std::size_t kDataSizeOffset = 12;
/// The most bytes of signature the probe reads. The signature of a real executable has well under this.
constexpr std::size_t kMaxSignatureSize = std::size_t{16} << 20U;

/// `CSMAGIC_EMBEDDED_SIGNATURE`, the magic number of the SuperBlob of an embedded signature.
constexpr std::uint32_t kSuperBlobMagic = 0xFADE0CC0;
/// `CSMAGIC_CODEDIRECTORY`, the magic number of a CodeDirectory.
constexpr std::uint32_t kCodeDirectoryMagic = 0xFADE0C02;
/// The offset of a blob's length, which every blob has after its magic number.
constexpr std::size_t kBlobLengthOffset = 4;
/// The size of a SuperBlob's header, its magic number, length and number of index entries, in bytes.
constexpr std::size_t kSuperBlobHeaderSize = 12;
/// The offset of a SuperBlob's number of index entries, `count`.
constexpr std::size_t kBlobCountOffset = 8;
/// The size of one entry of a SuperBlob's index, `CS_BlobIndex`, its slot type and offset, in bytes.
constexpr std::size_t kBlobIndexSize = 8;
/// The offset of the blob's offset in an entry of a SuperBlob's index.
constexpr std::size_t kBlobIndexOffsetOffset = 4;
/// `CSSLOT_CODEDIRECTORY`, the slot of the main CodeDirectory.
constexpr std::uint32_t kCodeDirectorySlot = 0;
/// `CSSLOT_ALTERNATE_CODEDIRECTORIES`, the first slot of an alternate CodeDirectory.
constexpr std::uint32_t kFirstAlternateSlot = 0x1000;
/// `CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT`, one past the last slot of an alternate CodeDirectory.
constexpr std::uint32_t kAlternateSlotLimit = 0x1005;
/// The offset of a CodeDirectory's version.
constexpr std::size_t kVersionOffset = 8;
/// The size of the fields every CodeDirectory version has, up to and including `spare2`, in bytes.
constexpr std::size_t kCodeDirectoryHeaderSize = 44;
/// The offset of a CodeDirectory's hash type, `hashType`.
constexpr std::size_t kHashTypeOffset = 37;
/// `CS_SUPPORTSTEAMID`, the first CodeDirectory version with a `teamOffset` field.
constexpr std::uint32_t kTeamIdVersion = 0x20200;
/// The offset of a CodeDirectory's `teamOffset` field.
constexpr std::size_t kTeamOffsetOffset = 48;
/// The most bytes of a Team ID the probe accepts. A real one has 10.
constexpr std::size_t kMaxTeamIdBytes = 64;
/// `CS_HASHTYPE_SHA256`, the hash type of a SHA-256 CodeDirectory.
constexpr std::uint8_t kHashTypeSha256 = 2;
/// The hash types the kernel knows, weakest first, as xnu's `hashPriorities` ranks them: SHA-1, SHA-256 truncated to 20
/// bytes, SHA-256, then SHA-384.
constexpr std::array<std::uint8_t, 4> kHashPriorities = {1, 3, 2, 4};
/// `CS_CDHASH_LEN`, the length of a cdhash, in bytes: the first bytes of the CodeDirectory's digest.
constexpr std::size_t kCdhashSize = 20;

/// Reads the big-endian 32-bit number at `offset` in `bytes`, the byte order of every code-signature structure.
///
/// @param bytes The bytes that hold the number.
/// @param offset The offset of the number's first byte.
/// @return The number, or nothing when its four bytes don't lie within `bytes`.
[[nodiscard]] std::optional<std::uint32_t> read_big_endian(std::span<const std::uint8_t> bytes, std::size_t offset) {
  if (!util::range_fits(offset, sizeof(std::uint32_t), bytes.size())) {
    return std::nullopt;
  }
  const std::span<const std::uint8_t> field = bytes.subspan(offset, sizeof(std::uint32_t));
  return (std::uint32_t{field[0]} << 24U) | (std::uint32_t{field[1]} << 16U) | (std::uint32_t{field[2]} << 8U) |
         std::uint32_t{field[3]};
}

/// Where the embedded signature lies in a Mach-O file, as its LC_CODE_SIGNATURE load command gives it.
struct SignatureRange {
  /// The offset of the signature's first byte in the file, `dataoff`.
  std::size_t offset = 0;
  /// The number of bytes of the signature, `datasize`.
  std::size_t size = 0;
};

/// Finds the one LC_CODE_SIGNATURE load command among `commands`.
///
/// @param commands The load commands of the Mach-O file, as util::load_commands splits them.
/// @return Where the signature lies, or nothing when the LC_CODE_SIGNATURE load command is shorter than a
/// `linkedit_data_command`, or when there is no LC_CODE_SIGNATURE load command or more than one.
[[nodiscard]] std::optional<SignatureRange> find_signature_range(std::span<const util::LoadCommand> commands) {
  std::optional<SignatureRange> range;
  for (const util::LoadCommand& command : commands) {
    if (command.command != kCodeSignatureCommand) {
      continue;
    }
    if (range.has_value() || command.bytes.size() < kLinkeditDataCommandSize) {
      return std::nullopt;
    }
    const std::optional<std::uint32_t> data_offset = util::read_little_endian(command.bytes, kDataOffsetOffset);
    const std::optional<std::uint32_t> data_size = util::read_little_endian(command.bytes, kDataSizeOffset);
    if (!data_offset || !data_size) {
      return std::nullopt;
    }
    range = SignatureRange{.offset = *data_offset, .size = *data_size};
  }
  return range;
}

/// Reads the embedded signature of the Mach-O file open as `file`, which must be a regular, thin 64-bit Mach-O file.
///
/// @param file The open file.
/// @return The bytes that the LC_CODE_SIGNATURE load command points to, or nothing when util::read_mach_file or
/// util::load_commands gives nothing, which covers a file that isn't a regular, thin 64-bit little-endian Mach-O file
/// or whose load commands are larger than util::kMaxCommandsSize bytes or malformed; when find_signature_range finds
/// no single signature; when the signature is larger than kMaxSignatureSize bytes or reaches past the end of the file;
/// or when a read fails.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> read_signature(int file) {
  const std::optional<util::MachFile> mach_file = util::read_mach_file(file);
  if (!mach_file) {
    return std::nullopt;
  }
  const std::optional<std::vector<util::LoadCommand>> commands = util::load_commands(mach_file->header_and_commands);
  if (!commands) {
    return std::nullopt;
  }
  const std::optional<SignatureRange> range = find_signature_range(*commands);
  if (!range || range->size > kMaxSignatureSize ||
      !util::range_fits(range->offset, range->size, mach_file->file_size)) {
    return std::nullopt;
  }
  std::vector<std::uint8_t> signature(range->size);
  if (!util::read_exactly(file, range->offset, signature)) {
    return std::nullopt;
  }
  return signature;
}

/// Reads the embedded signature of the Mach-O file at `path`.
///
/// The file is opened with close-on-exec, so it never leaks into a process the app starts, and without blocking, so a
/// FIFO can't stall the open before the regular-file check refuses it.
///
/// @param path The Mach-O file to read.
/// @return The signature's bytes, as read_signature reads them, or nothing when the file can't be opened or closed,
/// or read_signature gives nothing.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> read_executable_signature(const std::string& path) {
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
  const int file = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
  if (file < 0) {
    return std::nullopt;
  }
  std::optional<std::vector<std::uint8_t>> signature = read_signature(file);
  if (close(file) != 0) {
    return std::nullopt;
  }
  return signature;
}

/// The rank of the hash type `hash_type` among the hash types the kernel knows, as xnu's `hash_rank` gives it.
///
/// @param hash_type A CodeDirectory's `hashType`.
/// @return 1 for the weakest hash type in kHashPriorities up to its size for the strongest, or 0 when the kernel
/// doesn't know the hash type.
[[nodiscard]] std::size_t hash_rank(std::uint8_t hash_type) {
  std::size_t rank = 0;
  for (const std::uint8_t known : kHashPriorities) {
    ++rank;
    if (known == hash_type) {
      return rank;
    }
  }
  return 0;
}

/// Reads the Team ID of the CodeDirectory `directory` of version `version`.
///
/// @param directory The CodeDirectory's bytes, as long as its length says.
/// @param version The CodeDirectory's version.
/// @return The Team ID, which is empty when the version predates `teamOffset` or the offset is 0, or nothing when the
/// field or the offset lie past the end of `directory`, when no NUL ends the Team ID within `directory`, or when the
/// Team ID is longer than kMaxTeamIdBytes bytes.
[[nodiscard]] std::optional<std::string> read_team_id(std::span<const std::uint8_t> directory, std::uint32_t version) {
  if (version < kTeamIdVersion) {
    return std::string();
  }
  const std::optional<std::uint32_t> team_offset = read_big_endian(directory, kTeamOffsetOffset);
  if (!team_offset) {
    return std::nullopt;
  }
  if (*team_offset == 0) {
    return std::string();
  }
  if (*team_offset >= directory.size()) {
    return std::nullopt;
  }
  const std::span<const std::uint8_t> rest = directory.subspan(*team_offset);
  const std::span<const std::uint8_t> bounded = rest.first(std::min(rest.size(), kMaxTeamIdBytes + 1));
  const auto terminator = std::ranges::find(bounded, std::uint8_t{0});
  if (terminator == bounded.end()) {
    return std::nullopt;
  }
  return std::string(bounded.begin(), terminator);
}

/// What the probe reads of one CodeDirectory.
struct CodeDirectory {
  /// The offset of the CodeDirectory's first byte in the signature.
  std::size_t offset = 0;
  /// The CodeDirectory's length, the number of bytes its cdhash covers.
  std::size_t size = 0;
  /// The CodeDirectory's hash type, such as kHashTypeSha256.
  std::uint8_t hash_type = 0;
  /// The CodeDirectory's Team ID, empty when it has none.
  std::string team_id;
};

/// Reads the CodeDirectory at `offset` in `signature`, which must lie wholly within the signature.
///
/// @param signature The SuperBlob, as long as its length says.
/// @param offset The offset of the CodeDirectory's first byte in `signature`.
/// @param size The CodeDirectory's length, its blob length, which fits in `signature` from `offset`.
/// @return What the probe reads of the CodeDirectory, or nothing when it is shorter than the fields every version has,
/// its magic number isn't kCodeDirectoryMagic, the kernel doesn't know its hash type, or read_team_id gives nothing.
[[nodiscard]] std::optional<CodeDirectory> read_code_directory(std::span<const std::uint8_t> signature,
                                                               std::size_t offset, std::size_t size) {
  if (size < kCodeDirectoryHeaderSize) {
    return std::nullopt;
  }
  const std::span<const std::uint8_t> directory = signature.subspan(offset, size);
  const std::optional<std::uint32_t> magic = read_big_endian(directory, 0);
  const std::optional<std::uint32_t> version = read_big_endian(directory, kVersionOffset);
  const std::uint8_t hash_type = directory[kHashTypeOffset];
  if (!magic || !version || *magic != kCodeDirectoryMagic || hash_rank(hash_type) == 0) {
    return std::nullopt;
  }
  std::optional<std::string> team_id = read_team_id(directory, *version);
  if (!team_id) {
    return std::nullopt;
  }
  return CodeDirectory{.offset = offset, .size = size, .hash_type = hash_type, .team_id = std::move(*team_id)};
}

/// Whether `slot` is the slot of a CodeDirectory: the CodeDirectory slot or one of the alternate ones.
///
/// @param slot The slot type of an entry of a SuperBlob's index.
/// @return `true` for kCodeDirectorySlot and for the slots from kFirstAlternateSlot up to kAlternateSlotLimit.
[[nodiscard]] constexpr bool is_code_directory_slot(std::uint32_t slot) {
  return slot == kCodeDirectorySlot || (slot >= kFirstAlternateSlot && slot < kAlternateSlotLimit);
}

/// Picks the CodeDirectory of the embedded signature `signature` that the kernel uses, as xnu's
/// `cs_validate_csblob` does.
///
/// The SuperBlob's length must fit in `signature`, and every offset and length after it must fit in that length. Each
/// entry of the index must point to a blob whose length fits in what is left of the SuperBlob. Among the
/// CodeDirectories in the CodeDirectory slot and the alternate slots, the one whose hash type has the highest rank
/// wins. One with the same rank as the best so far is a second CodeDirectory of the same hash type, which the kernel
/// rejects.
///
/// @param signature The bytes that the LC_CODE_SIGNATURE load command points to.
/// @return The CodeDirectory the kernel uses, or nothing when the SuperBlob's magic number isn't kSuperBlobMagic,
/// its length is shorter than its header or longer than `signature`, its index doesn't fit in it, an entry points past
/// its end or to a blob that doesn't fit in it, read_code_directory gives nothing for one of its CodeDirectories, two
/// of them have the same hash type, or it has none.
[[nodiscard]] std::optional<CodeDirectory> select_code_directory(std::span<const std::uint8_t> signature) {
  const std::optional<std::uint32_t> magic = read_big_endian(signature, 0);
  const std::optional<std::uint32_t> length = read_big_endian(signature, kBlobLengthOffset);
  const std::optional<std::uint32_t> count = read_big_endian(signature, kBlobCountOffset);
  if (!magic || !length || !count || *magic != kSuperBlobMagic || *length < kSuperBlobHeaderSize ||
      *length > signature.size()) {
    return std::nullopt;
  }
  const std::span<const std::uint8_t> blob = signature.first(*length);
  if ((blob.size() - kSuperBlobHeaderSize) / kBlobIndexSize < *count) {
    return std::nullopt;
  }
  std::optional<CodeDirectory> best;
  std::size_t best_rank = 0;
  for (std::uint32_t index = 0; index < *count; ++index) {
    const std::size_t entry = kSuperBlobHeaderSize + (std::size_t{index} * kBlobIndexSize);
    const std::optional<std::uint32_t> slot = read_big_endian(blob, entry);
    const std::optional<std::uint32_t> offset = read_big_endian(blob, entry + kBlobIndexOffsetOffset);
    if (!slot || !offset || *offset > blob.size()) {
      return std::nullopt;
    }
    const std::optional<std::uint32_t> size = read_big_endian(blob.subspan(*offset), kBlobLengthOffset);
    if (!size || *size > blob.size() - *offset) {
      return std::nullopt;
    }
    if (!is_code_directory_slot(*slot)) {
      continue;
    }
    std::optional<CodeDirectory> candidate = read_code_directory(blob, *offset, *size);
    if (!candidate) {
      return std::nullopt;
    }
    const std::size_t rank = hash_rank(candidate->hash_type);
    if (rank == best_rank) {
      return std::nullopt;
    }
    if (rank > best_rank) {
      best = std::move(candidate);
      best_rank = rank;
    }
  }
  return best;
}

/// The cdhash of the CodeDirectory whose bytes are `directory`: their SHA-256, cut to its first kCdhashSize bytes, in
/// lowercase hex.
///
/// @param directory The CodeDirectory's bytes, as long as its length says.
/// @return The cdhash as 40 hex digits, or nothing when TF-PSA-Crypto can't start or can't compute the digest.
[[nodiscard]] std::optional<std::string> cdhash_hex(std::span<const std::uint8_t> directory) {
  std::optional<std::string> digest = util::sha256_hex(directory);
  if (!digest) {
    return std::nullopt;
  }
  digest->resize(kCdhashSize * 2);
  return digest;
}

/// Returns the id.team_id and id.cdhash observations of a signature the probe couldn't read.
///
/// @return The two observations through code_signature, both with an error status.
[[nodiscard]] std::vector<Observation> unreadable_signature() {
  return {failed(kTeamIdSignal, kCodeSignatureSource), failed(kCdhashSignal, kCodeSignatureSource)};
}

#ifdef __APPLE__
/// The path of the Info.plist file inside the directory of an iOS app bundle, which keeps it at its top level.
constexpr std::string_view kInfoPlistPath = "/Info.plist";

/// The largest Info.plist file the probe reads, in bytes. A real one is well under this.
constexpr std::size_t kMaxInfoPlistSize = std::size_t{1} << 20U;

/// The most bytes of UTF-8 the probes accept of a bundle identifier, so a forged value can't grow the observation
/// without bound.
constexpr std::size_t kMaxIdentifierBytes = 1024;

/// Converts `value` to UTF-8 text, when it is a CFString of at most kMaxIdentifierBytes bytes of UTF-8.
///
/// The value is not released: the caller owns it, or gets it under the Get rule.
///
/// @param value The value to convert, or null.
/// @return The text, or nothing when `value` is null or not a CFString, when its UTF-8 is longer than
/// kMaxIdentifierBytes bytes, or when it holds a character UTF-8 can't encode, a lone UTF-16 surrogate.
[[nodiscard]] std::optional<std::string> read_text(CFTypeRef value) {
  if (value == nullptr || CFGetTypeID(value) != CFStringGetTypeID()) {
    return std::nullopt;
  }
  const auto* const string = static_cast<CFStringRef>(value);
  const CFIndex length = CFStringGetLength(string);
  std::array<std::uint8_t, kMaxIdentifierBytes> buffer{};
  CFIndex used = 0;
  if (CFStringGetBytes(string, CFRangeMake(0, length), kCFStringEncodingUTF8, 0, 0, buffer.data(),
                       static_cast<CFIndex>(buffer.size()), &used) != length) {
    return std::nullopt;
  }
  return std::string(buffer.begin(), std::next(buffer.begin(), used));
}

/// Reads `file` to its end, or gives nothing when a read fails or the content is longer than kMaxInfoPlistSize bytes.
/// A read that a signal interrupts is retried.
///
/// @param file The open file to read.
/// @return The content of the file, or nothing when a read fails or the content is too long.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> read_all(int file) {
  std::vector<std::uint8_t> content;
  std::array<std::uint8_t, 1024> chunk{};
  while (true) {
    const ssize_t count = read(file, chunk.data(), chunk.size());
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count < 0 || static_cast<std::size_t>(count) > kMaxInfoPlistSize - content.size()) {
      return std::nullopt;
    }
    if (count == 0) {
      return content;
    }
    content.insert(content.end(), chunk.begin(), std::next(chunk.begin(), count));
  }
}

/// Reads the regular file at `path` to its end, when it holds at most kMaxInfoPlistSize bytes.
///
/// The file is opened with close-on-exec, so it never leaks into a process the app starts, and without blocking, so a
/// FIFO can't stall the open before the regular-file check refuses it.
///
/// @param path The file to read.
/// @return The content of the file, or nothing when it can't be opened, inspected, read or closed, isn't a regular
/// file, or is longer than kMaxInfoPlistSize bytes.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> read_file(const std::string& path) {
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
  const int file = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
  if (file < 0) {
    return std::nullopt;
  }
  struct stat status{};
  std::optional<std::vector<std::uint8_t>> content =
      fstat(file, &status) == 0 && S_ISREG(status.st_mode) ? read_all(file) : std::nullopt;
  if (close(file) != 0) {
    return std::nullopt;
  }
  return content;
}

/// Reads the bundle identifier, the value of the `CFBundleIdentifier` key, from `content`, the bytes of a property
/// list in the binary or the XML format.
///
/// The CFData that wraps the bytes and the property list parsed from it are created here, under the Create rule, so
/// both are released on every path. The identifier is owned by the property list, under the Get rule, so it is
/// converted before the property list is released and is not released itself.
///
/// @param content The property list's bytes.
/// @return The identifier, or nothing when `content` isn't a property list, when the property list isn't a
/// dictionary or has no `CFBundleIdentifier` key, or when the identifier can't be read as read_text reads it.
[[nodiscard]] std::optional<std::string> read_plist_identifier(std::span<const std::uint8_t> content) {
  const CFDataRef data = CFDataCreate(kCFAllocatorDefault, content.data(), static_cast<CFIndex>(content.size()));
  if (data == nullptr) {
    return std::nullopt;
  }
  const CFPropertyListRef plist =
      CFPropertyListCreateWithData(kCFAllocatorDefault, data, kCFPropertyListImmutable, nullptr, nullptr);
  std::optional<std::string> identifier;
  if (plist != nullptr) {
    if (CFGetTypeID(plist) == CFDictionaryGetTypeID()) {
      identifier = read_text(CFDictionaryGetValue(static_cast<CFDictionaryRef>(plist), kCFBundleIdentifierKey));
    }
    CFRelease(plist);
  }
  CFRelease(data);
  return identifier;
}

/// Reads the file system path of the main bundle's directory.
///
/// The main bundle is owned by CoreFoundation, under the Get rule, so it is not released. Its URL is created here,
/// under the Copy rule, so it is released on every path.
///
/// @return The path, or nothing when there is no main bundle or URL, or when the path doesn't fit in PATH_MAX bytes
/// with its terminating NUL.
[[nodiscard]] std::optional<std::string> main_bundle_directory() {
  auto* const bundle = CFBundleGetMainBundle();
  if (bundle == nullptr) {
    return std::nullopt;
  }
  const CFURLRef url = CFBundleCopyBundleURL(bundle);
  if (url == nullptr) {
    return std::nullopt;
  }
  std::array<std::uint8_t, PATH_MAX> buffer{};
  const bool converted =
      CFURLGetFileSystemRepresentation(url, 1, buffer.data(), static_cast<CFIndex>(buffer.size())) != 0;
  CFRelease(url);
  if (!converted) {
    return std::nullopt;
  }
  return std::string(buffer.begin(), std::ranges::find(buffer, std::uint8_t{0}));
}
#endif

}  // namespace

Observation observe_bundle_identifier() {
#ifdef __APPLE__
  auto* const bundle = CFBundleGetMainBundle();
  if (bundle == nullptr) {
    return failed(kBundleIdSignal, kBundleSource);
  }
  std::optional<std::string> identifier = read_text(CFBundleGetIdentifier(bundle));
  if (!identifier.has_value() || identifier->empty()) {
    return failed(kBundleIdSignal, kBundleSource);
  }
  return observed(kBundleIdSignal, kBundleSource, std::move(*identifier));
#else
  return unsupported(kBundleIdSignal, kBundleSource);
#endif
}

Observation observe_info_plist([[maybe_unused]] std::string_view plist_path) {
#ifdef __APPLE__
  const std::optional<std::vector<std::uint8_t>> content = read_file(std::string(plist_path));
  if (!content.has_value()) {
    return failed(kBundleIdSignal, kInfoPlistSource);
  }
  std::optional<std::string> identifier = read_plist_identifier(*content);
  if (!identifier.has_value() || identifier->empty()) {
    return failed(kBundleIdSignal, kInfoPlistSource);
  }
  return observed(kBundleIdSignal, kInfoPlistSource, std::move(*identifier));
#else
  return unsupported(kBundleIdSignal, kInfoPlistSource);
#endif
}

Observation observe_main_info_plist() {
#ifdef __APPLE__
  const std::optional<std::string> directory = main_bundle_directory();
  if (!directory.has_value()) {
    return failed(kBundleIdSignal, kInfoPlistSource);
  }
  return observe_info_plist(*directory + std::string(kInfoPlistPath));
#else
  return unsupported(kBundleIdSignal, kInfoPlistSource);
#endif
}

std::vector<Observation> observe_executable_signature(std::string_view executable_path) {
  const std::optional<std::vector<std::uint8_t>> signature = read_executable_signature(std::string(executable_path));
  if (!signature) {
    return unreadable_signature();
  }
  const std::optional<CodeDirectory> directory = select_code_directory(*signature);
  if (!directory) {
    return unreadable_signature();
  }
  const std::optional<std::string> cdhash =
      directory->hash_type == kHashTypeSha256
          ? cdhash_hex(std::span(*signature).subspan(directory->offset, directory->size))
          : std::nullopt;
  return {
      observed(kTeamIdSignal, kCodeSignatureSource, directory->team_id),
      cdhash ? observed(kCdhashSignal, kCodeSignatureSource, *cdhash) : failed(kCdhashSignal, kCodeSignatureSource),
  };
}

std::vector<Observation> observe_main_executable_signature() {
#ifdef __APPLE__
  std::array<char, PATH_MAX> path{};
  auto size = static_cast<std::uint32_t>(path.size());
  if (_NSGetExecutablePath(path.data(), &size) != 0) {
    return unreadable_signature();
  }
  return observe_executable_signature(std::string_view(path.data()));
#else
  return {unsupported(kTeamIdSignal, kCodeSignatureSource), unsupported(kCdhashSignal, kCodeSignatureSource)};
#endif
}

std::vector<Observation> identity() {
  if (!kPhysicalDevice) {
    return {
        unsupported(kBundleIdSignal, kBundleSource),
        unsupported(kBundleIdSignal, kInfoPlistSource),
        unsupported(kTeamIdSignal, kCodeSignatureSource),
        unsupported(kCdhashSignal, kCodeSignatureSource),
    };
  }
  std::vector<Observation> observations = {observe_bundle_identifier(), observe_main_info_plist()};
  std::ranges::move(observe_main_executable_signature(), std::back_inserter(observations));
  return observations;
}

}  // namespace rasp::ios::checks
