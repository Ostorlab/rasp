/// The iOS app-identity self-check: the Team ID and cdhash probe that reads the code signature of the main executable,
/// with its code-signature reader, and its unsupported result off a physical device. The Mach-O file is read through
/// util/macho.h; the code-signature reader draws only on the code-signature layout of xnu's `osfmk/kern/cs_blobs.h`.

#include "checks/identity.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
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
#include <TargetConditionals.h>
#include <mach-o/dyld.h>
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

}  // namespace

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
        unsupported(kTeamIdSignal, kCodeSignatureSource),
        unsupported(kCdhashSignal, kCodeSignatureSource),
    };
  }
  return observe_main_executable_signature();
}

}  // namespace rasp::ios::checks
