/// Tests for the iOS app-identity self-check: the bundle-identifier probes through CFBundle and through the main
/// bundle's Info.plist file, and the Team ID and cdhash probe that reads an executable's code signature, against the
/// signature codesign made in data/ and against signatures built here.

#include "checks/identity.h"

#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "rasp/observation.h"
#include "support/files.h"

namespace rasp::ios::checks {
namespace {

using test_support::make_fifo;
using test_support::read_file;
using test_support::TemporaryDirectory;
using test_support::write_file;

/// The CodeDirectory version that has a `teamOffset` field, the version codesign writes.
constexpr std::uint32_t kExecSegmentVersion = 0x20400;
/// A CodeDirectory version older than the `teamOffset` field.
constexpr std::uint32_t kScatterVersion = 0x20100;
/// `CS_HASHTYPE_SHA1`.
constexpr std::uint8_t kSha1 = 1;
/// `CS_HASHTYPE_SHA256`.
constexpr std::uint8_t kSha256 = 2;
/// `CS_HASHTYPE_SHA384`.
constexpr std::uint8_t kSha384 = 4;
/// `CSSLOT_CODEDIRECTORY`.
constexpr std::uint32_t kCodeDirectorySlot = 0;
/// `CSSLOT_REQUIREMENTS`.
constexpr std::uint32_t kRequirementsSlot = 2;
/// `CSSLOT_ALTERNATE_CODEDIRECTORIES`, the first alternate CodeDirectory slot.
constexpr std::uint32_t kFirstAlternateSlot = 0x1000;
/// The Team ID of the SHA-256 CodeDirectories built here.
constexpr std::string_view kTeamId = "ABCDE12345";
/// The Team ID of the CodeDirectories of other hash types built here, so a test sees which one the probe used.
constexpr std::string_view kOtherTeamId = "ZYXWV98765";
/// The cdhash of the SHA-256 CodeDirectory of version kExecSegmentVersion with kTeamId that code_directory builds,
/// computed with Python's hashlib from the same bytes.
constexpr std::string_view kTeamCdhash = "d33106eff2904124a77b585dfb1459beb04063ed";
/// The cdhash that `codesign -dvvv` reports for the ad-hoc signature in data/, computed with Python's hashlib from its
/// SHA-256 CodeDirectory.
constexpr std::string_view kFixtureCdhash = "a92fa5a19ede7cbd54cda3b06251845fa29795ec";

/// Writes `value` into `bytes` at `offset` as a big-endian 32-bit number, replacing what is there.
///
/// @param bytes The bytes to change, which hold at least `offset + 4` bytes.
/// @param offset Where the number starts.
/// @param value The number.
void set_big_endian(std::string& bytes, std::size_t offset, std::uint32_t value) {
  for (std::size_t index = 0; index < 4; ++index) {
    bytes[offset + index] = static_cast<char>((value >> (24U - (8U * index))) & 0xFFU);
  }
}

/// Appends `value` to `bytes` as a big-endian 32-bit number, the byte order of the code-signature structures.
///
/// @param bytes The bytes to append to.
/// @param value The number.
void append_big_endian(std::string& bytes, std::uint32_t value) {
  bytes.append(4, '\0');
  set_big_endian(bytes, bytes.size() - 4, value);
}

/// Appends `value` to `bytes` as a little-endian 32-bit number, the byte order of an arm64 Mach-O header.
///
/// @param bytes The bytes to append to.
/// @param value The number.
void append_little_endian(std::string& bytes, std::uint32_t value) {
  for (std::uint32_t shift = 0; shift < 32; shift += 8) {
    bytes.push_back(static_cast<char>((value >> shift) & 0xFFU));
  }
}

/// Returns a CodeDirectory with no hash slots, the identifier `co.ostorlab.app` and the Team ID `team_id`.
///
/// Its header has the fields of `version`: up to `spare2`, then `scatterOffset` from version 0x20100, then
/// `teamOffset` from version 0x20200. The identifier follows the header, then the Team ID with its NUL when it isn't
/// empty; `teamOffset` is 0 when it is.
///
/// @param hash_type The CodeDirectory's `hashType`.
/// @param team_id The Team ID, or empty for none.
/// @param version The CodeDirectory's version.
/// @return The CodeDirectory's bytes.
[[nodiscard]] std::string code_directory(std::uint8_t hash_type, std::string_view team_id, std::uint32_t version) {
  constexpr std::string_view kIdentifier{"co.ostorlab.app\0", 16};
  std::size_t header_size = 44;
  if (version >= 0x20100) {
    header_size += 4;
  }
  if (version >= 0x20200) {
    header_size += 4;
  }
  const std::size_t team_size = team_id.empty() ? 0 : team_id.size() + 1;
  const auto length = static_cast<std::uint32_t>(header_size + kIdentifier.size() + team_size);
  std::uint8_t hash_size = 0;
  if (hash_type == kSha1 || hash_type == 3) {
    hash_size = 20;
  } else if (hash_type == kSha256) {
    hash_size = 32;
  } else if (hash_type == kSha384) {
    hash_size = 48;
  }
  std::string bytes;
  for (const std::uint32_t field :
       {0xFADE0C02U, length, version, 0U, length, static_cast<std::uint32_t>(header_size), 0U, 0U, 0U}) {
    append_big_endian(bytes, field);
  }
  bytes.push_back(static_cast<char>(hash_size));
  bytes.push_back(static_cast<char>(hash_type));
  bytes.push_back('\0');
  bytes.push_back('\x0c');
  append_big_endian(bytes, 0);
  if (version >= 0x20100) {
    append_big_endian(bytes, 0);
  }
  if (version >= 0x20200) {
    append_big_endian(bytes, team_id.empty() ? 0 : static_cast<std::uint32_t>(header_size + kIdentifier.size()));
  }
  bytes += kIdentifier;
  if (!team_id.empty()) {
    bytes += team_id;
    bytes.push_back('\0');
  }
  return bytes;
}

/// One blob of a SuperBlob, with the slot its index entry gives it.
struct SlotBlob {
  /// The slot type, such as CSSLOT_CODEDIRECTORY.
  std::uint32_t slot = 0;
  /// The blob's bytes.
  std::string blob;
};

/// Returns the SuperBlob of an embedded signature that holds `blobs`, in that order, after its index.
///
/// @param blobs The blobs and their slots.
/// @return The SuperBlob's bytes.
[[nodiscard]] std::string super_blob(const std::vector<SlotBlob>& blobs) {
  std::size_t offset = 12 + (8 * blobs.size());
  std::string index;
  std::string content;
  for (const SlotBlob& entry : blobs) {
    append_big_endian(index, entry.slot);
    append_big_endian(index, static_cast<std::uint32_t>(offset));
    content += entry.blob;
    offset += entry.blob.size();
  }
  std::string bytes;
  append_big_endian(bytes, 0xFADE0CC0);
  append_big_endian(bytes, static_cast<std::uint32_t>(offset));
  append_big_endian(bytes, static_cast<std::uint32_t>(blobs.size()));
  return bytes + index + content;
}

/// Returns an LC_CODE_SIGNATURE load command that points to `size` bytes at `offset` in the file.
///
/// @param offset The signature's offset in the file, `dataoff`.
/// @param size The signature's size, `datasize`.
/// @return The load command's bytes.
[[nodiscard]] std::string signature_command(std::uint32_t offset, std::uint32_t size) {
  std::string bytes;
  for (const std::uint32_t field : {0x1DU, 16U, offset, size}) {
    append_little_endian(bytes, field);
  }
  return bytes;
}

/// Returns a 64-bit arm64 Mach-O executable whose `count` load commands are `commands`, followed by `tail`.
///
/// @param commands The load commands' bytes, which the header's `sizeofcmds` counts.
/// @param count The header's `ncmds`.
/// @param tail What the file holds after the load commands.
/// @return The file's bytes.
[[nodiscard]] std::string mach_o(std::string_view commands, std::uint32_t count, std::string_view tail) {
  std::string bytes;
  for (const std::uint32_t field :
       {0xFEEDFACFU, 0x0100000CU, 0U, 2U, count, static_cast<std::uint32_t>(commands.size()), 0U, 0U}) {
    append_little_endian(bytes, field);
  }
  bytes += commands;
  bytes += tail;
  return bytes;
}

/// Returns a 64-bit arm64 Mach-O executable whose one LC_CODE_SIGNATURE load command points to `signature`, which
/// follows it.
///
/// @param signature The bytes of the embedded signature.
/// @return The file's bytes.
[[nodiscard]] std::string signed_mach_o(std::string_view signature) {
  return mach_o(signature_command(48, static_cast<std::uint32_t>(signature.size())), 1, signature);
}

/// Writes `content` to an executable file in `directory` and returns its path.
///
/// @param directory The directory to write the file in.
/// @param content What the file holds.
/// @return The file's path, or empty when it couldn't be written.
[[nodiscard]] std::string write_executable(const TemporaryDirectory& directory, std::string_view content) {
  const std::string path = directory.path() + "/App";
  return write_file(path, content) ? path : std::string();
}

/// Returns the id.team_id and id.cdhash observations that report `team_id` and `cdhash`.
///
/// @param team_id The Team ID reported.
/// @param cdhash The cdhash reported.
/// @return The two observations through code_signature, with status kOk.
[[nodiscard]] std::vector<Observation> signature_values(std::string team_id, std::string cdhash) {
  return {
      {.signal = "id.team_id", .source = "code_signature", .status = Status::kOk, .value = std::move(team_id)},
      {.signal = "id.cdhash", .source = "code_signature", .status = Status::kOk, .value = std::move(cdhash)},
  };
}

/// Returns the id.team_id observation that reports `team_id`, and the id.cdhash observation that failed.
///
/// @param team_id The Team ID reported.
/// @return The two observations through code_signature.
[[nodiscard]] std::vector<Observation> team_id_only(std::string team_id) {
  return {
      {.signal = "id.team_id", .source = "code_signature", .status = Status::kOk, .value = std::move(team_id)},
      {.signal = "id.cdhash", .source = "code_signature", .status = Status::kError, .value = {}},
  };
}

/// Returns the id.team_id and id.cdhash observations of a signature the probe couldn't read.
///
/// @return The two observations through code_signature, with status kError and no value.
[[nodiscard]] std::vector<Observation> unreadable_signature() {
  return {
      {.signal = "id.team_id", .source = "code_signature", .status = Status::kError, .value = {}},
      {.signal = "id.cdhash", .source = "code_signature", .status = Status::kError, .value = {}},
  };
}

/// Writes `content` to an executable file and returns what observe_executable_signature reports for it.
///
/// @param content What the file holds.
/// @return The observations, or none when the file couldn't be written, which makes the test fail.
[[nodiscard]] std::vector<Observation> observe_file(std::string_view content) {
  const TemporaryDirectory directory;
  const std::string path = write_executable(directory, content);
  if (directory.path().empty() || path.empty()) {
    return {};
  }
  return observe_executable_signature(path);
}

/// Returns the signature in data/: the 548 bytes of the `CS_SuperBlob` that `codesign -s -` embedded in
/// `packer/tests/rasp_packer/ios/data/arm64_app_signed`, without the zero padding codesign leaves after it.
///
/// @return The SuperBlob's bytes, or empty when the file couldn't be read, which makes the test that uses it fail.
[[nodiscard]] std::string fixture_signature() { return read_file(RASP_TEST_SIGNATURE_PATH).value_or(std::string()); }

TEST(Identity, observeExecutableSignature_whenSignedAdHocByCodesign_reportsNoTeamIdAndTheCdhash) {
  const std::string signature = fixture_signature();
  ASSERT_EQ(signature.size(), 548U);

  EXPECT_EQ(observe_file(signed_mach_o(signature)), signature_values("", std::string(kFixtureCdhash)));
}

TEST(Identity, observeExecutableSignature_whenTheSignatureHasPaddingAfterTheSuperBlob_ignoresIt) {
  const std::string signature = fixture_signature() + std::string(4096, '\0');

  EXPECT_EQ(observe_file(signed_mach_o(signature)), signature_values("", std::string(kFixtureCdhash)));
}

TEST(Identity, observeExecutableSignature_whenTheCodeDirectoryHasATeamId_reportsIt) {
  const std::string signature =
      super_blob({{.slot = kCodeDirectorySlot, .blob = code_directory(kSha256, kTeamId, kExecSegmentVersion)}});

  EXPECT_EQ(observe_file(signed_mach_o(signature)), signature_values(std::string(kTeamId), std::string(kTeamCdhash)));
}

TEST(Identity, observeExecutableSignature_whenTheVersionPredatesTheTeamId_reportsAnEmptyTeamId) {
  const std::string signature =
      super_blob({{.slot = kCodeDirectorySlot, .blob = code_directory(kSha256, "", kScatterVersion)}});

  EXPECT_EQ(observe_file(signed_mach_o(signature)), signature_values("", "e7fbf5dc34204a4c4792fd468068ae1b92ff46f7"));
}

TEST(Identity, observeExecutableSignature_whenTheTeamIdIsAtTheLimit_reportsIt) {
  const std::string team_id(64, 'A');
  const std::string signature =
      super_blob({{.slot = kCodeDirectorySlot, .blob = code_directory(kSha256, team_id, kExecSegmentVersion)}});

  EXPECT_EQ(observe_file(signed_mach_o(signature)),
            signature_values(team_id, "60f2b4c74eeb273eb46e3fdb4b187512d914af20"));
}

TEST(Identity, observeExecutableSignature_whenAnAlternateCodeDirectoryIsSha256_usesIt) {
  const std::string signature = super_blob({
      {.slot = kCodeDirectorySlot, .blob = code_directory(kSha1, kOtherTeamId, kExecSegmentVersion)},
      {.slot = kRequirementsSlot, .blob = std::string("\xfa\xde\x0c\x01\x00\x00\x00\x0c\x00\x00\x00\x00", 12)},
      {.slot = kFirstAlternateSlot, .blob = code_directory(kSha256, kTeamId, kExecSegmentVersion)},
  });

  EXPECT_EQ(observe_file(signed_mach_o(signature)), signature_values(std::string(kTeamId), std::string(kTeamCdhash)));
}

TEST(Identity, observeExecutableSignature_whenTheSha256CodeDirectoryComesFirst_stillUsesIt) {
  const std::string signature = super_blob({
      {.slot = kCodeDirectorySlot, .blob = code_directory(kSha256, kTeamId, kExecSegmentVersion)},
      {.slot = kFirstAlternateSlot, .blob = code_directory(kSha1, kOtherTeamId, kExecSegmentVersion)},
  });

  EXPECT_EQ(observe_file(signed_mach_o(signature)), signature_values(std::string(kTeamId), std::string(kTeamCdhash)));
}

TEST(Identity, observeExecutableSignature_whenTheStrongestCodeDirectoryIsSha384_reportsItsTeamIdAndNoCdhash) {
  const std::string signature = super_blob({
      {.slot = kCodeDirectorySlot, .blob = code_directory(kSha256, kTeamId, kExecSegmentVersion)},
      {.slot = kFirstAlternateSlot + 1, .blob = code_directory(kSha384, kOtherTeamId, kExecSegmentVersion)},
  });

  EXPECT_EQ(observe_file(signed_mach_o(signature)), team_id_only(std::string(kOtherTeamId)));
}

TEST(Identity, observeExecutableSignature_whenTheOnlyCodeDirectoryIsSha1_reportsItsTeamIdAndNoCdhash) {
  const std::string signature =
      super_blob({{.slot = kCodeDirectorySlot, .blob = code_directory(kSha1, kOtherTeamId, kExecSegmentVersion)}});

  EXPECT_EQ(observe_file(signed_mach_o(signature)), team_id_only(std::string(kOtherTeamId)));
}

TEST(Identity, observeExecutableSignature_whenACodeDirectoryIsPastTheAlternateSlots_ignoresIt) {
  const std::string signature = super_blob({
      {.slot = kCodeDirectorySlot, .blob = code_directory(kSha1, kOtherTeamId, kExecSegmentVersion)},
      {.slot = kFirstAlternateSlot + 5, .blob = code_directory(kSha256, kTeamId, kExecSegmentVersion)},
  });

  EXPECT_EQ(observe_file(signed_mach_o(signature)), team_id_only(std::string(kOtherTeamId)));
}

TEST(Identity, observeExecutableSignature_whenTwoCodeDirectoriesHaveTheSameHashType_reportsAnError) {
  const std::string signature = super_blob({
      {.slot = kCodeDirectorySlot, .blob = code_directory(kSha256, kTeamId, kExecSegmentVersion)},
      {.slot = kFirstAlternateSlot, .blob = code_directory(kSha256, kOtherTeamId, kExecSegmentVersion)},
  });

  EXPECT_EQ(observe_file(signed_mach_o(signature)), unreadable_signature());
}

TEST(Identity, observeExecutableSignature_whenTheHashTypeIsUnknown_reportsAnError) {
  const std::string signature =
      super_blob({{.slot = kCodeDirectorySlot, .blob = code_directory(5, kTeamId, kExecSegmentVersion)}});

  EXPECT_EQ(observe_file(signed_mach_o(signature)), unreadable_signature());
}

TEST(Identity, observeExecutableSignature_whenThereIsNoCodeDirectory_reportsAnError) {
  const std::string signature = super_blob(
      {{.slot = kRequirementsSlot, .blob = std::string("\xfa\xde\x0c\x01\x00\x00\x00\x0c\x00\x00\x00\x00", 12)}});

  EXPECT_EQ(observe_file(signed_mach_o(signature)), unreadable_signature());
}

TEST(Identity, observeExecutableSignature_whenTheSuperBlobMagicIsWrong_reportsAnError) {
  std::string signature = fixture_signature();
  ASSERT_EQ(signature.size(), 548U);
  set_big_endian(signature, 0, 0xFADE0CC1);

  EXPECT_EQ(observe_file(signed_mach_o(signature)), unreadable_signature());
}

TEST(Identity, observeExecutableSignature_whenTheCodeDirectoryMagicIsWrong_reportsAnError) {
  std::string directory = code_directory(kSha256, kTeamId, kExecSegmentVersion);
  set_big_endian(directory, 0, 0xFADE0C01);
  const std::string signature = super_blob({{.slot = kCodeDirectorySlot, .blob = directory}});

  EXPECT_EQ(observe_file(signed_mach_o(signature)), unreadable_signature());
}

TEST(Identity, observeExecutableSignature_whenTheSignatureIsTruncated_reportsAnError) {
  const std::string signature = fixture_signature();
  ASSERT_EQ(signature.size(), 548U);

  EXPECT_EQ(observe_file(signed_mach_o(signature.substr(0, 300))), unreadable_signature());
}

TEST(Identity, observeExecutableSignature_whenABlobOffsetIsPastTheEnd_reportsAnError) {
  std::string signature = fixture_signature();
  ASSERT_EQ(signature.size(), 548U);
  set_big_endian(signature, 16, 549);

  EXPECT_EQ(observe_file(signed_mach_o(signature)), unreadable_signature());
}

TEST(Identity, observeExecutableSignature_whenABlobLengthIsPastTheEnd_reportsAnError) {
  std::string signature = fixture_signature();
  ASSERT_EQ(signature.size(), 548U);
  set_big_endian(signature, 36 + 4, 0xFFFFFFF0);

  EXPECT_EQ(observe_file(signed_mach_o(signature)), unreadable_signature());
}

TEST(Identity, observeExecutableSignature_whenTheBlobCountWouldOverflow_reportsAnError) {
  std::string signature = fixture_signature();
  ASSERT_EQ(signature.size(), 548U);
  set_big_endian(signature, 8, 0x20000001);

  EXPECT_EQ(observe_file(signed_mach_o(signature)), unreadable_signature());
}

TEST(Identity, observeExecutableSignature_whenTheCodeDirectoryIsShorterThanItsHeader_reportsAnError) {
  const std::string directory = code_directory(kSha256, kTeamId, kExecSegmentVersion);
  std::string short_directory = directory.substr(0, 40);
  set_big_endian(short_directory, 4, 40);
  const std::string signature = super_blob({{.slot = kCodeDirectorySlot, .blob = short_directory}});

  EXPECT_EQ(observe_file(signed_mach_o(signature)), unreadable_signature());
}

TEST(Identity, observeExecutableSignature_whenTheTeamOffsetIsPastTheEnd_reportsAnError) {
  std::string directory = code_directory(kSha256, kTeamId, kExecSegmentVersion);
  set_big_endian(directory, 48, static_cast<std::uint32_t>(directory.size() + 1));
  const std::string signature = super_blob({{.slot = kCodeDirectorySlot, .blob = directory}});

  EXPECT_EQ(observe_file(signed_mach_o(signature)), unreadable_signature());
}

TEST(Identity, observeExecutableSignature_whenTheTeamIdHasNoTerminator_reportsAnError) {
  std::string directory = code_directory(kSha256, kTeamId, kExecSegmentVersion);
  directory.pop_back();
  set_big_endian(directory, 4, static_cast<std::uint32_t>(directory.size()));
  const std::string signature = super_blob({{.slot = kCodeDirectorySlot, .blob = directory}});

  EXPECT_EQ(observe_file(signed_mach_o(signature)), unreadable_signature());
}

TEST(Identity, observeExecutableSignature_whenTheTeamIdIsTooLong_reportsAnError) {
  const std::string signature = super_blob(
      {{.slot = kCodeDirectorySlot, .blob = code_directory(kSha256, std::string(65, 'A'), kExecSegmentVersion)}});

  EXPECT_EQ(observe_file(signed_mach_o(signature)), unreadable_signature());
}

TEST(Identity, observeExecutableSignature_whenTheFileIsUniversal_reportsAnError) {
  std::string file = signed_mach_o(fixture_signature());
  set_big_endian(file, 0, 0xCAFEBABE);

  EXPECT_EQ(observe_file(file), unreadable_signature());
}

TEST(Identity, observeExecutableSignature_whenThereIsNoCodeSignatureCommand_reportsAnError) {
  std::string uuid_command;
  append_little_endian(uuid_command, 0x1B);
  append_little_endian(uuid_command, 24);
  uuid_command.append(16, '\x11');

  EXPECT_EQ(observe_file(mach_o(uuid_command, 1, fixture_signature())), unreadable_signature());
}

TEST(Identity, observeExecutableSignature_whenThereAreTwoCodeSignatureCommands_reportsAnError) {
  const std::string signature = fixture_signature();
  const std::string command = signature_command(64, static_cast<std::uint32_t>(signature.size()));

  EXPECT_EQ(observe_file(mach_o(command + command, 2, signature)), unreadable_signature());
}

TEST(Identity, observeExecutableSignature_whenTheSignatureIsPastTheEndOfTheFile_reportsAnError) {
  const std::string signature = fixture_signature();
  const std::string command = signature_command(48, static_cast<std::uint32_t>(signature.size() + 1));

  EXPECT_EQ(observe_file(mach_o(command, 1, signature)), unreadable_signature());
}

TEST(Identity, observeExecutableSignature_whenTheSignatureIsTooLarge_reportsAnError) {
  const std::string command = signature_command(48, (std::uint32_t{16} << 20U) + 1);

  EXPECT_EQ(observe_file(mach_o(command, 1, fixture_signature())), unreadable_signature());
}

TEST(Identity, observeExecutableSignature_whenALoadCommandIsPastTheEnd_reportsAnError) {
  std::string command = signature_command(48, 548);
  command[4] = '\x20';

  EXPECT_EQ(observe_file(mach_o(command, 1, fixture_signature())), unreadable_signature());
}

TEST(Identity, observeExecutableSignature_whenALoadCommandIsEmpty_reportsAnError) {
  std::string command = signature_command(48, 548);
  command[4] = '\0';

  EXPECT_EQ(observe_file(mach_o(command, 1, fixture_signature())), unreadable_signature());
}

TEST(Identity, observeExecutableSignature_whenTheLoadCommandsArePastTheEndOfTheFile_reportsAnError) {
  std::string file = signed_mach_o(fixture_signature());
  file[20] = '\x00';
  file[21] = '\x10';

  EXPECT_EQ(observe_file(file), unreadable_signature());
}

TEST(Identity, observeExecutableSignature_whenTheLoadCommandsAreTooLarge_reportsAnError) {
  std::string file = signed_mach_o(fixture_signature());
  file[20] = '\x01';
  file[21] = '\x00';
  file[22] = '\x10';

  EXPECT_EQ(observe_file(file), unreadable_signature());
}

TEST(Identity, observeExecutableSignature_whenTheFileIsMissing_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());

  EXPECT_EQ(observe_executable_signature(directory.path() + "/App"), unreadable_signature());
}

TEST(Identity, observeExecutableSignature_whenThePathIsAFifo_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string path = directory.path() + "/App";
  ASSERT_TRUE(make_fifo(path));

  EXPECT_EQ(observe_executable_signature(path), unreadable_signature());
}

#ifdef __APPLE__
/// The largest Info.plist file the probe reads, in bytes.
constexpr std::size_t kMaxInfoPlistSize = std::size_t{1} << 20U;

/// A binary property list whose `CFBundleIdentifier` key holds `co.ostorlab.app`, as Xcode writes an app's Info.plist.
constexpr std::string_view kBinaryPlist{
    "\x62\x70\x6c\x69\x73\x74\x30\x30\xd1\x01\x02\x5f\x10\x12\x43\x46\x42\x75\x6e\x64\x6c\x65\x49\x64\x65\x6e\x74\x69"
    "\x66\x69\x65\x72\x5f\x10\x0f\x63\x6f\x2e\x6f\x73\x74\x6f\x72\x6c\x61\x62\x2e\x61\x70\x70\x08\x0b\x20\x00\x00\x00"
    "\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x32",
    85};

/// Returns an XML property list whose top-level dictionary holds `entries`.
///
/// @param entries The keys and values of the dictionary, written as XML property list elements.
/// @return The property list's text.
[[nodiscard]] std::string xml_plist(std::string_view entries) {
  std::string plist =
      R"(<?xml version="1.0" encoding="UTF-8"?>)"
      R"(<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">)"
      R"(<plist version="1.0"><dict>)";
  plist += entries;
  plist += "</dict></plist>";
  return plist;
}

/// Returns the id.bundle_id observation through Info.plist that reports `identifier`.
///
/// @param identifier The bundle identifier reported.
/// @return The observation, with status kOk.
[[nodiscard]] Observation plist_identifier(std::string identifier) {
  return {.signal = "id.bundle_id", .source = "Info.plist", .status = Status::kOk, .value = std::move(identifier)};
}

/// Returns the id.bundle_id observation through Info.plist that failed.
///
/// @return The observation, with status kError and no value.
[[nodiscard]] Observation unreadable_plist() {
  return {.signal = "id.bundle_id", .source = "Info.plist", .status = Status::kError, .value = {}};
}

/// Writes `content` to an Info.plist file in `directory` and returns its path.
///
/// @param directory The directory to write the file in.
/// @param content What the file holds.
/// @return The file's path, or empty when it couldn't be written.
[[nodiscard]] std::string write_plist(const TemporaryDirectory& directory, std::string_view content) {
  const std::string path = directory.path() + "/Info.plist";
  return write_file(path, content) ? path : std::string();
}

TEST(Identity, observeInfoPlist_whenTheFileIsAnXmlPlist_reportsTheIdentifier) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string path =
      write_plist(directory, xml_plist("<key>CFBundleName</key><string>App</string>"
                                       "<key>CFBundleIdentifier</key><string>co.ostorlab.app</string>"));
  ASSERT_FALSE(path.empty());

  EXPECT_EQ(observe_info_plist(path), plist_identifier("co.ostorlab.app"));
}

TEST(Identity, observeInfoPlist_whenTheFileIsABinaryPlist_reportsTheIdentifier) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string path = write_plist(directory, kBinaryPlist);
  ASSERT_FALSE(path.empty());

  EXPECT_EQ(observe_info_plist(path), plist_identifier("co.ostorlab.app"));
}

TEST(Identity, observeInfoPlist_whenTheIdentifierIsNotAscii_reportsItAsUtf8) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string path =
      write_plist(directory, xml_plist("<key>CFBundleIdentifier</key><string>co.ostorlab.caf\xc3\xa9</string>"));
  ASSERT_FALSE(path.empty());

  EXPECT_EQ(observe_info_plist(path), plist_identifier("co.ostorlab.caf\xc3\xa9"));
}

TEST(Identity, observeInfoPlist_whenTheIdentifierIsAtTheLimit_reportsIt) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string identifier(1024, 'a');
  const std::string path =
      write_plist(directory, xml_plist("<key>CFBundleIdentifier</key><string>" + identifier + "</string>"));
  ASSERT_FALSE(path.empty());

  EXPECT_EQ(observe_info_plist(path), plist_identifier(identifier));
}

TEST(Identity, observeInfoPlist_whenTheIdentifierIsTooLong_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string path =
      write_plist(directory, xml_plist("<key>CFBundleIdentifier</key><string>" + std::string(1025, 'a') + "</string>"));
  ASSERT_FALSE(path.empty());

  EXPECT_EQ(observe_info_plist(path), unreadable_plist());
}

TEST(Identity, observeInfoPlist_whenTheIdentifierIsEmpty_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string path = write_plist(directory, xml_plist("<key>CFBundleIdentifier</key><string></string>"));
  ASSERT_FALSE(path.empty());

  EXPECT_EQ(observe_info_plist(path), unreadable_plist());
}

TEST(Identity, observeInfoPlist_whenTheIdentifierIsNotAString_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string path = write_plist(directory, xml_plist("<key>CFBundleIdentifier</key><integer>7</integer>"));
  ASSERT_FALSE(path.empty());

  EXPECT_EQ(observe_info_plist(path), unreadable_plist());
}

TEST(Identity, observeInfoPlist_whenThereIsNoIdentifier_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string path = write_plist(directory, xml_plist("<key>CFBundleName</key><string>App</string>"));
  ASSERT_FALSE(path.empty());

  EXPECT_EQ(observe_info_plist(path), unreadable_plist());
}

TEST(Identity, observeInfoPlist_whenThePlistIsNotADictionary_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string path =
      write_plist(directory, R"(<?xml version="1.0" encoding="UTF-8"?>)"
                             R"(<plist version="1.0"><array><string>co.ostorlab.app</string></array></plist>)");
  ASSERT_FALSE(path.empty());

  EXPECT_EQ(observe_info_plist(path), unreadable_plist());
}

TEST(Identity, observeInfoPlist_whenTheFileIsNotAPlist_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string path = write_plist(directory, "CFBundleIdentifier = co.ostorlab.app <");
  ASSERT_FALSE(path.empty());

  EXPECT_EQ(observe_info_plist(path), unreadable_plist());
}

TEST(Identity, observeInfoPlist_whenTheFileIsTooLarge_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  std::string content = xml_plist("<key>CFBundleIdentifier</key><string>co.ostorlab.app</string>");
  content.append(kMaxInfoPlistSize + 1 - content.size(), ' ');
  const std::string path = write_plist(directory, content);
  ASSERT_FALSE(path.empty());

  EXPECT_EQ(observe_info_plist(path), unreadable_plist());
}

TEST(Identity, observeInfoPlist_whenTheFileIsMissing_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());

  EXPECT_EQ(observe_info_plist(directory.path() + "/Info.plist"), unreadable_plist());
}

TEST(Identity, observeInfoPlist_whenThePathIsAFifo_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string path = directory.path() + "/Info.plist";
  ASSERT_TRUE(make_fifo(path));

  EXPECT_EQ(observe_info_plist(path), unreadable_plist());
}

TEST(Identity, observeBundleIdentifier_whenRunUnhooked_agreesWithTheInfoPlist) {
  const Observation bundle = observe_bundle_identifier();
  const Observation plist = observe_main_info_plist();

  EXPECT_EQ(bundle.signal, "id.bundle_id");
  EXPECT_EQ(bundle.source, "CFBundle");
  EXPECT_EQ(plist.signal, "id.bundle_id");
  EXPECT_EQ(plist.source, "Info.plist");
  EXPECT_EQ(bundle.status, plist.status);
  EXPECT_EQ(bundle.value, plist.value);
}
#else
TEST(Identity, observeBundleIdentifier_whenTheSystemHasNoCoreFoundation_reportsUnsupported) {
  EXPECT_EQ(observe_bundle_identifier(),
            (Observation{.signal = "id.bundle_id", .source = "CFBundle", .status = Status::kUnsupported, .value = {}}));
}

TEST(Identity, observeInfoPlist_whenTheSystemHasNoCoreFoundation_reportsUnsupported) {
  EXPECT_EQ(
      observe_info_plist("/Info.plist"),
      (Observation{.signal = "id.bundle_id", .source = "Info.plist", .status = Status::kUnsupported, .value = {}}));
}

TEST(Identity, observeMainInfoPlist_whenTheSystemHasNoCoreFoundation_reportsUnsupported) {
  EXPECT_EQ(
      observe_main_info_plist(),
      (Observation{.signal = "id.bundle_id", .source = "Info.plist", .status = Status::kUnsupported, .value = {}}));
}

TEST(Identity, observeMainExecutableSignature_whenTheSystemHasNoDyld_reportsUnsupported) {
  EXPECT_EQ(observe_main_executable_signature(),
            (std::vector<Observation>{
                {.signal = "id.team_id", .source = "code_signature", .status = Status::kUnsupported, .value = {}},
                {.signal = "id.cdhash", .source = "code_signature", .status = Status::kUnsupported, .value = {}},
            }));
}
#endif

TEST(Identity, identity_whenOffAPhysicalDevice_reportsEveryCheckAsUnsupported) {
  EXPECT_EQ(identity(),
            (std::vector<Observation>{
                {.signal = "id.bundle_id", .source = "CFBundle", .status = Status::kUnsupported, .value = {}},
                {.signal = "id.bundle_id", .source = "Info.plist", .status = Status::kUnsupported, .value = {}},
                {.signal = "id.team_id", .source = "code_signature", .status = Status::kUnsupported, .value = {}},
                {.signal = "id.cdhash", .source = "code_signature", .status = Status::kUnsupported, .value = {}},
            }));
}

}  // namespace
}  // namespace rasp::ios::checks
