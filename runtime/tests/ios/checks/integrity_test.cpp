/// Tests for the iOS code-integrity check: the layout of the `__TEXT,__text` section and the pair of file and memory
/// hashes, against the arm64 executables in `packer/tests/rasp_packer/ios/data/` and against copies of them changed
/// here.

#include "checks/integrity.h"

#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
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

/// The SHA-256 of the fixtures' `__text` section, computed with Python's hashlib from the section's bytes and with
/// `llvm-objcopy --dump-section=__TEXT,__text` and sha256sum, independently of the runtime.
constexpr std::string_view kFixtureTextHash = "2f6110664dbd16b514a0c2c7c8326932a36e85d2f15b91e57ca76efd2c7a625a";
/// The SHA-256 of the fixtures' `__text` section with its first byte inverted, computed with Python's hashlib.
constexpr std::string_view kPatchedTextHash = "0890f0b49f4c10cbd80bdf2397e3e2fe104e502d6771a6cc903c17b6205d798d";

/// The offset of the header's `ncmds`.
constexpr std::size_t kCommandCountOffset = 16;
/// The offset of the header's `sizeofcmds`.
constexpr std::size_t kCommandsSizeOffset = 20;
/// The offset of the `__TEXT` segment load command in the fixtures, the second load command.
constexpr std::size_t kTextSegment = 104;
/// The offset of the `__LINKEDIT` segment load command in the unsigned fixture, the third load command.
constexpr std::size_t kLinkeditSegment = 336;
/// The offset of the `__text` section in the fixtures, the first section of the `__TEXT` segment.
constexpr std::size_t kTextSection = kTextSegment + 72;
/// The offset of the `__unwind_info` section in the fixtures, the second section of the `__TEXT` segment.
constexpr std::size_t kUnwindSection = kTextSection + 80;
/// The offset of the `LC_ENCRYPTION_INFO_64` load command in the unsigned fixture.
constexpr std::size_t kEncryptionInfo = 672;
/// The offset of the `cmdsize` of the last load command of the unsigned fixture, its `LC_DATA_IN_CODE`.
constexpr std::size_t kLastCommandSize = 768 + 4;
/// The `__TEXT` segment's `vmaddr` in the fixtures.
constexpr std::uint64_t kSegmentAddress = 0x100000000;
/// The offset of the `__text` section's bytes in the fixtures' file and in their `__TEXT` segment.
constexpr std::uint64_t kTextOffset = 0x4000;

/// Reads the executable at `path` in `packer/tests/rasp_packer/ios/data/`.
///
/// @param path The fixture's path.
/// @return The file's bytes, or empty when it couldn't be read, which makes the test that uses it fail.
[[nodiscard]] std::vector<std::uint8_t> fixture(const std::string& path) {
  const std::string content = read_file(path).value_or(std::string());
  return {content.begin(), content.end()};
}

/// Returns the bytes of the unsigned fixture, `arm64_app`.
///
/// @return The file's bytes, or empty when it couldn't be read.
[[nodiscard]] std::vector<std::uint8_t> unsigned_fixture() { return fixture(RASP_TEST_EXECUTABLE_PATH); }

/// A little-endian field to write into an image: a value and how many bytes wide it is.
struct Field {
  /// The value to write.
  std::uint64_t value = 0;
  /// The width in bytes, 4 or 8.
  std::size_t width = 0;
};

/// Returns the 32-bit field that holds `value`.
///
/// @param value The value.
/// @return The field, 4 bytes wide.
[[nodiscard]] Field u32(std::uint32_t value) { return {.value = value, .width = 4}; }

/// Returns the 64-bit field that holds `value`.
///
/// @param value The value.
/// @return The field, 8 bytes wide.
[[nodiscard]] Field u64(std::uint64_t value) { return {.value = value, .width = 8}; }

/// Writes `field` into `bytes` at `offset` as a little-endian number, replacing what is there.
///
/// @param bytes The bytes to change, which hold at least `offset + field.width` bytes.
/// @param offset Where the number starts.
/// @param field The number and its width.
void set_little_endian(std::vector<std::uint8_t>& bytes, std::size_t offset, Field field) {
  for (std::size_t index = 0; index < field.width; ++index) {
    bytes[offset + index] = static_cast<std::uint8_t>((field.value >> (8U * index)) & 0xFFU);
  }
}

/// Writes `name` into the 16-byte name field of `bytes` at `offset`, padded with NUL bytes.
///
/// @param bytes The bytes to change, which hold at least `offset + 16` bytes.
/// @param offset Where the name field starts.
/// @param name The name, at most 16 bytes.
void set_name(std::vector<std::uint8_t>& bytes, std::size_t offset, std::string_view name) {
  for (std::size_t index = 0; index < 16; ++index) {
    bytes[offset + index] = index < name.size() ? static_cast<std::uint8_t>(name[index]) : 0;
  }
}

/// Writes `content` to a file in `directory` and returns its path.
///
/// @param directory The directory to write the file in.
/// @param content What the file holds.
/// @return The file's path, or empty when the directory couldn't be created or the file couldn't be written.
[[nodiscard]] std::string write_image(const TemporaryDirectory& directory, const std::vector<std::uint8_t>& content) {
  if (directory.path().empty()) {
    return {};
  }
  const std::string path = directory.path() + "/RaspRuntime";
  const std::string bytes(content.begin(), content.end());
  return write_file(path, bytes) ? path : std::string();
}

/// Writes `file` to a file and returns what observe_text_hashes reports for it with the image loaded at `memory`.
///
/// @param file What the file holds.
/// @param memory The image in memory, or null.
/// @return The observations, or none when the file couldn't be written, which makes the test fail.
[[nodiscard]] std::vector<Observation> observe(const std::vector<std::uint8_t>& file, const std::uint8_t* memory) {
  const TemporaryDirectory directory;
  const std::string path = write_image(directory, file);
  if (path.empty()) {
    return {};
  }
  return observe_text_hashes(path, memory);
}

/// Returns the integ.text_sha256 observation through `source` that reports `hash`.
///
/// @param source The source of the observation.
/// @param hash The hash reported.
/// @return The observation, with status kOk.
[[nodiscard]] Observation hashed(std::string source, std::string_view hash) {
  return {
      .signal = "integ.text_sha256",
      .source = std::move(source),
      .status = Status::kOk,
      .value = std::string(hash),
  };
}

/// Returns the integ.text_sha256 observation through `source` with the status `status` and no value.
///
/// @param source The source of the observation.
/// @param status The status of the observation.
/// @return The observation.
[[nodiscard]] Observation without_value(std::string source, Status status) {
  return {.signal = "integ.text_sha256", .source = std::move(source), .status = status, .value = {}};
}

/// Returns the two integ.text_sha256 observations of an image whose file the check couldn't read.
///
/// @return The file and memory observations, with status kError and no value.
[[nodiscard]] std::vector<Observation> unreadable() {
  return {without_value("file", Status::kError), without_value("memory", Status::kError)};
}

TEST(Integrity, findTextLayout_whenGivenTheUnsignedFixture_reportsItsTextSection) {
  const std::optional<TextLayout> layout = find_text_layout(unsigned_fixture());

  ASSERT_TRUE(layout.has_value());
  EXPECT_EQ(*layout, (TextLayout{
                         .command_count = 16,
                         .commands_size = 752,
                         .segment_address = kSegmentAddress,
                         .segment_size = 0x8000,
                         .segment_file_size = 0x8000,
                         .section_address = kSegmentAddress + kTextOffset,
                         .section_offset = kTextOffset,
                         .section_size = 8,
                         .encrypted = false,
                     }));
}

TEST(Integrity, findTextLayout_whenGivenTheSignedFixture_reportsTheSameSection) {
  const std::optional<TextLayout> layout = find_text_layout(fixture(RASP_TEST_SIGNED_EXECUTABLE_PATH));

  ASSERT_TRUE(layout.has_value());
  EXPECT_EQ(layout->command_count, 17U);
  EXPECT_EQ(layout->commands_size, 768U);
  EXPECT_EQ(layout->section_address, kSegmentAddress + kTextOffset);
  EXPECT_EQ(layout->section_offset, kTextOffset);
  EXPECT_EQ(layout->section_size, 8U);
}

TEST(Integrity, findTextLayout_whenGivenOnlyTheHeaderAndLoadCommands_reportsTheSection) {
  const std::vector<std::uint8_t> image = unsigned_fixture();
  const std::vector<std::uint8_t> header_and_commands(image.begin(), image.begin() + 32 + 752);

  EXPECT_EQ(find_text_layout(header_and_commands), find_text_layout(image));
}

TEST(Integrity, findTextLayout_whenTheImageIsEncrypted_reportsItEncrypted) {
  std::vector<std::uint8_t> image = unsigned_fixture();
  set_little_endian(image, kEncryptionInfo + 16, u32(1));

  const std::optional<TextLayout> layout = find_text_layout(image);

  ASSERT_TRUE(layout.has_value());
  EXPECT_TRUE(layout->encrypted);
}

TEST(Integrity, findTextLayout_whenTheLoadCommandsAreTruncated_reportsNothing) {
  const std::vector<std::uint8_t> image = unsigned_fixture();
  const std::vector<std::uint8_t> truncated(image.begin(), image.begin() + 32 + 751);

  EXPECT_EQ(find_text_layout(truncated), std::nullopt);
}

TEST(Integrity, findTextLayout_whenTheHeaderIsTruncated_reportsNothing) {
  const std::vector<std::uint8_t> image = unsigned_fixture();
  const std::vector<std::uint8_t> truncated(image.begin(), image.begin() + 31);

  EXPECT_EQ(find_text_layout(truncated), std::nullopt);
}

TEST(Integrity, findTextLayout_whenTheFileIsUniversal_reportsNothing) {
  std::vector<std::uint8_t> image = unsigned_fixture();
  set_little_endian(image, 0, u32(0xBEBAFECA));

  EXPECT_EQ(find_text_layout(image), std::nullopt);
}

TEST(Integrity, findTextLayout_whenTheLoadCommandsAreTooLarge_reportsNothing) {
  std::vector<std::uint8_t> image = unsigned_fixture();
  set_little_endian(image, kCommandsSizeOffset, u32((std::uint32_t{1} << 20U) + 1U));

  EXPECT_EQ(find_text_layout(image), std::nullopt);
}

TEST(Integrity, findTextLayout_whenALoadCommandIsPastTheEnd_reportsNothing) {
  std::vector<std::uint8_t> image = unsigned_fixture();
  set_little_endian(image, kLastCommandSize, u32(32));

  EXPECT_EQ(find_text_layout(image), std::nullopt);
}

TEST(Integrity, findTextLayout_whenALoadCommandIsEmpty_reportsNothing) {
  std::vector<std::uint8_t> image = unsigned_fixture();
  set_little_endian(image, kLinkeditSegment + 4, u32(0));

  EXPECT_EQ(find_text_layout(image), std::nullopt);
}

TEST(Integrity, findTextLayout_whenThereIsNoTextSegment_reportsNothing) {
  std::vector<std::uint8_t> image = unsigned_fixture();
  set_name(image, kTextSegment + 8, "__TEXU");

  EXPECT_EQ(find_text_layout(image), std::nullopt);
}

TEST(Integrity, findTextLayout_whenThereAreTwoTextSegments_reportsNothing) {
  std::vector<std::uint8_t> image = unsigned_fixture();
  set_name(image, kLinkeditSegment + 8, "__TEXT");

  EXPECT_EQ(find_text_layout(image), std::nullopt);
}

TEST(Integrity, findTextLayout_whenThereIsNoTextSection_reportsNothing) {
  std::vector<std::uint8_t> image = unsigned_fixture();
  set_name(image, kTextSection, "__textx");

  EXPECT_EQ(find_text_layout(image), std::nullopt);
}

TEST(Integrity, findTextLayout_whenTheTextSectionNamesAnotherSegment_reportsNothing) {
  std::vector<std::uint8_t> image = unsigned_fixture();
  set_name(image, kTextSection + 16, "__DATA");

  EXPECT_EQ(find_text_layout(image), std::nullopt);
}

TEST(Integrity, findTextLayout_whenThereAreTwoTextSections_reportsNothing) {
  std::vector<std::uint8_t> image = unsigned_fixture();
  set_name(image, kUnwindSection, "__text");

  EXPECT_EQ(find_text_layout(image), std::nullopt);
}

TEST(Integrity, findTextLayout_whenTheSectionsOverflowTheLoadCommand_reportsNothing) {
  std::vector<std::uint8_t> image = unsigned_fixture();
  set_little_endian(image, kTextSegment + 64, u32(3));

  EXPECT_EQ(find_text_layout(image), std::nullopt);
}

TEST(Integrity, findTextLayout_whenTheSegmentDoesNotStartTheFile_reportsNothing) {
  std::vector<std::uint8_t> image = unsigned_fixture();
  set_little_endian(image, kTextSegment + 40, u64(0x10));

  EXPECT_EQ(find_text_layout(image), std::nullopt);
}

TEST(Integrity, findTextLayout_whenTheLoadCommandsDoNotFitTheSegment_reportsNothing) {
  std::vector<std::uint8_t> image = unsigned_fixture();
  set_little_endian(image, kTextSegment + 32, u64(0x200));

  EXPECT_EQ(find_text_layout(image), std::nullopt);
}

TEST(Integrity, findTextLayout_whenTheSectionIsPastTheFilePartOfTheSegment_reportsNothing) {
  std::vector<std::uint8_t> image = unsigned_fixture();
  set_little_endian(image, kTextSegment + 48, u64(kTextOffset + 4));

  EXPECT_EQ(find_text_layout(image), std::nullopt);
}

TEST(Integrity, findTextLayout_whenTheSectionIsPastTheEndOfTheSegment_reportsNothing) {
  std::vector<std::uint8_t> image = unsigned_fixture();
  set_little_endian(image, kTextSection + 32, u64(kSegmentAddress + 0x7FFC));
  set_little_endian(image, kTextSection + 48, u32(0x7FFC));

  EXPECT_EQ(find_text_layout(image), std::nullopt);
}

TEST(Integrity, findTextLayout_whenTheSectionIsBeforeTheSegment_reportsNothing) {
  std::vector<std::uint8_t> image = unsigned_fixture();
  set_little_endian(image, kTextSection + 32, u64(kSegmentAddress - 8));

  EXPECT_EQ(find_text_layout(image), std::nullopt);
}

TEST(Integrity, findTextLayout_whenTheSectionSizeOverflows_reportsNothing) {
  std::vector<std::uint8_t> image = unsigned_fixture();
  set_little_endian(image, kTextSection + 40, u64(~std::uint64_t{0}));

  EXPECT_EQ(find_text_layout(image), std::nullopt);
}

TEST(Integrity, findTextLayout_whenTheSectionIsEmpty_reportsNothing) {
  std::vector<std::uint8_t> image = unsigned_fixture();
  set_little_endian(image, kTextSection + 40, u64(0));

  EXPECT_EQ(find_text_layout(image), std::nullopt);
}

TEST(Integrity, findTextLayout_whenTheSectionOffsetDoesNotMatchItsAddress_reportsNothing) {
  std::vector<std::uint8_t> image = unsigned_fixture();
  set_little_endian(image, kTextSection + 48, u32(static_cast<std::uint32_t>(kTextOffset) + 4U));

  EXPECT_EQ(find_text_layout(image), std::nullopt);
}

TEST(Integrity, observeTextHashes_whenMemoryMatchesTheFile_reportsTheFixtureHashTwice) {
  const std::vector<std::uint8_t> image = unsigned_fixture();

  EXPECT_EQ(observe(image, image.data()),
            (std::vector<Observation>{hashed("file", kFixtureTextHash), hashed("memory", kFixtureTextHash)}));
}

TEST(Integrity, observeTextHashes_whenTheImageIsSigned_reportsTheSameHash) {
  const std::vector<std::uint8_t> image = fixture(RASP_TEST_SIGNED_EXECUTABLE_PATH);

  EXPECT_EQ(observe(image, image.data()),
            (std::vector<Observation>{hashed("file", kFixtureTextHash), hashed("memory", kFixtureTextHash)}));
}

TEST(Integrity, observeTextHashes_whenMemoryWasPatched_reportsTheHashOfThePatchedCode) {
  const std::vector<std::uint8_t> file = unsigned_fixture();
  std::vector<std::uint8_t> memory = file;
  memory[kTextOffset] = static_cast<std::uint8_t>(memory[kTextOffset] ^ 0xFFU);

  EXPECT_EQ(observe(file, memory.data()),
            (std::vector<Observation>{hashed("file", kFixtureTextHash), hashed("memory", kPatchedTextHash)}));
}

TEST(Integrity, observeTextHashes_whenTheImageIsEncrypted_reportsTheFileAsUnsupported) {
  std::vector<std::uint8_t> image = unsigned_fixture();
  set_little_endian(image, kEncryptionInfo + 16, u32(1));

  EXPECT_EQ(observe(image, image.data()), (std::vector<Observation>{without_value("file", Status::kUnsupported),
                                                                    hashed("memory", kFixtureTextHash)}));
}

TEST(Integrity, observeTextHashes_whenTheHeaderInMemoryDiffers_reportsAMemoryError) {
  const std::vector<std::uint8_t> file = unsigned_fixture();
  std::vector<std::uint8_t> memory = file;
  set_little_endian(memory, kCommandCountOffset, u32(15));

  EXPECT_EQ(observe(file, memory.data()),
            (std::vector<Observation>{hashed("file", kFixtureTextHash), without_value("memory", Status::kError)}));
}

TEST(Integrity, observeTextHashes_whenTheLayoutInMemoryDiffers_reportsAMemoryError) {
  const std::vector<std::uint8_t> file = unsigned_fixture();
  std::vector<std::uint8_t> memory = file;
  set_little_endian(memory, kTextSection + 40, u64(16));

  EXPECT_EQ(observe(file, memory.data()),
            (std::vector<Observation>{hashed("file", kFixtureTextHash), without_value("memory", Status::kError)}));
}

TEST(Integrity, observeTextHashes_whenTheLoadCommandsInMemoryAreMalformed_reportsAMemoryError) {
  const std::vector<std::uint8_t> file = unsigned_fixture();
  std::vector<std::uint8_t> memory = file;
  set_little_endian(memory, kLastCommandSize, u32(32));

  EXPECT_EQ(observe(file, memory.data()),
            (std::vector<Observation>{hashed("file", kFixtureTextHash), without_value("memory", Status::kError)}));
}

TEST(Integrity, observeTextHashes_whenTheImageIsNull_reportsAMemoryError) {
  EXPECT_EQ(observe(unsigned_fixture(), nullptr),
            (std::vector<Observation>{hashed("file", kFixtureTextHash), without_value("memory", Status::kError)}));
}

TEST(Integrity, observeTextHashes_whenTheFileEndsBeforeTheSection_reportsAnError) {
  const std::vector<std::uint8_t> image = unsigned_fixture();
  const std::vector<std::uint8_t> truncated(image.begin(),
                                            image.begin() + static_cast<std::ptrdiff_t>(kTextOffset) + 4);

  EXPECT_EQ(observe(truncated, image.data()), unreadable());
}

TEST(Integrity, observeTextHashes_whenTheFileHasNoTextSection_reportsAnError) {
  std::vector<std::uint8_t> image = unsigned_fixture();
  set_name(image, kTextSection, "__textx");

  EXPECT_EQ(observe(image, image.data()), unreadable());
}

TEST(Integrity, observeTextHashes_whenTheFileIsMissing_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::vector<std::uint8_t> image = unsigned_fixture();

  EXPECT_EQ(observe_text_hashes(directory.path() + "/RaspRuntime", image.data()), unreadable());
}

TEST(Integrity, observeTextHashes_whenThePathIsAFifo_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string path = directory.path() + "/RaspRuntime";
  ASSERT_TRUE(make_fifo(path));
  const std::vector<std::uint8_t> image = unsigned_fixture();

  EXPECT_EQ(observe_text_hashes(path, image.data()), unreadable());
}

TEST(Integrity, integrity_whenOffAPhysicalDevice_reportsEveryCheckAsUnsupported) {
  EXPECT_EQ(integrity(), (std::vector<Observation>{without_value("file", Status::kUnsupported),
                                                   without_value("memory", Status::kUnsupported)}));
}

}  // namespace
}  // namespace rasp::ios::checks
