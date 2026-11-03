/// Tests for the shared ELF reader: the headers, the dynamic symbol lookup and the translation of a code address to its
/// file offset. They read two small libraries built with the Android NDK from data/prologue.c: an ELF64 arm64 one, and
/// an ELF32 armeabi-v7a one compiled as Thumb code.

#include "util/elf.h"

#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "support/files.h"

namespace rasp::android::util {
namespace {

/// The arm64 fixture library.
constexpr std::string_view kArm64Library = RASP_TEST_ELF_DATA "/libprologue-arm64.so";
/// The armeabi-v7a fixture library, built as Thumb code.
constexpr std::string_view kArmv7Library = RASP_TEST_ELF_DATA "/libprologue-armv7.so";

/// EM_AARCH64, the machine of an arm64 image.
constexpr std::uint16_t kMachineAarch64 = 183;
/// STT_GNU_IFUNC, the symbol type of an indirect function.
constexpr std::uint8_t kSymbolIndirectFunction = 10;

/// The bytes of the file at `path`, or an empty vector when it can't be read.
[[nodiscard]] std::vector<std::uint8_t> read_bytes(std::string_view path) {
  const std::optional<std::string> content = test_support::read_file(std::string(path));
  if (!content) {
    return {};
  }
  return {content->begin(), content->end()};
}

TEST(Elf, readElfHeaders_whenArm64Library_readsElf64AndItsMachine) {
  const std::vector<std::uint8_t> image = read_bytes(kArm64Library);

  const std::optional<ElfHeaders> headers = read_elf_headers(image);

  ASSERT_TRUE(headers.has_value());
  EXPECT_TRUE(headers->elf64);
  EXPECT_EQ(headers->machine, kMachineAarch64);
}

TEST(Elf, readElfHeaders_whenArmv7Library_readsElf32AndTheArmMachine) {
  const std::vector<std::uint8_t> image = read_bytes(kArmv7Library);

  const std::optional<ElfHeaders> headers = read_elf_headers(image);

  ASSERT_TRUE(headers.has_value());
  EXPECT_FALSE(headers->elf64);
  EXPECT_EQ(headers->machine, kMachineArm);
}

TEST(Elf, readElfHeaders_whenImageIsNotElf_reportsNothing) {
  std::vector<std::uint8_t> image = read_bytes(kArm64Library);
  ASSERT_FALSE(image.empty());
  image[1] = 'X';

  EXPECT_FALSE(read_elf_headers(image).has_value());
}

TEST(Elf, readElfHeaders_whenImageIsShorterThanItsHeader_reportsNothing) {
  std::vector<std::uint8_t> image = read_bytes(kArm64Library);
  image.resize(32);

  EXPECT_FALSE(read_elf_headers(image).has_value());
}

TEST(Elf, findSection_whenNamed_returnsTheSection) {
  const std::vector<std::uint8_t> image = read_bytes(kArm64Library);
  const std::optional<ElfHeaders> headers = read_elf_headers(image);
  ASSERT_TRUE(headers.has_value());

  const std::optional<ElfSection> text = find_section(image, *headers, ".text");

  ASSERT_TRUE(text.has_value());
  EXPECT_EQ(text->address, 0x43ACU);
  EXPECT_EQ(text->file_offset, 0x3ACU);
  EXPECT_EQ(text->size, 0x44U);
}

TEST(Elf, findDynamicSymbol_whenDefined_returnsItsAddressAndFunctionType) {
  const std::vector<std::uint8_t> image = read_bytes(kArm64Library);
  const std::optional<ElfHeaders> headers = read_elf_headers(image);
  ASSERT_TRUE(headers.has_value());

  const std::optional<ElfSymbol> symbol = find_dynamic_symbol(image, *headers, "rasp_fixture_second");

  ASSERT_TRUE(symbol.has_value());
  EXPECT_EQ(symbol->value, 0x43D0U);
  EXPECT_EQ(symbol->type, kSymbolFunction);
}

TEST(Elf, findDynamicSymbol_whenThumbFunction_keepsTheThumbBit) {
  const std::vector<std::uint8_t> image = read_bytes(kArmv7Library);
  const std::optional<ElfHeaders> headers = read_elf_headers(image);
  ASSERT_TRUE(headers.has_value());

  const std::optional<ElfSymbol> symbol = find_dynamic_symbol(image, *headers, "rasp_fixture_first");

  ASSERT_TRUE(symbol.has_value());
  EXPECT_EQ(symbol->value, 0x1225U);
  EXPECT_EQ(symbol->type, kSymbolFunction);
}

TEST(Elf, findDynamicSymbol_whenIndirectFunction_reportsItsType) {
  const std::vector<std::uint8_t> image = read_bytes(kArm64Library);
  const std::optional<ElfHeaders> headers = read_elf_headers(image);
  ASSERT_TRUE(headers.has_value());

  const std::optional<ElfSymbol> symbol = find_dynamic_symbol(image, *headers, "rasp_fixture_indirect");

  ASSERT_TRUE(symbol.has_value());
  EXPECT_EQ(symbol->type, kSymbolIndirectFunction);
}

TEST(Elf, findDynamicSymbol_whenImported_reportsNothing) {
  const std::vector<std::uint8_t> image = read_bytes(kArm64Library);
  const std::optional<ElfHeaders> headers = read_elf_headers(image);
  ASSERT_TRUE(headers.has_value());

  EXPECT_FALSE(find_dynamic_symbol(image, *headers, "getpid").has_value());
}

TEST(Elf, findDynamicSymbol_whenMissing_reportsNothing) {
  const std::vector<std::uint8_t> image = read_bytes(kArm64Library);
  const std::optional<ElfHeaders> headers = read_elf_headers(image);
  ASSERT_TRUE(headers.has_value());

  EXPECT_FALSE(find_dynamic_symbol(image, *headers, "rasp_fixture").has_value());
}

TEST(Elf, findDynamicSymbol_whenFileIsCutOff_reportsNothing) {
  std::vector<std::uint8_t> image = read_bytes(kArm64Library);
  const std::optional<ElfHeaders> headers = read_elf_headers(image);
  ASSERT_TRUE(headers.has_value());
  image.resize(0x220);

  EXPECT_FALSE(find_dynamic_symbol(image, *headers, "rasp_fixture_first").has_value());
}

TEST(Elf, findCode_whenInTheExecutableSegment_translatesTheAddressToItsFileOffset) {
  const std::vector<std::uint8_t> image = read_bytes(kArm64Library);
  const std::optional<ElfHeaders> headers = read_elf_headers(image);
  ASSERT_TRUE(headers.has_value());

  const std::optional<CodeLocation> code = find_code(image, *headers, {.address = 0x43D0, .length = 16});

  ASSERT_TRUE(code.has_value());
  EXPECT_EQ(code->file_offset, 0x3D0U);
  EXPECT_EQ(code->available, 0x50U);
}

TEST(Elf, findCode_whenElf32_translatesTheAddressToItsFileOffset) {
  const std::vector<std::uint8_t> image = read_bytes(kArmv7Library);
  const std::optional<ElfHeaders> headers = read_elf_headers(image);
  ASSERT_TRUE(headers.has_value());

  const std::optional<CodeLocation> code = find_code(image, *headers, {.address = 0x1224, .length = 16});

  ASSERT_TRUE(code.has_value());
  EXPECT_EQ(code->file_offset, 0x224U);
  EXPECT_EQ(code->available, 0x6CU);
}

TEST(Elf, findCode_whenRangeReachesPastTheSegmentsFilePart_reportsNothing) {
  const std::vector<std::uint8_t> image = read_bytes(kArm64Library);
  const std::optional<ElfHeaders> headers = read_elf_headers(image);
  ASSERT_TRUE(headers.has_value());

  EXPECT_FALSE(find_code(image, *headers, {.address = 0x43AC, .length = 0x75}).has_value());
}

TEST(Elf, findCode_whenInTheReadOnlyDataSegment_reportsNothing) {
  const std::vector<std::uint8_t> image = read_bytes(kArm64Library);
  const std::optional<ElfHeaders> headers = read_elf_headers(image);
  ASSERT_TRUE(headers.has_value());

  EXPECT_FALSE(find_code(image, *headers, {.address = 0x200, .length = 16}).has_value());
}

TEST(Elf, findCode_whenInTheWritableSegment_reportsNothing) {
  const std::vector<std::uint8_t> image = read_bytes(kArm64Library);
  const std::optional<ElfHeaders> headers = read_elf_headers(image);
  ASSERT_TRUE(headers.has_value());

  EXPECT_FALSE(find_code(image, *headers, {.address = 0x8420, .length = 16}).has_value());
}

}  // namespace
}  // namespace rasp::android::util
