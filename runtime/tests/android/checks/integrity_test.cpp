/// Tests for the Android integrity check: the ELF reader that locates `.text`, the SHA-256 helper, and the pair of
/// file and memory hashes. The tests build small ELF32 and ELF64 images in memory so the file-offset-to-address
/// translation and its edge cases can be driven without a device.

#include "checks/integrity.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "rasp/decision.h"
#include "rasp/observation.h"
#include "support/decision.h"
#include "support/files.h"

namespace rasp::android::checks {
namespace {

using test_support::TemporaryDirectory;
using test_support::write_file;

/// The page size the images align their segments to, so a file offset and its virtual address differ.
constexpr std::uint64_t kPageSize = 0x1000;
/// The load address the images place their segments at, non-zero so the address isn't the same as the file offset.
constexpr std::uint64_t kSegmentVaddr = 0x2000;

/// ELF constants the builder writes.
constexpr std::uint32_t kPtLoad = 1;
constexpr std::uint32_t kPfX = 0x1;
constexpr std::uint32_t kPfW = 0x2;
constexpr std::uint32_t kPfR = 0x4;
constexpr std::uint32_t kShtProgbits = 1;
constexpr std::uint32_t kShtStrtab = 3;
constexpr std::uint64_t kShfWrite = 0x1;
constexpr std::uint64_t kShfAlloc = 0x2;
constexpr std::uint64_t kShfExecinstr = 0x4;

/// Where the builder writes each header field for one ELF class, and how wide that class's address-sized fields are.
struct ElfClass {
  /// The class byte of the ELF identification: 1 for ELF32, 2 for ELF64.
  std::uint8_t identifier = 0;
  /// The width in bytes of an address, a file offset, and a section's flags and size: 4 in ELF32, 8 in ELF64.
  std::size_t word_size = 0;
  /// The size of the ELF header.
  std::uint16_t header_size = 0;
  /// The size of one program header.
  std::uint16_t program_header_size = 0;
  /// The size of one section header.
  std::uint16_t section_header_size = 0;
  /// The offsets of `e_phoff`, `e_shoff`, `e_ehsize`, `e_phentsize`, `e_phnum`, `e_shentsize`, `e_shnum` and
  /// `e_shstrndx` in the ELF header, in that order.
  std::array<std::size_t, 8> header_fields{};
  /// The offsets of `p_type`, `p_flags`, `p_offset`, `p_vaddr`, `p_paddr`, `p_filesz`, `p_memsz` and `p_align` in a
  /// program header, in that order.
  std::array<std::size_t, 8> program_fields{};
  /// The offsets of `sh_name`, `sh_type`, `sh_flags`, `sh_addr`, `sh_offset` and `sh_size` in a section header, in that
  /// order.
  std::array<std::size_t, 6> section_fields{};
};

/// The ELF32 layout, as a 32-bit Android library such as an armeabi-v7a or x86 one has.
constexpr ElfClass kElf32{
    .identifier = 1,
    .word_size = 4,
    .header_size = 52,
    .program_header_size = 32,
    .section_header_size = 40,
    .header_fields = {0x1C, 0x20, 0x28, 0x2A, 0x2C, 0x2E, 0x30, 0x32},
    .program_fields = {0x00, 0x18, 0x04, 0x08, 0x0C, 0x10, 0x14, 0x1C},
    .section_fields = {0x00, 0x04, 0x08, 0x0C, 0x10, 0x14},
};

/// The ELF64 layout, as a 64-bit Android library such as an arm64-v8a or x86_64 one has.
constexpr ElfClass kElf64{
    .identifier = 2,
    .word_size = 8,
    .header_size = 64,
    .program_header_size = 56,
    .section_header_size = 64,
    .header_fields = {0x20, 0x28, 0x34, 0x36, 0x38, 0x3A, 0x3C, 0x3E},
    .program_fields = {0x00, 0x04, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30},
    .section_fields = {0x00, 0x04, 0x08, 0x10, 0x18, 0x20},
};

/// A little-endian field to write into an image: a value and how many bytes wide it is. Grouping the two keeps callers
/// from swapping them.
struct Field {
  /// The value to write.
  std::uint64_t value = 0;
  /// The width in bytes, 1 to 8.
  std::size_t width = 0;
};

/// Writes `field` as little-endian bytes at `offset`, growing `image` when needed.
void put(std::vector<std::uint8_t>& image, std::size_t offset, Field field) {
  if (image.size() < offset + field.width) {
    image.resize(offset + field.width);
  }
  const std::span<std::uint8_t> target = std::span(image).subspan(offset, field.width);
  for (std::size_t index = 0; index < field.width; ++index) {
    target[index] = static_cast<std::uint8_t>((field.value >> (8U * index)) & 0xFFU);
  }
}

/// How one section of a built image is laid out.
struct SectionSpec {
  std::string_view name;
  std::uint32_t type = kShtProgbits;
  std::uint64_t flags = 0;
  std::uint64_t address = 0;
  std::uint64_t file_offset = 0;
  std::uint64_t size = 0;
};

/// How one segment of a built image is laid out.
struct SegmentSpec {
  std::uint32_t flags = 0;
  std::uint64_t file_offset = 0;
  std::uint64_t address = 0;
  std::uint64_t file_size = 0;
  std::uint64_t memory_size = 0;
};

/// Builds a little-endian image of the `elf` class from `sections` and `segments`, with `text_bytes` written at the
/// file offset of the section named `.text`. The section headers go after the file bytes, the string table holds every
/// section name, and the program headers go right after the ELF header.
[[nodiscard]] std::vector<std::uint8_t> build_image(const std::vector<SectionSpec>& sections,
                                                    const std::vector<SegmentSpec>& segments,
                                                    std::span<const std::uint8_t> text_bytes,
                                                    const ElfClass& elf = kElf64) {
  std::vector<std::uint8_t> image;

  // The section header table holds a leading null header, one header per section, then the section-name string table's
  // own header: sections.size() + 2 in all, with the string table last.
  const auto section_count = static_cast<std::uint16_t>(sections.size() + 2);
  const auto strtab_index = static_cast<std::uint16_t>(sections.size() + 1);

  // The string table holds, after a leading null byte, every section's name, then ".shstrtab" for its own header.
  std::string strtab(1, '\0');
  std::vector<std::uint32_t> name_offsets;
  name_offsets.reserve(sections.size());
  for (const SectionSpec& section : sections) {
    name_offsets.push_back(static_cast<std::uint32_t>(strtab.size()));
    strtab.append(section.name);
    strtab.push_back('\0');
  }
  const auto strtab_name_offset = static_cast<std::uint32_t>(strtab.size());
  strtab.append(".shstrtab");
  strtab.push_back('\0');

  const std::uint64_t program_offset = elf.header_size;
  const std::uint64_t section_offset =
      program_offset + (static_cast<std::uint64_t>(segments.size()) * elf.program_header_size);
  const std::uint64_t strtab_offset =
      section_offset + (static_cast<std::uint64_t>(section_count) * elf.section_header_size);
  const std::uint64_t content_offset = strtab_offset + strtab.size();

  for (std::size_t index = 0; index < segments.size(); ++index) {
    const std::uint64_t base = program_offset + (index * elf.program_header_size);
    const SegmentSpec& segment = segments[index];
    const auto fields = std::to_array<Field>({
        {.value = kPtLoad, .width = 4},
        {.value = segment.flags, .width = 4},
        {.value = segment.file_offset, .width = elf.word_size},
        {.value = segment.address, .width = elf.word_size},
        {.value = segment.address, .width = elf.word_size},
        {.value = segment.file_size, .width = elf.word_size},
        {.value = segment.memory_size, .width = elf.word_size},
        {.value = kPageSize, .width = elf.word_size},
    });
    for (const auto& [offset, field] : std::views::zip(elf.program_fields, fields)) {
      put(image, base + offset, field);
    }
  }

  const auto write_section = [&](std::size_t index, const SectionSpec& section, std::uint32_t name_offset) {
    const std::uint64_t base = section_offset + (index * elf.section_header_size);
    const auto fields = std::to_array<Field>({
        {.value = name_offset, .width = 4},
        {.value = section.type, .width = 4},
        {.value = section.flags, .width = elf.word_size},
        {.value = section.address, .width = elf.word_size},
        {.value = section.file_offset, .width = elf.word_size},
        {.value = section.size, .width = elf.word_size},
    });
    for (const auto& [offset, field] : std::views::zip(elf.section_fields, fields)) {
      put(image, base + offset, field);
    }
  };
  write_section(0, SectionSpec{.name = "", .type = 0}, 0);
  for (std::size_t index = 0; index < sections.size(); ++index) {
    write_section(index + 1, sections[index], name_offsets[index]);
  }
  write_section(strtab_index,
                SectionSpec{
                    .name = ".shstrtab",
                    .type = kShtStrtab,
                    .flags = 0,
                    .address = 0,
                    .file_offset = strtab_offset,
                    .size = strtab.size(),
                },
                strtab_name_offset);

  for (std::size_t index = 0; index < strtab.size(); ++index) {
    put(image, static_cast<std::size_t>(strtab_offset) + index,
        {.value = static_cast<std::uint8_t>(strtab[index]), .width = 1});
  }

  if (image.size() < content_offset) {
    image.resize(static_cast<std::size_t>(content_offset));
  }

  for (const SectionSpec& section : sections) {
    if (section.name == ".text" && !text_bytes.empty()) {
      const auto offset = static_cast<std::size_t>(section.file_offset);
      if (image.size() < offset + text_bytes.size()) {
        image.resize(offset + text_bytes.size());
      }
      std::ranges::copy(text_bytes, std::span(image).subspan(offset, text_bytes.size()).begin());
    }
  }

  const std::array<std::uint8_t, 7> identifier = {0x7F, 'E', 'L', 'F', elf.identifier, 1, 1};
  std::size_t identifier_offset = 0;
  for (const std::uint8_t byte : identifier) {
    put(image, identifier_offset, {.value = byte, .width = 1});
    ++identifier_offset;
  }
  put(image, 0x10, {.value = 3, .width = 2});  // e_type: ET_DYN
  put(image, 0x14, {.value = 1, .width = 4});  // e_version
  const auto fields = std::to_array<Field>({
      {.value = program_offset, .width = elf.word_size},
      {.value = section_offset, .width = elf.word_size},
      {.value = elf.header_size, .width = 2},
      {.value = elf.program_header_size, .width = 2},
      {.value = static_cast<std::uint64_t>(segments.size()), .width = 2},
      {.value = elf.section_header_size, .width = 2},
      {.value = section_count, .width = 2},
      {.value = strtab_index, .width = 2},
  });
  for (const auto& [offset, field] : std::views::zip(elf.header_fields, fields)) {
    put(image, offset, field);
  }
  return image;
}

/// How the one text segment of a built image is sized: how many of its bytes the file holds, how many it spans in
/// memory, and where the `.text` section sits inside it. Grouping these keeps callers from swapping the sizes.
struct TextLayout {
  /// The offset of the `.text` section inside the segment.
  std::uint64_t text_offset_in_segment = 0;
  /// The number of the segment's bytes the file holds.
  std::uint64_t segment_file_size = 0;
  /// The number of bytes the segment spans in memory. The loader zero-fills the part past the file bytes.
  std::uint64_t segment_memory_size = 0;
};

/// An image of the `elf` class with a text segment whose file offset and virtual address differ by a whole number of
/// pages, as the loader maps it, laid out as `layout` describes.
[[nodiscard]] std::vector<std::uint8_t> image_with_text(std::span<const std::uint8_t> text_bytes,
                                                        const TextLayout& layout, const ElfClass& elf = kElf64) {
  const std::uint64_t segment_file_offset = kPageSize;  // page-aligned, non-zero, different from the vaddr
  const SegmentSpec text_segment{
      .flags = kPfR | kPfX,
      .file_offset = segment_file_offset,
      .address = kSegmentVaddr,
      .file_size = layout.segment_file_size,
      .memory_size = layout.segment_memory_size,
  };
  const SectionSpec text_section{
      .name = ".text",
      .type = kShtProgbits,
      .flags = kShfAlloc | kShfExecinstr,
      .address = kSegmentVaddr + layout.text_offset_in_segment,
      .file_offset = segment_file_offset + layout.text_offset_in_segment,
      .size = text_bytes.size(),
  };
  return build_image({text_section}, {text_segment}, text_bytes, elf);
}

/// The loaded image of a single-segment library built by `image_with_text`, as the loader lays it out from load bias 0:
/// a buffer indexed by virtual address, with the segment's file bytes placed at its virtual address and the rest zero.
/// `observe_text_hashes` and `integrity` read the `.text` bytes from such an image by the section's virtual address.
[[nodiscard]] std::vector<std::uint8_t> loaded_image(std::span<const std::uint8_t> file_image,
                                                     const TextLayout& layout) {
  const std::uint64_t segment_file_offset = kPageSize;
  std::vector<std::uint8_t> memory(static_cast<std::size_t>(kSegmentVaddr + layout.segment_memory_size), 0);
  const std::uint64_t copied =
      std::min<std::uint64_t>(layout.segment_file_size, file_image.size() - segment_file_offset);
  const std::span<const std::uint8_t> source =
      file_image.subspan(static_cast<std::size_t>(segment_file_offset), static_cast<std::size_t>(copied));
  std::ranges::copy(source, std::span(memory).subspan(kSegmentVaddr, static_cast<std::size_t>(copied)).begin());
  return memory;
}

/// A set of distinct `.text` bytes to hash.
[[nodiscard]] std::vector<std::uint8_t> sample_text(std::size_t size) {
  std::vector<std::uint8_t> bytes(size);
  for (std::size_t index = 0; index < size; ++index) {
    bytes[index] = static_cast<std::uint8_t>(((index * 7) + 3) & 0xFFU);
  }
  return bytes;
}

/// The integ.text_sha256 observation for `source` that holds `hash`.
[[nodiscard]] Observation hashed(std::string_view source, const std::string& hash) {
  return {.signal = "integ.text_sha256", .source = std::string(source), .status = Status::kOk, .value = hash};
}

/// The integ.text_sha256 observation for `source` that failed.
[[nodiscard]] Observation failed_hash(std::string_view source) {
  return {.signal = "integ.text_sha256", .source = std::string(source), .status = Status::kError, .value = {}};
}

/// The bytes of `image` as a string, so an image can be written to a file with write_file. Each byte is copied, so no
/// pointer is reinterpreted.
[[nodiscard]] std::string as_string(std::span<const std::uint8_t> image) { return {image.begin(), image.end()}; }

/// The whole-page text layout the hash tests use: a 0x1000-byte segment, both in the file and in memory, with `.text`
/// at `text_offset` inside it.
[[nodiscard]] TextLayout whole_page_layout(std::uint64_t text_offset) {
  return {.text_offset_in_segment = text_offset, .segment_file_size = 0x1000, .segment_memory_size = 0x1000};
}

TEST(Integrity, findTextRegion_whenSegmentIsPageShifted_translatesOffsetToAddress) {
  const std::vector<std::uint8_t> text = sample_text(200);
  const std::uint64_t text_offset_in_segment = 0x40;
  const std::vector<std::uint8_t> image = image_with_text(
      text,
      {.text_offset_in_segment = text_offset_in_segment, .segment_file_size = 0x1000, .segment_memory_size = 0x1000});
  const std::uintptr_t load_bias = 0x7000000000;

  const std::optional<TextRegion> region = find_text_region(image, load_bias);

  ASSERT_TRUE(region.has_value());
  EXPECT_EQ(region->size, text.size());
  EXPECT_EQ(region->file_offset, kPageSize + text_offset_in_segment);
  EXPECT_EQ(region->memory_address, load_bias + kSegmentVaddr + text_offset_in_segment);
}

TEST(Integrity, findTextRegion_whenImageIsElf32_translatesOffsetToAddress) {
  const std::vector<std::uint8_t> text = sample_text(200);
  const std::uint64_t text_offset_in_segment = 0x40;
  const std::vector<std::uint8_t> image = image_with_text(
      text,
      {.text_offset_in_segment = text_offset_in_segment, .segment_file_size = 0x1000, .segment_memory_size = 0x1000},
      kElf32);
  const std::uintptr_t load_bias = 0x70000000;

  const std::optional<TextRegion> region = find_text_region(image, load_bias);

  ASSERT_TRUE(region.has_value());
  EXPECT_EQ(region->size, text.size());
  EXPECT_EQ(region->file_offset, kPageSize + text_offset_in_segment);
  EXPECT_EQ(region->memory_address, load_bias + kSegmentVaddr + text_offset_in_segment);
}

TEST(Integrity, findTextRegion_whenClassIsUnknown_reportsNothing) {
  std::vector<std::uint8_t> image = image_with_text(sample_text(64), whole_page_layout(0x40));
  image[4] = 3;

  EXPECT_FALSE(find_text_region(image, 0).has_value());
}

TEST(Integrity, findTextRegion_whenImageIsNotElf_reportsNothing) {
  std::vector<std::uint8_t> image(128, 0);
  image[0] = 'N';

  EXPECT_FALSE(find_text_region(image, 0).has_value());
}

TEST(Integrity, findTextRegion_whenTextStraddlesEndOfFileInSegment_reportsNothing) {
  // The segment holds 0x100 bytes in the file but 0x1000 in memory: the loader zero-fills the rest in memory, so a
  // `.text` that reaches past the file part would hash memory bytes the file doesn't hold.
  const std::vector<std::uint8_t> text = sample_text(0x80);
  // 0xC0 + 0x80 = 0x140 > 0x100 file size
  const std::vector<std::uint8_t> image = image_with_text(
      text, {.text_offset_in_segment = 0xC0, .segment_file_size = 0x100, .segment_memory_size = 0x1000});

  EXPECT_FALSE(find_text_region(image, 0).has_value());
}

TEST(Integrity, findTextRegion_whenTextIsWritable_reportsNothing) {
  const std::vector<std::uint8_t> text = sample_text(64);
  const SegmentSpec segment{
      .flags = kPfR | kPfX,
      .file_offset = kPageSize,
      .address = kSegmentVaddr,
      .file_size = 0x1000,
      .memory_size = 0x1000,
  };
  const SectionSpec writable_text{
      .name = ".text",
      .type = kShtProgbits,
      .flags = kShfAlloc | kShfWrite,  // writable: not immutable code
      .address = kSegmentVaddr,
      .file_offset = kPageSize,
      .size = text.size(),
  };
  const std::vector<std::uint8_t> image = build_image({writable_text}, {segment}, text);

  EXPECT_FALSE(find_text_region(image, 0).has_value());
}

TEST(Integrity, findTextRegion_whenOnlySegmentIsWritable_reportsNothing) {
  const std::vector<std::uint8_t> text = sample_text(64);
  const SegmentSpec writable_segment{
      .flags = kPfR | kPfW,  // not executable-read-only: a data segment
      .file_offset = kPageSize,
      .address = kSegmentVaddr,
      .file_size = 0x1000,
      .memory_size = 0x1000,
  };
  const SectionSpec text_section{
      .name = ".text",
      .type = kShtProgbits,
      .flags = kShfAlloc | kShfExecinstr,
      .address = kSegmentVaddr,
      .file_offset = kPageSize,
      .size = text.size(),
  };
  const std::vector<std::uint8_t> image = build_image({text_section}, {writable_segment}, text);

  EXPECT_FALSE(find_text_region(image, 0).has_value());
}

TEST(Integrity, sha256Hex_whenGivenKnownInput_matchesTheKnownAnswer) {
  const std::string_view input = "abc";
  const std::vector<std::uint8_t> bytes(input.begin(), input.end());

  EXPECT_EQ(sha256_hex(bytes), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(Integrity, sha256Hex_whenGivenEmptyInput_matchesTheKnownAnswer) {
  EXPECT_EQ(sha256_hex({}), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(Integrity, observeTextHashes_whenMemoryMatchesTheFile_reportsEqualHashes) {
  const std::vector<std::uint8_t> text = sample_text(300);
  const std::vector<std::uint8_t> image = image_with_text(text, whole_page_layout(0x30));
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string library = directory.path() + "/librasp.so";
  ASSERT_TRUE(write_file(library, as_string(image)));
  const std::vector<std::uint8_t> memory = loaded_image(image, whole_page_layout(0x30));

  const std::vector<Observation> observations = observe_text_hashes(library, memory);

  const std::optional<std::string> hash = sha256_hex(text);
  ASSERT_TRUE(hash.has_value());
  EXPECT_EQ(observations, (std::vector<Observation>{hashed("file", *hash), hashed("memory", *hash)}));
  const auto snapshot = test_support::decide("android", observations);
  EXPECT_TRUE(std::ranges::any_of(snapshot->local_decisions.rows, [](const auto& decision) {
    return decision.rule_id == "local.android.integrity_pair" && decision.reason == LocalReason::kHashesEqualUntrusted;
  }));
}

TEST(Integrity, observeTextHashes_whenElf32MemoryMatchesTheFile_reportsEqualHashes) {
  const std::vector<std::uint8_t> text = sample_text(300);
  const std::vector<std::uint8_t> image = image_with_text(text, whole_page_layout(0x30), kElf32);
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string library = directory.path() + "/librasp.so";
  ASSERT_TRUE(write_file(library, as_string(image)));
  const std::vector<std::uint8_t> memory = loaded_image(image, whole_page_layout(0x30));

  const std::vector<Observation> observations = observe_text_hashes(library, memory);

  const std::optional<std::string> hash = sha256_hex(text);
  ASSERT_TRUE(hash.has_value());
  EXPECT_EQ(observations, (std::vector<Observation>{hashed("file", *hash), hashed("memory", *hash)}));
}

TEST(Integrity, observeTextHashes_whenMemoryWasPatched_reportsDifferentHashes) {
  const std::vector<std::uint8_t> text = sample_text(300);
  const std::vector<std::uint8_t> image = image_with_text(text, whole_page_layout(0x30));
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string library = directory.path() + "/librasp.so";
  ASSERT_TRUE(write_file(library, as_string(image)));

  std::vector<std::uint8_t> patched = loaded_image(image, whole_page_layout(0x30));
  patched[static_cast<std::size_t>(kSegmentVaddr + 0x30)] ^= 0xFFU;  // flip a byte of `.text` in the loaded copy

  const std::vector<Observation> observations = observe_text_hashes(library, patched);

  ASSERT_EQ(observations.size(), 2U);
  EXPECT_EQ(observations[0].status, Status::kOk);
  EXPECT_EQ(observations[1].status, Status::kOk);
  EXPECT_NE(observations[0].value, observations[1].value);
  const auto snapshot = test_support::decide("android", observations);
  EXPECT_TRUE(std::ranges::any_of(snapshot->local_decisions.rows, [](const auto& decision) {
    return decision.rule_id == "local.android.integrity_pair" && decision.reason == LocalReason::kHashesDiffer &&
           decision.confidence == LocalConfidence::kLimited;
  }));
}

TEST(Integrity, observeTextHashes_whenFileIsMissing_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::vector<std::uint8_t> memory = sample_text(64);

  const std::vector<Observation> observations = observe_text_hashes(directory.path() + "/missing", memory);

  EXPECT_EQ(observations, (std::vector<Observation>{failed_hash("file"), failed_hash("memory")}));
}

TEST(Integrity, observeTextHashes_whenTextReachesPastTheMemorySpan_reportsAnError) {
  const std::vector<std::uint8_t> text = sample_text(300);
  const std::vector<std::uint8_t> image = image_with_text(text, whole_page_layout(0x30));
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string library = directory.path() + "/librasp.so";
  ASSERT_TRUE(write_file(library, as_string(image)));

  // A memory span shorter than the `.text` address plus its size: reading it would run past the mapped image.
  const std::span<const std::uint8_t> short_memory(image.data(), static_cast<std::size_t>(kSegmentVaddr));

  const std::vector<Observation> observations = observe_text_hashes(library, short_memory);

  EXPECT_EQ(observations, (std::vector<Observation>{failed_hash("file"), failed_hash("memory")}));
}

TEST(Integrity, integrity_whenOffAndroid_reportsEveryCheckAsUnsupported) {
  EXPECT_EQ(integrity(),
            (std::vector<Observation>{
                {.signal = "integ.text_sha256", .source = "file", .status = Status::kUnsupported, .value = {}},
                {.signal = "integ.text_sha256", .source = "memory", .status = Status::kUnsupported, .value = {}},
            }));
}

}  // namespace
}  // namespace rasp::android::checks
