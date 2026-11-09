/// The Android integrity check: the file and memory hashes of librasp.so's `.text`, and its unsupported result off
/// Android. The ELF reader draws only on the standard ELF32 and ELF64 layouts.

#include "checks/integrity.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <psa/crypto.h>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "rasp/observation.h"
#include "util/apk_file.h"

#ifdef __ANDROID__
#include <bit>
#include <dlfcn.h>
#include <link.h>

#include "rasp/util/obfuscation.h"
#endif

namespace rasp::android::checks {

namespace {

using util::read_library_file;

/// The signal of the integrity check: the hash of librasp.so's executable code.
constexpr std::string_view kTextHashSignal = "integ.text_sha256";
/// The source that reads the hash from the installed file.
constexpr std::string_view kFileSource = "file";
/// The source that reads the hash from the process's memory.
constexpr std::string_view kMemorySource = "memory";

/// The largest library file read. librasp.so is well under this, and the limit bounds what the read allocates for a
/// forged file.
constexpr std::size_t kMaxLibrarySize = std::size_t{64} << 20U;

/// The ELF identification bytes every image this reader accepts starts with: the magic.
constexpr std::array<std::uint8_t, 4> kElfMagic = {0x7F, 'E', 'L', 'F'};
/// The offset of the class byte in the ELF identification bytes.
constexpr std::size_t kClassOffset = 4;
/// The offset of the data-encoding byte in the ELF identification bytes.
constexpr std::size_t kDataOffset = 5;
/// ELFCLASS32, the class byte of a 32-bit image.
constexpr std::uint8_t kElfClass32 = 1;
/// ELFCLASS64, the class byte of a 64-bit image.
constexpr std::uint8_t kElfClass64 = 2;
/// ELFDATA2LSB, the data-encoding byte of a little-endian image.
constexpr std::uint8_t kElfLittleEndian = 1;

/// Where the fields the reader uses sit in the headers of one ELF class, and how wide that class's address-sized fields
/// are. A 32-bit library, as armeabi-v7a and x86 use, has ELF32 headers, and a 64-bit one ELF64 headers; the two
/// differ only in these offsets and widths.
struct ElfLayout {
  /// The width in bytes of an address, a file offset, and a section's flags and size: 4 in ELF32, 8 in ELF64.
  std::size_t word_size = 0;
  /// The size of the ELF header.
  std::size_t header_size = 0;
  /// The offset of `e_phoff`, the program header table's file offset, in the ELF header.
  std::size_t phoff = 0;
  /// The offset of `e_shoff`, the section header table's file offset, in the ELF header.
  std::size_t shoff = 0;
  /// The offset of `e_phentsize`, the size of one program header, in the ELF header.
  std::size_t phentsize = 0;
  /// The offset of `e_phnum`, the number of program headers, in the ELF header.
  std::size_t phnum = 0;
  /// The offset of `e_shentsize`, the size of one section header, in the ELF header.
  std::size_t shentsize = 0;
  /// The offset of `e_shnum`, the number of section headers, in the ELF header.
  std::size_t shnum = 0;
  /// The offset of `e_shstrndx`, the index of the section-name string table, in the ELF header.
  std::size_t shstrndx = 0;
  /// The smallest section header entry size the reader accepts: the size of one section header.
  std::size_t section_header_size = 0;
  /// The offset of `sh_name` in a section header.
  std::size_t sh_name = 0;
  /// The offset of `sh_flags` in a section header.
  std::size_t sh_flags = 0;
  /// The offset of `sh_addr` in a section header.
  std::size_t sh_addr = 0;
  /// The offset of `sh_offset` in a section header.
  std::size_t sh_offset = 0;
  /// The offset of `sh_size` in a section header.
  std::size_t sh_size = 0;
  /// The smallest program header entry size the reader accepts: the size of one program header.
  std::size_t program_header_size = 0;
  /// The offset of `p_type` in a program header.
  std::size_t p_type = 0;
  /// The offset of `p_flags` in a program header.
  std::size_t p_flags = 0;
  /// The offset of `p_offset` in a program header.
  std::size_t p_offset = 0;
  /// The offset of `p_vaddr` in a program header.
  std::size_t p_vaddr = 0;
  /// The offset of `p_filesz` in a program header.
  std::size_t p_filesz = 0;
};

/// The ELF32 layout.
constexpr ElfLayout kElf32Layout{
    .word_size = 4,
    .header_size = 52,
    .phoff = 0x1C,
    .shoff = 0x20,
    .phentsize = 0x2A,
    .phnum = 0x2C,
    .shentsize = 0x2E,
    .shnum = 0x30,
    .shstrndx = 0x32,
    .section_header_size = 40,
    .sh_name = 0x00,
    .sh_flags = 0x08,
    .sh_addr = 0x0C,
    .sh_offset = 0x10,
    .sh_size = 0x14,
    .program_header_size = 32,
    .p_type = 0x00,
    .p_flags = 0x18,
    .p_offset = 0x04,
    .p_vaddr = 0x08,
    .p_filesz = 0x10,
};

/// The ELF64 layout.
constexpr ElfLayout kElf64Layout{
    .word_size = 8,
    .header_size = 64,
    .phoff = 0x20,
    .shoff = 0x28,
    .phentsize = 0x36,
    .phnum = 0x38,
    .shentsize = 0x3A,
    .shnum = 0x3C,
    .shstrndx = 0x3E,
    .section_header_size = 64,
    .sh_name = 0x00,
    .sh_flags = 0x08,
    .sh_addr = 0x10,
    .sh_offset = 0x18,
    .sh_size = 0x20,
    .program_header_size = 56,
    .p_type = 0x00,
    .p_flags = 0x04,
    .p_offset = 0x08,
    .p_vaddr = 0x10,
    .p_filesz = 0x20,
};

/// PT_LOAD, the program header type of a segment the loader maps into memory.
constexpr std::uint32_t kPtLoad = 1;
/// PF_X, the program header flag of an executable segment.
constexpr std::uint32_t kPfExecute = 0x1;
/// PF_W, the program header flag of a writable segment.
constexpr std::uint32_t kPfWrite = 0x2;
/// SHF_WRITE, the section flag of a writable section.
constexpr std::uint64_t kShfWrite = 0x1;
/// SHF_ALLOC, the section flag of a section the loader maps into memory.
constexpr std::uint64_t kShfAlloc = 0x2;

/// The name of the executable code section.
constexpr std::string_view kTextSectionName = ".text";

/// The name of the runtime's config section, whose trailing 32 bytes carry the expected plaintext `.text` digest
/// on packed builds.
constexpr std::string_view kConfigSectionName = ".rasp_config";

/// Whether the range `[offset, offset + length)` lies within a container of `size` bytes, checked without any addition
/// that could overflow. Every bounds check on an attacker-controlled ELF offset and size goes through this, so a
/// crafted header can't wrap a sum past the end and still pass.
///
/// @param offset The start of the range.
/// @param length The length of the range.
/// @param size The size of the container the range must fit in.
/// @return `true` when `offset <= size` and `length <= size - offset`.
[[nodiscard]] constexpr bool range_fits(std::uint64_t offset, std::uint64_t length, std::uint64_t size) {
  return offset <= size && length <= size - offset;
}

/// Reads a little-endian unsigned integer of type `T` at `offset`, or nothing when the span is too short to hold it.
/// The offset is 64 bits wide, as ELF64 offsets are, and fits a `std::size_t` once it is known to lie inside the span.
template <typename T>
[[nodiscard]] std::optional<T> read_scalar(std::span<const std::uint8_t> bytes, std::uint64_t offset) {
  if (!range_fits(offset, sizeof(T), bytes.size())) {
    return std::nullopt;
  }
  T value = 0;
  std::memcpy(&value, bytes.subspan(static_cast<std::size_t>(offset), sizeof(T)).data(), sizeof(T));
  return value;
}

/// Reads a little-endian 16-bit number at `offset`, or nothing when the span is too short to hold it.
[[nodiscard]] std::optional<std::uint16_t> read_u16(std::span<const std::uint8_t> bytes, std::uint64_t offset) {
  return read_scalar<std::uint16_t>(bytes, offset);
}

/// Reads a little-endian 32-bit number at `offset`, or nothing when the span is too short to hold it.
[[nodiscard]] std::optional<std::uint32_t> read_u32(std::span<const std::uint8_t> bytes, std::uint64_t offset) {
  return read_scalar<std::uint32_t>(bytes, offset);
}

/// Reads a little-endian 64-bit number at `offset`, or nothing when the span is too short to hold it.
[[nodiscard]] std::optional<std::uint64_t> read_u64(std::span<const std::uint8_t> bytes, std::uint64_t offset) {
  return read_scalar<std::uint64_t>(bytes, offset);
}

/// Reads a little-endian address-sized field of the `layout` class at `offset`: 32 bits in ELF32 and 64 bits in ELF64,
/// widened to 64 bits. Nothing when the span is too short to hold it.
[[nodiscard]] std::optional<std::uint64_t> read_word(std::span<const std::uint8_t> bytes, std::uint64_t offset,
                                                     const ElfLayout& layout) {
  if (layout.word_size == sizeof(std::uint64_t)) {
    return read_u64(bytes, offset);
  }
  return read_u32(bytes, offset);
}

/// The layout of the class `image` declares, or nothing when it isn't a little-endian ELF32 or ELF64 image.
[[nodiscard]] std::optional<ElfLayout> layout_of(std::span<const std::uint8_t> image) {
  if (image.size() <= kDataOffset || !std::equal(kElfMagic.begin(), kElfMagic.end(), image.begin()) ||
      image[kDataOffset] != kElfLittleEndian) {
    return std::nullopt;
  }
  if (image[kClassOffset] == kElfClass32) {
    return kElf32Layout;
  }
  if (image[kClassOffset] == kElfClass64) {
    return kElf64Layout;
  }
  return std::nullopt;
}

/// One section header, with the fields the reader needs.
struct SectionHeader {
  /// The offset of the section's name in the section-name string table.
  std::uint32_t name_offset = 0;
  /// The section's flags, such as SHF_ALLOC and SHF_WRITE.
  std::uint64_t flags = 0;
  /// The section's virtual address, relative to the image's load address.
  std::uint64_t address = 0;
  /// The offset of the section's bytes in the file.
  std::uint64_t file_offset = 0;
  /// The number of bytes in the section.
  std::uint64_t size = 0;
};

/// A header table in the ELF image: where it starts, how large each entry is, and how many entries it has. Section
/// headers and program headers are both described this way.
struct HeaderTable {
  /// The offset of the first entry in the file.
  std::uint64_t offset = 0;
  /// The size of one entry in bytes.
  std::uint16_t entry_size = 0;
  /// The number of entries.
  std::uint16_t count = 0;
};

/// One loadable segment, with the fields the reader needs.
struct LoadSegment {
  /// Whether the segment is executable and not writable, as an immutable-code segment is.
  bool executable_read_only = false;
  /// The offset of the segment's bytes in the file.
  std::uint64_t file_offset = 0;
  /// The segment's virtual address, relative to the image's load address.
  std::uint64_t address = 0;
  /// The number of the segment's bytes the file holds. The loader zero-fills the rest of the last page in memory.
  std::uint64_t file_size = 0;
};

/// Reads the section header `index` from `image`, given the section header `table` and the `layout` of its class.
[[nodiscard]] std::optional<SectionHeader> read_section_header(std::span<const std::uint8_t> image,
                                                               const HeaderTable& table, const ElfLayout& layout,
                                                               std::uint16_t index) {
  if (table.entry_size < layout.section_header_size) {
    return std::nullopt;
  }
  const std::uint64_t offset_in_table = std::uint64_t{index} * table.entry_size;
  if (!range_fits(table.offset, offset_in_table + table.entry_size, image.size())) {
    return std::nullopt;
  }
  const std::uint64_t base = table.offset + offset_in_table;
  const std::optional<std::uint32_t> name_offset = read_u32(image, base + layout.sh_name);
  const std::optional<std::uint64_t> flags = read_word(image, base + layout.sh_flags, layout);
  const std::optional<std::uint64_t> address = read_word(image, base + layout.sh_addr, layout);
  const std::optional<std::uint64_t> file_offset = read_word(image, base + layout.sh_offset, layout);
  const std::optional<std::uint64_t> size = read_word(image, base + layout.sh_size, layout);
  if (!name_offset || !flags || !address || !file_offset || !size) {
    return std::nullopt;
  }
  return SectionHeader{
      .name_offset = *name_offset,
      .flags = *flags,
      .address = *address,
      .file_offset = *file_offset,
      .size = *size,
  };
}

/// Reads the loadable segment at program header `index`, given the program header `table` and the `layout` of its
/// class, or nothing when the index is past the table, the entry can't be read, or the entry isn't a PT_LOAD segment.
[[nodiscard]] std::optional<LoadSegment> read_load_segment(std::span<const std::uint8_t> image,
                                                           const HeaderTable& table, const ElfLayout& layout,
                                                           std::uint16_t index) {
  if (table.entry_size < layout.program_header_size) {
    return std::nullopt;
  }
  const std::uint64_t offset_in_table = std::uint64_t{index} * table.entry_size;
  if (!range_fits(table.offset, offset_in_table + table.entry_size, image.size())) {
    return std::nullopt;
  }
  const std::uint64_t base = table.offset + offset_in_table;
  const std::optional<std::uint32_t> type = read_u32(image, base + layout.p_type);
  if (!type || *type != kPtLoad) {
    return std::nullopt;
  }
  const std::optional<std::uint32_t> flags = read_u32(image, base + layout.p_flags);
  const std::optional<std::uint64_t> file_offset = read_word(image, base + layout.p_offset, layout);
  const std::optional<std::uint64_t> address = read_word(image, base + layout.p_vaddr, layout);
  const std::optional<std::uint64_t> file_size = read_word(image, base + layout.p_filesz, layout);
  if (!flags || !file_offset || !address || !file_size) {
    return std::nullopt;
  }
  return LoadSegment{
      .executable_read_only = (*flags & kPfExecute) != 0U && (*flags & kPfWrite) == 0U,
      .file_offset = *file_offset,
      .address = *address,
      .file_size = *file_size,
  };
}

/// Whether the section `header` is named `name` in the section-name string table `strtab`. The name in the table is a
/// run of bytes ending at the first null; it is compared to `name` byte for byte, with no view that aliases the bytes
/// as characters.
[[nodiscard]] bool section_named(std::span<const std::uint8_t> strtab, const SectionHeader& header,
                                 std::string_view name) {
  if (header.name_offset >= strtab.size()) {
    return false;
  }
  const std::span<const std::uint8_t> rest = strtab.subspan(header.name_offset);
  const auto terminator = std::ranges::find(rest, std::uint8_t{0});
  if (terminator == rest.end()) {
    return false;
  }
  const auto length = static_cast<std::size_t>(terminator - rest.begin());
  return std::ranges::equal(rest.first(length), name, [](std::uint8_t byte, char character) {
    return byte == static_cast<std::uint8_t>(character);
  });
}

/// The `.text` section header of `image`, found through the section header `table` of the `layout` class and the
/// string table at `strtab_index`, or nothing when the image has no section with that name.
[[nodiscard]] std::optional<SectionHeader> find_named_section(std::span<const std::uint8_t> image,
                                                              const HeaderTable& table, const ElfLayout& layout,
                                                              std::uint16_t strtab_index, std::string_view name) {
  if (strtab_index >= table.count) {
    return std::nullopt;
  }
  const std::optional<SectionHeader> strtab_header = read_section_header(image, table, layout, strtab_index);
  if (!strtab_header || !range_fits(strtab_header->file_offset, strtab_header->size, image.size())) {
    return std::nullopt;
  }
  const std::span<const std::uint8_t> strtab = image.subspan(static_cast<std::size_t>(strtab_header->file_offset),
                                                             static_cast<std::size_t>(strtab_header->size));
  for (std::uint16_t index = 0; index < table.count; ++index) {
    const std::optional<SectionHeader> header = read_section_header(image, table, layout, index);
    if (!header) {
      return std::nullopt;
    }
    if (section_named(strtab, *header, name)) {
      return header;
    }
  }
  return std::nullopt;
}

/// Whether the `.text` section `text` lies wholly inside the file part of the executable, non-writable segment
/// `segment`.
[[nodiscard]] bool fits_in_file_part(const LoadSegment& segment, const SectionHeader& text) {
  if (!segment.executable_read_only) {
    return false;
  }
  if (text.address < segment.address) {
    return false;
  }
  const std::uint64_t offset_in_segment = text.address - segment.address;
  return offset_in_segment <= segment.file_size && text.size <= segment.file_size - offset_in_segment;
}

/// Whether the `.text` section lies wholly inside the file part of one loadable, executable, non-writable segment of
/// the program header `table` of the `layout` class.
[[nodiscard]] bool text_is_backed_by_file(std::span<const std::uint8_t> image, const HeaderTable& table,
                                          const ElfLayout& layout, const SectionHeader& text) {
  for (std::uint16_t index = 0; index < table.count; ++index) {
    const std::optional<LoadSegment> segment = read_load_segment(image, table, layout, index);
    if (segment && fits_in_file_part(*segment, text)) {
      return true;
    }
  }
  return false;
}

}  // namespace

std::optional<TextRegion> find_text_region(std::span<const std::uint8_t> image, std::uintptr_t load_bias) {
  const std::optional<ElfLayout> layout = layout_of(image);
  if (!layout || image.size() < layout->header_size) {
    return std::nullopt;
  }
  const std::optional<std::uint64_t> section_offset = read_word(image, layout->shoff, *layout);
  const std::optional<std::uint16_t> section_entry_size = read_u16(image, layout->shentsize);
  const std::optional<std::uint16_t> section_count = read_u16(image, layout->shnum);
  const std::optional<std::uint16_t> strtab_index = read_u16(image, layout->shstrndx);
  const std::optional<std::uint64_t> program_offset = read_word(image, layout->phoff, *layout);
  const std::optional<std::uint16_t> program_entry_size = read_u16(image, layout->phentsize);
  const std::optional<std::uint16_t> program_count = read_u16(image, layout->phnum);
  if (!section_offset || !section_entry_size || !section_count || !strtab_index || !program_offset ||
      !program_entry_size || !program_count || *section_count == 0 || *program_count == 0) {
    return std::nullopt;
  }

  const HeaderTable section_table{
      .offset = *section_offset,
      .entry_size = *section_entry_size,
      .count = *section_count,
  };
  const HeaderTable program_table{
      .offset = *program_offset,
      .entry_size = *program_entry_size,
      .count = *program_count,
  };

  const std::optional<SectionHeader> text =
      find_named_section(image, section_table, *layout, *strtab_index, kTextSectionName);
  if (!text || text->size == 0 || (text->flags & kShfAlloc) == 0U || (text->flags & kShfWrite) != 0U ||
      !range_fits(text->file_offset, text->size, image.size()) || !std::in_range<std::uintptr_t>(text->address)) {
    return std::nullopt;
  }
  if (!text_is_backed_by_file(image, program_table, *layout, *text)) {
    return std::nullopt;
  }

  return TextRegion{
      .file_offset = text->file_offset,
      .memory_address = load_bias + static_cast<std::uintptr_t>(text->address),
      .size = text->size,
  };
}

std::optional<SectionRegion> find_section_region(std::span<const std::uint8_t> image, std::string_view name) {
  const std::optional<ElfLayout> layout = layout_of(image);
  if (!layout || image.size() < layout->header_size) {
    return std::nullopt;
  }
  const std::optional<std::uint64_t> section_offset = read_word(image, layout->shoff, *layout);
  const std::optional<std::uint16_t> section_entry_size = read_u16(image, layout->shentsize);
  const std::optional<std::uint16_t> section_count = read_u16(image, layout->shnum);
  const std::optional<std::uint16_t> strtab_index = read_u16(image, layout->shstrndx);
  if (!section_offset || !section_entry_size || !section_count || !strtab_index || *section_count == 0) {
    return std::nullopt;
  }
  const HeaderTable table{
      .offset = *section_offset,
      .entry_size = *section_entry_size,
      .count = *section_count,
  };
  const std::optional<SectionHeader> section = find_named_section(image, table, *layout, *strtab_index, name);
  if (!section || !range_fits(section->file_offset, section->size, image.size())) {
    return std::nullopt;
  }
  return SectionRegion{
      .file_offset = section->file_offset,
      .size = section->size,
  };
}

std::optional<std::array<std::uint8_t, kDigestSize>> sha256(std::span<const std::uint8_t> bytes) {
  if (psa_crypto_init() != PSA_SUCCESS) {
    return std::nullopt;
  }
  std::array<std::uint8_t, kDigestSize> digest{};
  std::size_t length = 0;
  const psa_status_t status =
      psa_hash_compute(PSA_ALG_SHA_256, bytes.data(), bytes.size(), digest.data(), digest.size(), &length);
  if (status != PSA_SUCCESS || length != digest.size()) {
    return std::nullopt;
  }
  return digest;
}

namespace {

/// Encodes bytes as lowercase hex.
///
/// @param bytes The bytes to encode.
/// @return Their hex string.
[[nodiscard]] std::string hex_encode(std::span<const std::uint8_t> bytes) {
  constexpr std::string_view kDigits = "0123456789abcdef";
  std::string hex;
  hex.reserve(bytes.size() * 2);
  for (const std::uint8_t byte : bytes) {
    hex.push_back(kDigits[byte >> 4U]);
    hex.push_back(kDigits[byte & 0x0FU]);
  }
  return hex;
}

/// The expected plaintext `.text` digest a packed runtime carries, as hex: the `.rasp_config` section's 32 bytes before
/// its keystore share, which the packer's fold writes there and binds into the root key. All-zero bytes mean the
/// library was never packed, and the caller falls back to comparing the file against memory.
///
/// @param image The library's whole file bytes.
/// @return The digest as hex. Nothing when the section is missing, too small, or unwritten.
[[nodiscard]] std::optional<std::string> expected_text_hash(std::span<const std::uint8_t> image) {
  const std::optional<SectionRegion> section = find_section_region(image, kConfigSectionName);
  if (!section || section->size < 2 * kDigestSize || !range_fits(section->file_offset, section->size, image.size())) {
    return std::nullopt;
  }
  const auto start = static_cast<std::size_t>(section->file_offset + section->size - (2 * kDigestSize));
  const std::span<const std::uint8_t> digest = image.subspan(start, kDigestSize);
  if (std::ranges::all_of(digest, [](std::uint8_t byte) { return byte == 0; })) {
    return std::nullopt;
  }
  return hex_encode(digest);
}

}  // namespace

std::optional<std::string> sha256_hex(std::span<const std::uint8_t> bytes) {
  const std::optional<std::array<std::uint8_t, kDigestSize>> digest = sha256(bytes);
  if (!digest.has_value()) {
    return std::nullopt;
  }
  return hex_encode(*digest);
}

std::vector<Observation> observe_text_hashes(std::string_view library_path, std::span<const std::uint8_t> text_memory) {
  const std::optional<std::vector<std::uint8_t>> file = read_library_file(library_path, kMaxLibrarySize);
  if (!file) {
    return {failed(kTextHashSignal, kFileSource), failed(kTextHashSignal, kMemorySource)};
  }
  const std::span<const std::uint8_t> image(*file);
  const std::optional<TextRegion> region = find_text_region(image, 0);
  if (!region || region->memory_address > text_memory.size() ||
      region->size > text_memory.size() - region->memory_address) {
    return {failed(kTextHashSignal, kFileSource), failed(kTextHashSignal, kMemorySource)};
  }

  const std::span<const std::uint8_t> file_bytes =
      image.subspan(static_cast<std::size_t>(region->file_offset), static_cast<std::size_t>(region->size));
  const std::span<const std::uint8_t> memory_bytes =
      text_memory.subspan(static_cast<std::size_t>(region->memory_address), static_cast<std::size_t>(region->size));

  // A packed library ships ciphertext where this digest was taken, so its file bytes can never match the decrypted
  // memory. The packer's fold ships the expected plaintext digest in `.rasp_config` instead; comparing the running
  // `.text` against it observes the same fact: the running code is the code that shipped.
  if (const std::optional<std::string> expected = expected_text_hash(image)) {
    const std::optional<std::string> memory_hash = sha256_hex(memory_bytes);
    return {
        observed(kTextHashSignal, kFileSource, *expected),
        memory_hash ? observed(kTextHashSignal, kMemorySource, *memory_hash) : failed(kTextHashSignal, kMemorySource),
    };
  }

  const std::optional<std::string> file_hash = sha256_hex(file_bytes);
  const std::optional<std::string> memory_hash = sha256_hex(memory_bytes);
  return {
      file_hash ? observed(kTextHashSignal, kFileSource, *file_hash) : failed(kTextHashSignal, kFileSource),
      memory_hash ? observed(kTextHashSignal, kMemorySource, *memory_hash) : failed(kTextHashSignal, kMemorySource),
  };
}

#ifdef __ANDROID__

namespace {

/// Where librasp.so is loaded: its on-disk path and its loaded image as a span starting at its load address.
struct LoadedLibrary {
  /// The path of the installed library file, under lib/<abi>/ inside the APK.
  std::string path;
  /// The load address of the library: its load bias, where the span of its image begins.
  std::uintptr_t load_bias = 0;
  /// The highest virtual address any of its loadable segments reaches, relative to the load address, which bounds the
  /// span of its image.
  std::uint64_t image_size = 0;
};

/// What dl_iterate_phdr looks for and fills in while it visits each loaded object.
struct LibrarySearch {
  /// The load address of librasp.so, found through a symbol in it.
  std::uintptr_t load_bias = 0;
  /// The library, set when the visitor finds the object whose load address matches.
  std::optional<LoadedLibrary> found;
};

/// Visits one loaded object: when its load address is the one being looked for, records its path and the extent of its
/// loadable segments. The callback dl_iterate_phdr runs for each object, so it takes C linkage and a void cookie.
// NOLINTNEXTLINE(misc-const-correctness): dl_iterate_phdr's callback takes a non-const dl_phdr_info* by its C signature.
[[nodiscard]] int visit_object(dl_phdr_info* info, std::size_t /*size*/, void* cookie) {
  auto* const search = static_cast<LibrarySearch*>(cookie);
  const dl_phdr_info& object = *info;
  if (object.dlpi_addr != search->load_bias || object.dlpi_name == nullptr) {
    return 0;
  }
  std::uint64_t image_size = 0;
  const std::span<const ElfW(Phdr)> headers(object.dlpi_phdr, object.dlpi_phnum);
  for (const ElfW(Phdr) & header : headers) {
    // NOLINTNEXTLINE(misc-include-cleaner): PT_LOAD comes from the included <link.h>.
    if (header.p_type == PT_LOAD) {
      image_size = std::max<std::uint64_t>(image_size, header.p_vaddr + header.p_memsz);
    }
  }
  search->found = LoadedLibrary{
      .path = object.dlpi_name,
      .load_bias = search->load_bias,
      .image_size = image_size,
  };
  return 1;
}

/// Finds where librasp.so is loaded, through the address of a symbol in it.
///
/// dladdr gives the library's load address from the address of `integrity`, a function in it, and dl_iterate_phdr then
/// gives the object with that load address: its path and the extent of its segments. Both are needed because dladdr
/// alone doesn't give the span of the image, and dl_iterate_phdr alone doesn't say which object is ours.
/// An object in this library, used only for its address: dladdr on it names librasp.so, with no function-pointer cast.
constexpr char kAnchor = 0;

[[nodiscard]] std::optional<LoadedLibrary> find_own_library() {
  Dl_info info{};
  if (dladdr(&kAnchor, &info) == 0 || info.dli_fbase == nullptr) {
    return std::nullopt;
  }
  LibrarySearch search{.load_bias = std::bit_cast<std::uintptr_t>(info.dli_fbase), .found = std::nullopt};
  dl_iterate_phdr(&visit_object, &search);
  return search.found;
}

}  // namespace

std::vector<Observation> integrity() {
  static constexpr std::array kObfuscatedLiterals = {kTextHashSignal, kFileSource, kMemorySource, kTextSectionName,
                                                     kConfigSectionName};
  rasp::util::anchor_literals(kObfuscatedLiterals);
  const std::optional<LoadedLibrary> library = find_own_library();
  if (!library || library->path.empty()) {
    return {failed(kTextHashSignal, kFileSource), failed(kTextHashSignal, kMemorySource)};
  }
  const std::span<const std::uint8_t> image(std::bit_cast<const std::uint8_t*>(library->load_bias),
                                            static_cast<std::size_t>(library->image_size));
  return observe_text_hashes(library->path, image);
}

#else

std::vector<Observation> integrity() {
  return {unsupported(kTextHashSignal, kFileSource), unsupported(kTextHashSignal, kMemorySource)};
}

#endif

}  // namespace rasp::android::checks
