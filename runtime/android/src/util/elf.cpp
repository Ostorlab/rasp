/// The ELF reader the Android checks share. It draws only on the standard ELF32 and ELF64 layouts.

#include "util/elf.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string_view>

namespace rasp::android::util {

namespace {

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
/// The offset of `e_machine` in the ELF header, the same in both classes.
constexpr std::size_t kMachineOffset = 0x12;

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
  /// The offset of `sh_type` in a section header.
  std::size_t sh_type = 0;
  /// The offset of `sh_flags` in a section header.
  std::size_t sh_flags = 0;
  /// The offset of `sh_addr` in a section header.
  std::size_t sh_addr = 0;
  /// The offset of `sh_offset` in a section header.
  std::size_t sh_offset = 0;
  /// The offset of `sh_size` in a section header.
  std::size_t sh_size = 0;
  /// The offset of `sh_link` in a section header.
  std::size_t sh_link = 0;
  /// The offset of `sh_entsize` in a section header.
  std::size_t sh_entsize = 0;
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
  /// The smallest symbol entry size the reader accepts: the size of one symbol.
  std::size_t symbol_size = 0;
  /// The offset of `st_name` in a symbol.
  std::size_t st_name = 0;
  /// The offset of `st_info` in a symbol.
  std::size_t st_info = 0;
  /// The offset of `st_shndx` in a symbol.
  std::size_t st_shndx = 0;
  /// The offset of `st_value` in a symbol.
  std::size_t st_value = 0;
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
    .sh_type = 0x04,
    .sh_flags = 0x08,
    .sh_addr = 0x0C,
    .sh_offset = 0x10,
    .sh_size = 0x14,
    .sh_link = 0x18,
    .sh_entsize = 0x24,
    .program_header_size = 32,
    .p_type = 0x00,
    .p_flags = 0x18,
    .p_offset = 0x04,
    .p_vaddr = 0x08,
    .p_filesz = 0x10,
    .symbol_size = 16,
    .st_name = 0x00,
    .st_info = 0x0C,
    .st_shndx = 0x0E,
    .st_value = 0x04,
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
    .sh_type = 0x04,
    .sh_flags = 0x08,
    .sh_addr = 0x10,
    .sh_offset = 0x18,
    .sh_size = 0x20,
    .sh_link = 0x28,
    .sh_entsize = 0x38,
    .program_header_size = 56,
    .p_type = 0x00,
    .p_flags = 0x04,
    .p_offset = 0x08,
    .p_vaddr = 0x10,
    .p_filesz = 0x20,
    .symbol_size = 24,
    .st_name = 0x00,
    .st_info = 0x04,
    .st_shndx = 0x06,
    .st_value = 0x08,
};

/// PT_LOAD, the program header type of a segment the loader maps into memory.
constexpr std::uint32_t kPtLoad = 1;
/// PF_X, the program header flag of an executable segment.
constexpr std::uint32_t kPfExecute = 0x1;
/// PF_W, the program header flag of a writable segment.
constexpr std::uint32_t kPfWrite = 0x2;
/// SHT_DYNSYM, the section type of the dynamic symbol table.
constexpr std::uint32_t kShtDynsym = 11;
/// SHN_UNDEF, the section index of an undefined symbol, one the image imports.
constexpr std::uint16_t kShnUndefined = 0;
/// The bits of `st_info` that hold a symbol's type.
constexpr std::uint8_t kSymbolTypeMask = 0x0F;

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

/// Reads a byte at `offset`, or nothing when the span is too short to hold it.
[[nodiscard]] std::optional<std::uint8_t> read_u8(std::span<const std::uint8_t> bytes, std::uint64_t offset) {
  return read_scalar<std::uint8_t>(bytes, offset);
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

/// The layout of the class `headers` describe.
[[nodiscard]] const ElfLayout& layout_of(const ElfHeaders& headers) {
  return headers.elf64 ? kElf64Layout : kElf32Layout;
}

/// The offset in the file of entry `index` of `table`, or nothing when the entry lies outside `image`.
[[nodiscard]] std::optional<std::uint64_t> entry_offset(std::span<const std::uint8_t> image, const ElfTable& table,
                                                        std::uint16_t index) {
  const std::uint64_t offset_in_table = std::uint64_t{index} * table.entry_size;
  if (!range_fits(table.offset, offset_in_table + table.entry_size, image.size())) {
    return std::nullopt;
  }
  return table.offset + offset_in_table;
}

/// Reads the section header `index` from `image`, or nothing when it lies outside the image.
[[nodiscard]] std::optional<ElfSection> read_section(std::span<const std::uint8_t> image, const ElfHeaders& headers,
                                                     std::uint16_t index) {
  const ElfLayout& layout = layout_of(headers);
  if (headers.sections.entry_size < layout.section_header_size) {
    return std::nullopt;
  }
  const std::optional<std::uint64_t> base = entry_offset(image, headers.sections, index);
  if (!base) {
    return std::nullopt;
  }
  const std::optional<std::uint32_t> name_offset = read_u32(image, *base + layout.sh_name);
  const std::optional<std::uint32_t> type = read_u32(image, *base + layout.sh_type);
  const std::optional<std::uint64_t> flags = read_word(image, *base + layout.sh_flags, layout);
  const std::optional<std::uint64_t> address = read_word(image, *base + layout.sh_addr, layout);
  const std::optional<std::uint64_t> file_offset = read_word(image, *base + layout.sh_offset, layout);
  const std::optional<std::uint64_t> size = read_word(image, *base + layout.sh_size, layout);
  const std::optional<std::uint32_t> link = read_u32(image, *base + layout.sh_link);
  const std::optional<std::uint64_t> entry_size = read_word(image, *base + layout.sh_entsize, layout);
  if (!name_offset || !type || !flags || !address || !file_offset || !size || !link || !entry_size) {
    return std::nullopt;
  }
  return ElfSection{
      .name_offset = *name_offset,
      .type = *type,
      .flags = *flags,
      .address = *address,
      .file_offset = *file_offset,
      .size = *size,
      .link = *link,
      .entry_size = *entry_size,
  };
}

/// Reads the loadable segment at program header `index`, or nothing when the entry lies outside the image or isn't a
/// PT_LOAD segment.
[[nodiscard]] std::optional<LoadSegment> read_load_segment(std::span<const std::uint8_t> image,
                                                           const ElfHeaders& headers, std::uint16_t index) {
  const ElfLayout& layout = layout_of(headers);
  if (headers.segments.entry_size < layout.program_header_size) {
    return std::nullopt;
  }
  const std::optional<std::uint64_t> base = entry_offset(image, headers.segments, index);
  if (!base) {
    return std::nullopt;
  }
  const std::optional<std::uint32_t> type = read_u32(image, *base + layout.p_type);
  if (!type || *type != kPtLoad) {
    return std::nullopt;
  }
  const std::optional<std::uint32_t> flags = read_u32(image, *base + layout.p_flags);
  const std::optional<std::uint64_t> file_offset = read_word(image, *base + layout.p_offset, layout);
  const std::optional<std::uint64_t> address = read_word(image, *base + layout.p_vaddr, layout);
  const std::optional<std::uint64_t> file_size = read_word(image, *base + layout.p_filesz, layout);
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

/// The bytes of `section`, or nothing when they lie outside `image`.
[[nodiscard]] std::optional<std::span<const std::uint8_t>> section_bytes(std::span<const std::uint8_t> image,
                                                                         const ElfSection& section) {
  if (!range_fits(section.file_offset, section.size, image.size())) {
    return std::nullopt;
  }
  return image.subspan(static_cast<std::size_t>(section.file_offset), static_cast<std::size_t>(section.size));
}

/// Whether the string at `offset` in the string table `strings` is `name`. The string is a run of bytes ending at the
/// first null; it is compared to `name` byte for byte, with no view that aliases the bytes as characters.
[[nodiscard]] bool string_at_is(std::span<const std::uint8_t> strings, std::uint64_t offset, std::string_view name) {
  if (offset >= strings.size()) {
    return false;
  }
  const std::span<const std::uint8_t> rest = strings.subspan(static_cast<std::size_t>(offset));
  const auto terminator = std::ranges::find(rest, std::uint8_t{0});
  if (terminator == rest.end()) {
    return false;
  }
  const auto length = static_cast<std::size_t>(terminator - rest.begin());
  return std::ranges::equal(rest.first(length), name, [](std::uint8_t byte, char character) {
    return byte == static_cast<std::uint8_t>(character);
  });
}

/// The first section of type `type` in `image`, or nothing when there is none or a section header can't be read.
[[nodiscard]] std::optional<ElfSection> find_section_of_type(std::span<const std::uint8_t> image,
                                                             const ElfHeaders& headers, std::uint32_t type) {
  for (std::uint16_t index = 0; index < headers.sections.count; ++index) {
    const std::optional<ElfSection> section = read_section(image, headers, index);
    if (!section) {
      return std::nullopt;
    }
    if (section->type == type) {
      return section;
    }
  }
  return std::nullopt;
}

/// One entry of a symbol table, with the fields the reader needs.
struct SymbolEntry {
  /// The offset of the symbol's name in the symbol table's string table.
  std::uint32_t name_offset = 0;
  /// Whether the image defines the symbol, rather than importing it.
  bool defined = false;
  /// The symbol's value and type.
  ElfSymbol symbol;
};

/// Reads the symbol at offset `base` of the symbol table `symbols` of the `layout` class, or nothing when it lies
/// outside the table.
[[nodiscard]] std::optional<SymbolEntry> read_symbol(std::span<const std::uint8_t> symbols, std::uint64_t base,
                                                     const ElfLayout& layout) {
  const std::optional<std::uint32_t> name_offset = read_u32(symbols, base + layout.st_name);
  const std::optional<std::uint8_t> info = read_u8(symbols, base + layout.st_info);
  const std::optional<std::uint16_t> section_index = read_u16(symbols, base + layout.st_shndx);
  const std::optional<std::uint64_t> value = read_word(symbols, base + layout.st_value, layout);
  if (!name_offset || !info || !section_index || !value) {
    return std::nullopt;
  }
  return SymbolEntry{
      .name_offset = *name_offset,
      .defined = *section_index != kShnUndefined,
      .symbol = {.value = *value, .type = static_cast<std::uint8_t>(*info & kSymbolTypeMask)},
  };
}

}  // namespace

std::optional<ElfHeaders> read_elf_headers(std::span<const std::uint8_t> image) {
  if (image.size() <= kDataOffset || !std::equal(kElfMagic.begin(), kElfMagic.end(), image.begin()) ||
      image[kDataOffset] != kElfLittleEndian) {
    return std::nullopt;
  }
  const bool elf64 = image[kClassOffset] == kElfClass64;
  if (!elf64 && image[kClassOffset] != kElfClass32) {
    return std::nullopt;
  }
  const ElfLayout& layout = elf64 ? kElf64Layout : kElf32Layout;
  if (image.size() < layout.header_size) {
    return std::nullopt;
  }
  const std::optional<std::uint16_t> machine = read_u16(image, kMachineOffset);
  const std::optional<std::uint64_t> section_offset = read_word(image, layout.shoff, layout);
  const std::optional<std::uint16_t> section_entry_size = read_u16(image, layout.shentsize);
  const std::optional<std::uint16_t> section_count = read_u16(image, layout.shnum);
  const std::optional<std::uint16_t> section_names_index = read_u16(image, layout.shstrndx);
  const std::optional<std::uint64_t> segment_offset = read_word(image, layout.phoff, layout);
  const std::optional<std::uint16_t> segment_entry_size = read_u16(image, layout.phentsize);
  const std::optional<std::uint16_t> segment_count = read_u16(image, layout.phnum);
  if (!machine || !section_offset || !section_entry_size || !section_count || !section_names_index || !segment_offset ||
      !segment_entry_size || !segment_count || *section_count == 0 || *segment_count == 0) {
    return std::nullopt;
  }
  return ElfHeaders{
      .elf64 = elf64,
      .machine = *machine,
      .sections = {.offset = *section_offset, .entry_size = *section_entry_size, .count = *section_count},
      .section_names_index = *section_names_index,
      .segments = {.offset = *segment_offset, .entry_size = *segment_entry_size, .count = *segment_count},
  };
}

std::optional<ElfSection> find_section(std::span<const std::uint8_t> image, const ElfHeaders& headers,
                                       std::string_view name) {
  if (headers.section_names_index >= headers.sections.count) {
    return std::nullopt;
  }
  const std::optional<ElfSection> names_section = read_section(image, headers, headers.section_names_index);
  if (!names_section) {
    return std::nullopt;
  }
  const std::optional<std::span<const std::uint8_t>> names = section_bytes(image, *names_section);
  if (!names) {
    return std::nullopt;
  }
  for (std::uint16_t index = 0; index < headers.sections.count; ++index) {
    const std::optional<ElfSection> section = read_section(image, headers, index);
    if (!section) {
      return std::nullopt;
    }
    if (string_at_is(*names, section->name_offset, name)) {
      return section;
    }
  }
  return std::nullopt;
}

std::optional<ElfSymbol> find_dynamic_symbol(std::span<const std::uint8_t> image, const ElfHeaders& headers,
                                             std::string_view name) {
  const ElfLayout& layout = layout_of(headers);
  const std::optional<ElfSection> symbol_section = find_section_of_type(image, headers, kShtDynsym);
  if (!symbol_section || symbol_section->entry_size < layout.symbol_size ||
      symbol_section->link >= headers.sections.count) {
    return std::nullopt;
  }
  const std::optional<ElfSection> names_section =
      read_section(image, headers, static_cast<std::uint16_t>(symbol_section->link));
  if (!names_section) {
    return std::nullopt;
  }
  const std::optional<std::span<const std::uint8_t>> symbols = section_bytes(image, *symbol_section);
  const std::optional<std::span<const std::uint8_t>> names = section_bytes(image, *names_section);
  if (!symbols || !names) {
    return std::nullopt;
  }
  const std::uint64_t count = symbols->size() / symbol_section->entry_size;
  for (std::uint64_t index = 0; index < count; ++index) {
    const std::optional<SymbolEntry> entry = read_symbol(*symbols, index * symbol_section->entry_size, layout);
    if (entry && entry->defined && string_at_is(*names, entry->name_offset, name)) {
      return entry->symbol;
    }
  }
  return std::nullopt;
}

std::optional<CodeLocation> find_code(std::span<const std::uint8_t> image, const ElfHeaders& headers,
                                      const CodeRange& range) {
  for (std::uint16_t index = 0; index < headers.segments.count; ++index) {
    const std::optional<LoadSegment> segment = read_load_segment(image, headers, index);
    if (!segment || !segment->executable_read_only || range.address < segment->address) {
      continue;
    }
    const std::uint64_t offset_in_segment = range.address - segment->address;
    if (!range_fits(offset_in_segment, range.length, segment->file_size) ||
        !range_fits(segment->file_offset, offset_in_segment, image.size())) {
      continue;
    }
    const std::uint64_t file_offset = segment->file_offset + offset_in_segment;
    if (!range_fits(file_offset, range.length, image.size())) {
      continue;
    }
    return CodeLocation{
        .file_offset = file_offset,
        .available = std::min(segment->file_size - offset_in_segment, image.size() - file_offset),
    };
  }
  return std::nullopt;
}

}  // namespace rasp::android::util
