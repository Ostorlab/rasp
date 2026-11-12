/// The ELF reader the Android checks share: it reads the headers, sections, loadable segments and dynamic symbols of a
/// little-endian ELF32 or ELF64 image held in memory, checking every offset and size against the image's bounds.

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace rasp::android::util {

/// EM_ARM, the machine of a 32-bit Arm image, whose Thumb function addresses carry the Thumb bit.
inline constexpr std::uint16_t kMachineArm = 40;

/// STT_FUNC, the symbol type of a function whose code starts at the symbol's value.
inline constexpr std::uint8_t kSymbolFunction = 2;

/// A table of ELF headers in an image: where it starts, how large each entry is, and how many entries it has.
struct ElfTable {
  /// The offset of the first entry in the file.
  std::uint64_t offset = 0;
  /// The size of one entry in bytes, as the ELF header declares it.
  std::uint16_t entry_size = 0;
  /// The number of entries.
  std::uint16_t count = 0;
};

/// The parts of an ELF header the readers need, read from an image and checked against the image's size.
struct ElfHeaders {
  /// Whether the image is ELF64. It is ELF32 otherwise.
  bool elf64 = false;
  /// The image's machine, `e_machine`, such as kMachineArm.
  std::uint16_t machine = 0;
  /// The section header table.
  ElfTable sections;
  /// The index of the section-name string table in the section header table, `e_shstrndx`.
  std::uint16_t section_names_index = 0;
  /// The program header table.
  ElfTable segments;
};

/// One section header, with the fields the readers need.
struct ElfSection {
  /// The offset of the section's name in the section-name string table.
  std::uint32_t name_offset = 0;
  /// The section's type, such as SHT_DYNSYM.
  std::uint32_t type = 0;
  /// The section's flags, such as SHF_ALLOC and SHF_WRITE.
  std::uint64_t flags = 0;
  /// The section's virtual address, relative to the image's load address.
  std::uint64_t address = 0;
  /// The offset of the section's bytes in the file.
  std::uint64_t file_offset = 0;
  /// The number of bytes in the section.
  std::uint64_t size = 0;
  /// The index of a section this one refers to: for a symbol table, its string table.
  std::uint32_t link = 0;
  /// The size of one entry, for a section that holds a table such as a symbol table.
  std::uint64_t entry_size = 0;
};

/// One dynamic symbol, with the fields the readers need.
struct ElfSymbol {
  /// The function size; zero means the ELF does not bound its extent.
  std::uint64_t size = 0;
  /// The symbol's value: for a function, the virtual address of its code, relative to the image's load address. On
  /// 32-bit Arm, the lowest bit of a Thumb function's value is set, and the code starts one byte lower.
  std::uint64_t value = 0;
  /// The symbol's type, the low four bits of `st_info`, such as kSymbolFunction.
  std::uint8_t type = 0;
};

/// A range of a loaded image's code, by virtual address.
struct CodeRange {
  /// The virtual address of the range's first byte, relative to the image's load address.
  std::uint64_t address = 0;
  /// The number of bytes in the range.
  std::uint64_t length = 0;
};

/// Where a range of a loaded image's code lies in the file.
struct CodeLocation {
  /// The offset in the file of the range's first byte.
  std::uint64_t file_offset = 0;
  /// How many bytes the file holds from that offset to the end of the segment's file part. At least the length asked
  /// for.
  std::uint64_t available = 0;
};

/// Reads the ELF header of `image`.
///
/// @param image The bytes of the ELF file, read whole.
/// @return The header's fields, or nothing when the image isn't a little-endian ELF32 or ELF64 file, is shorter than
/// its ELF header, or has no section or no program header.
[[nodiscard]] std::optional<ElfHeaders> read_elf_headers(std::span<const std::uint8_t> image);

/// Finds the section named `name` in `image`.
///
/// @param image The bytes of the ELF file, read whole.
/// @param headers The image's headers, from read_elf_headers.
/// @param name The section's name, such as `.text`.
/// @return The first section with that name, or nothing when there is none, or when the section-name string table or a
/// section header lies outside the image.
[[nodiscard]] std::optional<ElfSection> find_section(std::span<const std::uint8_t> image, const ElfHeaders& headers,
                                                     std::string_view name);

/// Finds the defined dynamic symbol named `name` in `image`.
///
/// It reads the symbols of the unique SHT_DYNSYM section and their names from the string table that section links to.
/// An undefined symbol, one that the image imports, is skipped.
///
/// @param image The bytes of the ELF file, read whole.
/// @param headers The image's headers, from read_elf_headers.
/// @param name The symbol's name, such as `open`.
/// @return The unique defined symbol with that name, or nothing for missing/duplicate/reserved definitions,
/// multiple or malformed symbol tables (maximum 65536 entries), or an out-of-bounds table/string range.
[[nodiscard]] std::optional<ElfSymbol> find_dynamic_symbol(std::span<const std::uint8_t> image,
                                                           const ElfHeaders& headers, std::string_view name);

/// Checks for loader-declared text relocations before comparing immutable code.
/// @param image The complete ELF image.
/// @param headers Validated ELF headers.
/// @return False for text relocations or malformed dynamic metadata, true otherwise.
[[nodiscard]] bool immutable_code(std::span<const std::uint8_t> image, const ElfHeaders& headers);

/// Finds where the code `range` lies in the file.
///
/// The range must lie wholly inside the file part of one loadable, executable, non-writable segment: the loader maps
/// such a segment unchanged, so its bytes in memory equal its bytes in the file. The part of a segment past the bytes
/// the file holds is zero-filled in memory, so a range that reaches into it has no file bytes to compare.
///
/// @param image The bytes of the ELF file, read whole.
/// @param headers The image's headers, from read_elf_headers.
/// @param range The range of code, by virtual address.
/// @return Where the range lies in the file, or nothing when no loadable, executable, non-writable segment holds the
/// whole range in its file part, or when that part lies outside the image.
[[nodiscard]] std::optional<CodeLocation> find_code(std::span<const std::uint8_t> image, const ElfHeaders& headers,
                                                    const CodeRange& range);

}  // namespace rasp::android::util
