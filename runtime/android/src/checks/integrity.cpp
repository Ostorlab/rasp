/// The Android integrity check: the file and memory hashes of librasp.so's `.text`, and its unsupported result off
/// Android. The ELF reader draws only on the standard ELF64 layout.

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
#include <vector>

#include "rasp/observation.h"
#include "util/apk_file.h"

#ifdef __ANDROID__
#include <bit>
#include <dlfcn.h>
#include <link.h>
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

/// The length of a SHA-256 digest, in bytes.
constexpr std::size_t kDigestSize = 32;

/// The ELF identification bytes this reader accepts: the magic, 64-bit class, little-endian data.
constexpr std::array<std::uint8_t, 6> kElfIdentifier = {0x7F, 'E', 'L', 'F', 2, 1};

/// The offsets of the ELF64 header fields the reader uses, and the sizes it checks against.
constexpr std::size_t kElfHeaderSize = 64;
constexpr std::size_t kPhoffOffset = 0x20;
constexpr std::size_t kShoffOffset = 0x28;
constexpr std::size_t kPhentSizeOffset = 0x36;
constexpr std::size_t kPhnumOffset = 0x38;
constexpr std::size_t kShentSizeOffset = 0x3A;
constexpr std::size_t kShnumOffset = 0x3C;
constexpr std::size_t kShstrndxOffset = 0x3E;

/// The offsets of the ELF64 section header fields the reader uses, and the entry size it expects.
constexpr std::size_t kSectionHeaderSize = 64;
constexpr std::size_t kShNameOffset = 0x00;
constexpr std::size_t kShFlagsOffset = 0x08;
constexpr std::size_t kShAddrOffset = 0x10;
constexpr std::size_t kShOffsetOffset = 0x18;
constexpr std::size_t kShSizeOffset = 0x20;

/// The offsets of the ELF64 program header fields the reader uses, and the entry size it expects.
constexpr std::size_t kProgramHeaderSize = 56;
constexpr std::size_t kPhTypeOffset = 0x00;
constexpr std::size_t kPhFlagsOffset = 0x04;
constexpr std::size_t kPhOffsetOffset = 0x08;
constexpr std::size_t kPhVaddrOffset = 0x10;
constexpr std::size_t kPhFileszOffset = 0x20;

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
template <typename T>
[[nodiscard]] std::optional<T> read_scalar(std::span<const std::uint8_t> bytes, std::size_t offset) {
  if (!range_fits(offset, sizeof(T), bytes.size())) {
    return std::nullopt;
  }
  T value = 0;
  std::memcpy(&value, bytes.subspan(offset, sizeof(T)).data(), sizeof(T));
  return value;
}

/// Reads a little-endian 16-bit number at `offset`, or nothing when the span is too short to hold it.
[[nodiscard]] std::optional<std::uint16_t> read_u16(std::span<const std::uint8_t> bytes, std::size_t offset) {
  return read_scalar<std::uint16_t>(bytes, offset);
}

/// Reads a little-endian 32-bit number at `offset`, or nothing when the span is too short to hold it.
[[nodiscard]] std::optional<std::uint32_t> read_u32(std::span<const std::uint8_t> bytes, std::size_t offset) {
  return read_scalar<std::uint32_t>(bytes, offset);
}

/// Reads a little-endian 64-bit number at `offset`, or nothing when the span is too short to hold it.
[[nodiscard]] std::optional<std::uint64_t> read_u64(std::span<const std::uint8_t> bytes, std::size_t offset) {
  return read_scalar<std::uint64_t>(bytes, offset);
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

/// Reads the section header `index` from `image`, given the section header `table`.
[[nodiscard]] std::optional<SectionHeader> read_section_header(std::span<const std::uint8_t> image,
                                                               const HeaderTable& table, std::uint16_t index) {
  if (table.entry_size < kSectionHeaderSize) {
    return std::nullopt;
  }
  const std::uint64_t offset_in_table = std::uint64_t{index} * table.entry_size;
  if (!range_fits(table.offset, offset_in_table + table.entry_size, image.size())) {
    return std::nullopt;
  }
  const std::uint64_t base = table.offset + offset_in_table;
  const std::optional<std::uint32_t> name_offset = read_u32(image, base + kShNameOffset);
  const std::optional<std::uint64_t> flags = read_u64(image, base + kShFlagsOffset);
  const std::optional<std::uint64_t> address = read_u64(image, base + kShAddrOffset);
  const std::optional<std::uint64_t> file_offset = read_u64(image, base + kShOffsetOffset);
  const std::optional<std::uint64_t> size = read_u64(image, base + kShSizeOffset);
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

/// Reads the loadable segment at program header `index`, or nothing when the index is past the table, the entry can't
/// be read, or the entry isn't a PT_LOAD segment.
[[nodiscard]] std::optional<LoadSegment> read_load_segment(std::span<const std::uint8_t> image,
                                                           const HeaderTable& table, std::uint16_t index) {
  if (table.entry_size < kProgramHeaderSize) {
    return std::nullopt;
  }
  const std::uint64_t offset_in_table = std::uint64_t{index} * table.entry_size;
  if (!range_fits(table.offset, offset_in_table + table.entry_size, image.size())) {
    return std::nullopt;
  }
  const std::uint64_t base = table.offset + offset_in_table;
  const std::optional<std::uint32_t> type = read_u32(image, base + kPhTypeOffset);
  if (!type || *type != kPtLoad) {
    return std::nullopt;
  }
  const std::optional<std::uint32_t> flags = read_u32(image, base + kPhFlagsOffset);
  const std::optional<std::uint64_t> file_offset = read_u64(image, base + kPhOffsetOffset);
  const std::optional<std::uint64_t> address = read_u64(image, base + kPhVaddrOffset);
  const std::optional<std::uint64_t> file_size = read_u64(image, base + kPhFileszOffset);
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

/// The `.text` section header of `image`, found through the section header `table` and the string table at
/// `strtab_index`, or nothing when the image has no section with that name.
[[nodiscard]] std::optional<SectionHeader> find_text_section(std::span<const std::uint8_t> image,
                                                             const HeaderTable& table, std::uint16_t strtab_index) {
  if (strtab_index >= table.count) {
    return std::nullopt;
  }
  const std::optional<SectionHeader> strtab_header = read_section_header(image, table, strtab_index);
  if (!strtab_header || !range_fits(strtab_header->file_offset, strtab_header->size, image.size())) {
    return std::nullopt;
  }
  const std::span<const std::uint8_t> strtab = image.subspan(static_cast<std::size_t>(strtab_header->file_offset),
                                                             static_cast<std::size_t>(strtab_header->size));
  for (std::uint16_t index = 0; index < table.count; ++index) {
    const std::optional<SectionHeader> header = read_section_header(image, table, index);
    if (!header) {
      return std::nullopt;
    }
    if (section_named(strtab, *header, kTextSectionName)) {
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
/// the program header `table`.
[[nodiscard]] bool text_is_backed_by_file(std::span<const std::uint8_t> image, const HeaderTable& table,
                                          const SectionHeader& text) {
  for (std::uint16_t index = 0; index < table.count; ++index) {
    const std::optional<LoadSegment> segment = read_load_segment(image, table, index);
    if (segment && fits_in_file_part(*segment, text)) {
      return true;
    }
  }
  return false;
}

}  // namespace

std::optional<TextRegion> find_text_region(std::span<const std::uint8_t> image, std::uintptr_t load_bias) {
  if (image.size() < kElfHeaderSize || !std::equal(kElfIdentifier.begin(), kElfIdentifier.end(), image.begin())) {
    return std::nullopt;
  }
  const std::optional<std::uint64_t> section_offset = read_u64(image, kShoffOffset);
  const std::optional<std::uint16_t> section_entry_size = read_u16(image, kShentSizeOffset);
  const std::optional<std::uint16_t> section_count = read_u16(image, kShnumOffset);
  const std::optional<std::uint16_t> strtab_index = read_u16(image, kShstrndxOffset);
  const std::optional<std::uint64_t> program_offset = read_u64(image, kPhoffOffset);
  const std::optional<std::uint16_t> program_entry_size = read_u16(image, kPhentSizeOffset);
  const std::optional<std::uint16_t> program_count = read_u16(image, kPhnumOffset);
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

  const std::optional<SectionHeader> text = find_text_section(image, section_table, *strtab_index);
  if (!text || text->size == 0 || (text->flags & kShfAlloc) == 0U || (text->flags & kShfWrite) != 0U ||
      !range_fits(text->file_offset, text->size, image.size())) {
    return std::nullopt;
  }
  if (!text_is_backed_by_file(image, program_table, *text)) {
    return std::nullopt;
  }

  return TextRegion{
      .file_offset = text->file_offset,
      .memory_address = load_bias + static_cast<std::uintptr_t>(text->address),
      .size = text->size,
  };
}

std::optional<std::string> sha256_hex(std::span<const std::uint8_t> bytes) {
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
  constexpr std::string_view kDigits = "0123456789abcdef";
  std::string hex;
  hex.reserve(digest.size() * 2);
  for (const std::uint8_t byte : digest) {
    hex.push_back(kDigits[byte >> 4U]);
    hex.push_back(kDigits[byte & 0x0FU]);
  }
  return hex;
}

std::vector<Observation> observe_text_hashes(std::string_view library_path, std::span<const std::uint8_t> text_memory) {
  const std::optional<std::string> file = read_library_file(library_path, kMaxLibrarySize);
  if (!file) {
    return {failed(kTextHashSignal, kFileSource), failed(kTextHashSignal, kMemorySource)};
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): the file's characters are read as raw octets.
  const std::span<const std::uint8_t> image(reinterpret_cast<const std::uint8_t*>(file->data()), file->size());
  const std::optional<TextRegion> region = find_text_region(image, 0);
  if (!region || region->memory_address > text_memory.size() ||
      region->size > text_memory.size() - region->memory_address) {
    return {failed(kTextHashSignal, kFileSource), failed(kTextHashSignal, kMemorySource)};
  }

  const std::span<const std::uint8_t> file_bytes =
      image.subspan(static_cast<std::size_t>(region->file_offset), static_cast<std::size_t>(region->size));
  const std::span<const std::uint8_t> memory_bytes =
      text_memory.subspan(static_cast<std::size_t>(region->memory_address), static_cast<std::size_t>(region->size));
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
  /// The path of the installed library file, under lib/arm64-v8a/ inside the APK.
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
// NOLINTNEXTLINE(misc-const-correctness): dl_iterate_phdr's callback takes a non-const dl_phdr_info* by its C
// signature.
[[nodiscard]] int visit_object(dl_phdr_info* info, std::size_t /*size*/, void* cookie) {
  auto* const search = static_cast<LibrarySearch*>(cookie);
  if (info->dlpi_addr != search->load_bias || info->dlpi_name == nullptr) {
    return 0;
  }
  std::uint64_t image_size = 0;
  const std::span<const ElfW(Phdr)> headers(info->dlpi_phdr, info->dlpi_phnum);
  for (const ElfW(Phdr) & header : headers) {
    // NOLINTNEXTLINE(misc-include-cleaner): PT_LOAD comes from the included <link.h>.
    if (header.p_type == PT_LOAD) {
      image_size = std::max<std::uint64_t>(image_size, header.p_vaddr + header.p_memsz);
    }
  }
  search->found = LoadedLibrary{
      .path = info->dlpi_name,
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
[[nodiscard]] std::optional<LoadedLibrary> find_own_library() {
  Dl_info info{};
  std::vector<Observation> (*const own_symbol)() = &integrity;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): dladdr needs the address of a symbol in this library.
  if (dladdr(reinterpret_cast<const void*>(own_symbol), &info) == 0 || info.dli_fbase == nullptr) {
    return std::nullopt;
  }
  LibrarySearch search{.load_bias = std::bit_cast<std::uintptr_t>(info.dli_fbase), .found = std::nullopt};
  dl_iterate_phdr(&visit_object, &search);
  return search.found;
}

}  // namespace

std::vector<Observation> integrity() {
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
