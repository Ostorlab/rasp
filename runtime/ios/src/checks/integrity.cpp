/// The iOS code-integrity check: the layout of the `__TEXT,__text` section, the file and memory hashes of the runtime's
/// own image, and their unsupported result off a physical device. The Mach-O image is read through util/macho.h, and
/// the segment, section and encryption load commands draw only on the standard layout of `<mach-o/loader.h>`.

#include "checks/integrity.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <fcntl.h>
#include <limits>
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
#include <bit>
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#endif

namespace rasp::ios::checks {

namespace {

#if defined(__APPLE__) && TARGET_OS_IOS && !TARGET_OS_SIMULATOR
/// Whether this build runs on a physical iOS device, the only place the check means anything.
constexpr bool kPhysicalDevice = true;
#else
/// Whether this build runs on a physical iOS device, the only place the check means anything.
constexpr bool kPhysicalDevice = false;
#endif

/// The signal of the check: the hash of the runtime's own executable code.
constexpr std::string_view kTextHashSignal = "integ.text_sha256";
/// The source that reads the hash from the framework's file.
constexpr std::string_view kFileSource = "file";
/// The source that reads the hash from the process's memory.
constexpr std::string_view kMemorySource = "memory";

/// The largest `__text` section the check reads from the file. The runtime's is well under this, and the limit bounds
/// what the read allocates for a forged file.
constexpr std::uint64_t kMaxTextSize = std::uint64_t{64} << 20U;

/// `LC_SEGMENT_64`, the load command of a 64-bit segment.
constexpr std::uint32_t kSegmentCommand = 0x19;
/// `LC_ENCRYPTION_INFO_64`, the load command of a 64-bit image's encrypted range.
constexpr std::uint32_t kEncryptionInfoCommand = 0x2C;
/// The size of the fixed fields of a `segment_command_64`, before its sections, in bytes.
constexpr std::size_t kSegmentCommandSize = 72;
/// The size of a `section_64`, in bytes.
constexpr std::size_t kSectionSize = 80;
/// The size of an `encryption_info_command_64`, in bytes.
constexpr std::size_t kEncryptionInfoCommandSize = 24;
/// The size of a segment or section name field, in bytes.
constexpr std::size_t kNameSize = 16;
/// The offset of a segment's name, `segname`, in a `segment_command_64`.
constexpr std::size_t kSegmentNameOffset = 8;
/// The offset of a segment's address, `vmaddr`, in a `segment_command_64`.
constexpr std::size_t kSegmentAddressOffset = 24;
/// The offset of a segment's size in memory, `vmsize`, in a `segment_command_64`.
constexpr std::size_t kSegmentSizeOffset = 32;
/// The offset of a segment's file offset, `fileoff`, in a `segment_command_64`.
constexpr std::size_t kSegmentFileOffsetOffset = 40;
/// The offset of a segment's size in the file, `filesize`, in a `segment_command_64`.
constexpr std::size_t kSegmentFileSizeOffset = 48;
/// The offset of a segment's number of sections, `nsects`, in a `segment_command_64`.
constexpr std::size_t kSectionCountOffset = 64;
/// The offset of a section's name, `sectname`, in a `section_64`.
constexpr std::size_t kSectionNameOffset = 0;
/// The offset of the name of a section's segment, `segname`, in a `section_64`.
constexpr std::size_t kSectionSegmentNameOffset = 16;
/// The offset of a section's address, `addr`, in a `section_64`.
constexpr std::size_t kSectionAddressOffset = 32;
/// The offset of a section's size, `size`, in a `section_64`.
constexpr std::size_t kSectionSizeOffset = 40;
/// The offset of a section's file offset, `offset`, in a `section_64`.
constexpr std::size_t kSectionFileOffsetOffset = 48;
/// The offset of an image's encryption flag, `cryptid`, in an `encryption_info_command_64`.
constexpr std::size_t kCryptIdOffset = 16;
/// The name of the segment that holds the executable code.
constexpr std::string_view kTextSegmentName = "__TEXT";
/// The name of the section that holds the executable code.
constexpr std::string_view kTextSectionName = "__text";

/// Whether the fixed-size name field `field` holds `name`: its bytes, then NUL padding to the end of the field, or
/// exactly its bytes when they fill the field.
///
/// @param field The name field, kNameSize bytes.
/// @param name The name to compare with.
/// @return `true` when the field holds `name`.
[[nodiscard]] bool name_is(std::span<const std::uint8_t> field, std::string_view name) {
  if (name.size() > field.size()) {
    return false;
  }
  const bool same_bytes = std::ranges::equal(field.first(name.size()), name, [](std::uint8_t byte, char character) {
    return byte == static_cast<std::uint8_t>(character);
  });
  return same_bytes && std::ranges::all_of(field.subspan(name.size()), [](std::uint8_t byte) { return byte == 0; });
}

/// The `__text` section of a `__TEXT` segment, with the fields the check uses.
struct Section {
  /// The section's address before the slide, its `addr`.
  std::uint64_t address = 0;
  /// The number of bytes in the section, its `size`.
  std::uint64_t size = 0;
  /// The offset of the section's bytes in the file, its `offset`.
  std::uint64_t file_offset = 0;
};

/// The `__TEXT` segment, with the fields the check uses and its `__text` section.
struct TextSegment {
  /// The segment's address before the slide, its `vmaddr`.
  std::uint64_t address = 0;
  /// The segment's size in memory, its `vmsize`.
  std::uint64_t size = 0;
  /// The segment's offset in the file, its `fileoff`.
  std::uint64_t file_offset = 0;
  /// The number of the segment's bytes the file holds, its `filesize`.
  std::uint64_t file_size = 0;
  /// The segment's `__text` section.
  Section text;
};

/// Finds the one `__text` section among the sections of the `__TEXT` segment load command `command`.
///
/// @param command The bytes of the segment load command, at least kSegmentCommandSize long.
/// @param count The number of sections, the segment's `nsects`, which fit in `command`.
/// @return The section, or nothing when a field can't be read, or when the segment has no section named `__text` with
/// the segment name `__TEXT`, or more than one.
[[nodiscard]] std::optional<Section> find_text_section(std::span<const std::uint8_t> command, std::uint32_t count) {
  std::optional<Section> found;
  for (std::uint32_t index = 0; index < count; ++index) {
    const std::span<const std::uint8_t> section =
        command.subspan(kSegmentCommandSize + (std::size_t{index} * kSectionSize), kSectionSize);
    if (!name_is(section.subspan(kSectionNameOffset, kNameSize), kTextSectionName) ||
        !name_is(section.subspan(kSectionSegmentNameOffset, kNameSize), kTextSegmentName)) {
      continue;
    }
    const std::optional<std::uint64_t> address = util::read_little_endian_64(section, kSectionAddressOffset);
    const std::optional<std::uint64_t> size = util::read_little_endian_64(section, kSectionSizeOffset);
    const std::optional<std::uint32_t> file_offset = util::read_little_endian(section, kSectionFileOffsetOffset);
    const auto flags = util::read_little_endian(section, 64);
    if (found.has_value() || !address.has_value() || !size.has_value() || !file_offset.has_value() ||
        util::read_little_endian(section, 60) != 0U || !flags.has_value() || (*flags & 0x800003FFU) != 0x80000000U) {
      return std::nullopt;
    }
    found = Section{.address = *address, .size = *size, .file_offset = *file_offset};
  }
  return found;
}

/// Reads the `__TEXT` segment load command `command` and its `__text` section.
///
/// @param command The bytes of a segment load command named `__TEXT`, at least kSegmentCommandSize long.
/// @return The segment, or nothing when a field can't be read, its sections don't fit in the load command, or
/// find_text_section finds no single `__text` section.
[[nodiscard]] std::optional<TextSegment> read_text_segment(std::span<const std::uint8_t> command) {
  const std::optional<std::uint64_t> address = util::read_little_endian_64(command, kSegmentAddressOffset);
  const std::optional<std::uint64_t> size = util::read_little_endian_64(command, kSegmentSizeOffset);
  const std::optional<std::uint64_t> file_offset = util::read_little_endian_64(command, kSegmentFileOffsetOffset);
  const std::optional<std::uint64_t> file_size = util::read_little_endian_64(command, kSegmentFileSizeOffset);
  const std::optional<std::uint32_t> section_count = util::read_little_endian(command, kSectionCountOffset);
  if (!address.has_value() || !size.has_value() || !file_offset.has_value() || !file_size.has_value() ||
      !section_count.has_value() || util::read_little_endian(command, 60) != 5U ||
      (command.size() - kSegmentCommandSize) / kSectionSize < *section_count) {
    return std::nullopt;
  }
  const std::optional<Section> text = find_text_section(command, *section_count);
  if (!text.has_value()) {
    return std::nullopt;
  }
  return TextSegment{
      .address = *address,
      .size = *size,
      .file_offset = *file_offset,
      .file_size = *file_size,
      .text = *text,
  };
}

/// Whether the `__TEXT` segment `segment` is laid out as dyld maps it, with its `__text` section's file bytes at the
/// section's address.
///
/// @param segment The `__TEXT` segment and its `__text` section.
/// @param header_and_commands_size The size of the image's header and load commands, in bytes.
/// @return `true` when the segment starts at file offset 0 and its mapped file part, the first `min(vmsize,
/// filesize)` bytes, holds the header and load commands and the whole non-empty section, and the section's file
/// offset is its offset in the segment.
[[nodiscard]] bool is_mapped_from_file(const TextSegment& segment, std::uint64_t header_and_commands_size) {
  const std::uint64_t mapped_size = std::min(segment.size, segment.file_size);
  if (segment.file_offset != 0 || header_and_commands_size > mapped_size || segment.text.size == 0 ||
      segment.text.address < segment.address || segment.text.file_offset < header_and_commands_size ||
      !util::range_fits(segment.address, segment.size, std::numeric_limits<std::uint64_t>::max())) {
    return false;
  }
  const std::uint64_t offset_in_segment = segment.text.address - segment.address;
  return util::range_fits(offset_in_segment, segment.text.size, mapped_size) &&
         segment.text.file_offset == offset_in_segment;
}

/// Finds the one `__TEXT` segment load command among `commands` and reads it.
///
/// @param commands The load commands of the image, as util::load_commands splits them.
/// @return The segment, or nothing when a segment load command is shorter than its fixed fields, when there is no
/// segment named `__TEXT` or more than one, or when read_text_segment gives nothing for it.
[[nodiscard]] std::optional<TextSegment> find_text_segment(std::span<const util::LoadCommand> commands) {
  std::optional<TextSegment> found;
  for (const util::LoadCommand& command : commands) {
    if (command.command != kSegmentCommand) {
      continue;
    }
    if (command.bytes.size() < kSegmentCommandSize) {
      return std::nullopt;
    }
    if (!name_is(command.bytes.subspan(kSegmentNameOffset, kNameSize), kTextSegmentName)) {
      continue;
    }
    if (found.has_value()) {
      return std::nullopt;
    }
    found = read_text_segment(command.bytes);
    if (!found.has_value()) {
      return std::nullopt;
    }
  }
  return found;
}

/// Whether an `LC_ENCRYPTION_INFO_64` load command among `commands` marks the image as encrypted.
///
/// @param commands The load commands of the image, as util::load_commands splits them.
/// @return `true` when one has a `cryptid` other than 0, `false` when none does or there is none, or nothing when one
/// is shorter than an `encryption_info_command_64`.
[[nodiscard]] std::optional<bool> is_encrypted(std::span<const util::LoadCommand> commands) {
  bool encrypted = false;
  for (const util::LoadCommand& command : commands) {
    if (command.command != kEncryptionInfoCommand) {
      continue;
    }
    const std::optional<std::uint32_t> crypt_id = command.bytes.size() < kEncryptionInfoCommandSize
                                                      ? std::nullopt
                                                      : util::read_little_endian(command.bytes, kCryptIdOffset);
    if (!crypt_id.has_value()) {
      return std::nullopt;
    }
    encrypted = encrypted || *crypt_id != 0;
  }
  return encrypted;
}

/// The most bytes accepted in each loader-fixup stream.
constexpr std::uint32_t kMaxFixupSize = 1U << 20U;

/// Reads a bounded linkedit payload with checked offsets before converting to off_t.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> read_payload(int file, std::uint32_t offset,
                                                                    std::uint32_t length, std::size_t file_size) {
  if (length > kMaxFixupSize || !util::range_fits(offset, length, file_size)) {
    return std::nullopt;
  }
  std::vector<std::uint8_t> bytes(length);
  if (!util::read_exactly(file, offset, bytes)) {
    return std::nullopt;
  }
  return bytes;
}

/// Reads a LEB operand with a strict 64-bit bound, optionally permitting signed addends.
[[nodiscard]] std::optional<std::uint64_t> read_leb(std::span<const std::uint8_t> bytes, std::size_t& offset,
                                                    bool is_signed = false) {
  std::uint64_t value = 0;
  for (std::size_t index = 0; index < 10 && offset < bytes.size(); ++index) {
    const std::uint8_t byte = bytes[offset++];
    if (index == 9 && byte != 0 && byte != 1 && (!is_signed || byte != 0x7F)) {
      return std::nullopt;
    }
    value |= std::uint64_t{byte & 0x7FU} << (index * 7);
    if ((byte & 0x80U) == 0) {
      return value;
    }
  }
  return std::nullopt;
}

/// The current target of classic dyld pointer fixups.
struct FixupTarget {
  /// Whether a segment was selected before the write.
  bool selected = false;
  /// Current segment-relative offset.
  std::uint64_t offset = 0;
  /// Maximum segment-relative offset.
  std::uint64_t size = 0;
};

/// A bounded sequence of pointer writes, without expanding loader loops.
struct FixupWrites {
  /// Number of writes.
  std::uint64_t count = 1;
  /// Additional bytes skipped after each pointer.
  std::uint64_t skip = 0;
};

/// Advances a fixup target without wrapping or escaping the segment.
[[nodiscard]] bool advance_target(FixupTarget& target, std::uint64_t amount) {
  if (!target.selected || !util::range_fits(target.offset, amount, target.size)) {
    return false;
  }
  target.offset += amount;
  return true;
}

/// Bounds every repeated pointer write and its subsequent advance in constant time.
[[nodiscard]] Status write_target(FixupTarget& target, FixupWrites writes) {
  if (!target.selected || writes.skip > std::numeric_limits<std::uint64_t>::max() - 8) {
    return Status::kError;
  }
  const std::uint64_t stride = writes.skip + 8;
  return writes.count <= (target.size - target.offset) / stride && advance_target(target, writes.count * stride)
             ? Status::kOk
             : Status::kError;
}

/// Loader state shared by classic bind and rebase streams.
struct DyldStream {
  /// Bounded stream bytes.
  std::span<const std::uint8_t> bytes;
  /// Segment virtual sizes, in load-command order.
  std::span<const std::uint64_t> segment_sizes;
  /// Segment index that must never contain loader writes.
  std::uint32_t text_index = 0;
  /// Next opcode or operand.
  std::size_t cursor = 0;
  /// Current loader target.
  FixupTarget target{};
};

/// Selects a valid non-text target from a segment-relative ULEB offset.
[[nodiscard]] Status select_target(DyldStream& stream, std::uint8_t index) {
  const auto offset = read_leb(stream.bytes, stream.cursor);
  if (!offset.has_value() || index >= stream.segment_sizes.size() || *offset > stream.segment_sizes[index]) {
    return Status::kError;
  }
  if (index == stream.text_index) {
    return Status::kUnsupported;
  }
  stream.target = {.selected = true, .offset = *offset, .size = stream.segment_sizes[index]};
  return Status::kOk;
}

/// Reads the operands for the three variable-count or variable-skip pointer-write opcodes.
[[nodiscard]] Status write_operands(DyldStream& stream, std::uint8_t opcode) {
  const auto first = read_leb(stream.bytes, stream.cursor);
  if (!first.has_value()) {
    return Status::kError;
  }
  if (opcode == 0x60) {
    return write_target(stream.target, {.count = *first});
  }
  if (opcode == 0x70) {
    return write_target(stream.target, {.skip = *first});
  }
  const auto skip = read_leb(stream.bytes, stream.cursor);
  return skip.has_value() ? write_target(stream.target, {.count = *first, .skip = *skip}) : Status::kError;
}

/// Validates one rebase operation; type-32 fixups and unknown opcodes are explicitly unsupported.
[[nodiscard]] Status rebase_opcode(DyldStream& stream, std::uint8_t byte) {
  const std::uint8_t immediate = byte & 0x0FU;
  switch (byte & 0xF0U) {
    case 0x00:
      stream.target.selected = false;
      return Status::kOk;
    case 0x10:
      return immediate == 1 ? Status::kOk : Status::kUnsupported;
    case 0x20:
      return select_target(stream, immediate);
    case 0x30: {
      const auto amount = read_leb(stream.bytes, stream.cursor);
      return amount.has_value() && advance_target(stream.target, *amount) ? Status::kOk : Status::kError;
    }
    case 0x40:
      return advance_target(stream.target, std::uint64_t{immediate} * 8) ? Status::kOk : Status::kError;
    case 0x50:
      return write_target(stream.target, {.count = immediate});
    case 0x60:
    case 0x70:
    case 0x80:
      return write_operands(stream, byte & 0xF0U);
    default:
      return Status::kUnsupported;
  }
}

/// Consumes a terminated symbol name without allocating or reading beyond the stream.
[[nodiscard]] Status skip_symbol(DyldStream& stream) {
  while (stream.cursor < stream.bytes.size()) {
    if (stream.bytes[stream.cursor++] == 0) {
      return Status::kOk;
    }
  }
  return Status::kError;
}

/// Validates a bind opcode, translating its pointer operations to the corresponding rebase operation.
[[nodiscard]] Status bind_opcode(DyldStream& stream, std::uint8_t byte) {
  const std::uint8_t immediate = byte & 0x0FU;
  switch (byte & 0xF0U) {
    case 0x00:
      return rebase_opcode(stream, 0);
    case 0x10:
    case 0x30:
      return Status::kOk;
    case 0x20:
    case 0x60:
      return read_leb(stream.bytes, stream.cursor, (byte & 0xF0U) == 0x60).has_value() ? Status::kOk : Status::kError;
    case 0x40:
      return skip_symbol(stream);
    case 0x50:
      return rebase_opcode(stream, static_cast<std::uint8_t>(0x10U | immediate));
    case 0x70:
      return select_target(stream, immediate);
    case 0x80:
      return rebase_opcode(stream, 0x30);
    case 0x90:
      return write_target(stream.target, {});
    case 0xA0:
      return write_operands(stream, 0x70);
    case 0xB0:
      return write_target(stream.target, {.skip = std::uint64_t{immediate} * 8});
    case 0xC0:
      return write_operands(stream, 0x80);
    default:
      return Status::kUnsupported;
  }
}

/// Checks classic dyld streams; threaded opcodes and any __TEXT target are explicitly unsupported.
[[nodiscard]] Status check_dyld_stream(DyldStream stream, bool binding) {
  while (stream.cursor < stream.bytes.size()) {
    const std::uint8_t byte = stream.bytes[stream.cursor++];
    const Status status = binding ? bind_opcode(stream, byte) : rebase_opcode(stream, byte);
    if (status != Status::kOk) {
      return status;
    }
  }
  return Status::kOk;
}

/// The image's segment ranges, in dyld's segment-index order.
struct Segments {
  /// Virtual sizes used to bound classic fixup writes.
  std::vector<std::uint64_t> sizes;
  /// Preferred addresses used to validate chained fixup segment offsets.
  std::vector<std::uint64_t> addresses;
  /// __TEXT's index in both vectors.
  std::uint32_t text_index = 0;
};

/// Collects segment ranges after validating the complete segment fields and file extents.
[[nodiscard]] std::optional<Segments> read_segments(std::span<const util::LoadCommand> commands,
                                                    std::size_t file_size) {
  Segments segments;
  for (const auto& command : commands) {
    if (command.command != kSegmentCommand) {
      continue;
    }
    const auto size = util::read_little_endian_64(command.bytes, 32);
    const auto address = util::read_little_endian_64(command.bytes, 24);
    const auto offset = util::read_little_endian_64(command.bytes, 40);
    const auto length = util::read_little_endian_64(command.bytes, 48);
    if (!size.has_value() || !address.has_value() || !offset.has_value() || !length.has_value() ||
        !util::range_fits(*offset, *length, file_size)) {
      return std::nullopt;
    }
    if (name_is(command.bytes.subspan(8, 16), kTextSegmentName)) {
      segments.text_index = static_cast<std::uint32_t>(segments.sizes.size());
    }
    segments.sizes.push_back(*size);
    segments.addresses.push_back(*address);
  }
  return segments;
}

/// Validates one chained-start record, including the segment-relative mapping and bounded page table.
[[nodiscard]] Status check_chain_segment(std::span<const std::uint8_t> starts, std::size_t info_offset,
                                         const Segments& segments, std::uint32_t index) {
  const auto length = util::read_little_endian(starts, info_offset);
  if (!length.has_value() || *length < 22 || !util::range_fits(info_offset, *length, starts.size())) {
    return Status::kError;
  }
  const auto info = starts.subspan(info_offset, *length);
  const auto segment_offset = util::read_little_endian_64(info, 8);
  const std::uint64_t text_address = segments.addresses[segments.text_index];
  if (!segment_offset.has_value() || segments.addresses[index] < text_address ||
      *segment_offset != segments.addresses[index] - text_address) {
    return Status::kError;
  }
  if (index == segments.text_index) {
    return Status::kUnsupported;
  }
  const std::uint32_t page_size = std::uint32_t{info[4]} | (std::uint32_t{info[5]} << 8U);
  const std::uint32_t page_count = std::uint32_t{info[20]} | (std::uint32_t{info[21]} << 8U);
  if ((page_size != 4096 && page_size != 16384) || !util::range_fits(22, std::uint64_t{page_count} * 2U, info.size()) ||
      page_count > (segments.sizes[index] / page_size) + (segments.sizes[index] % page_size != 0 ? 1U : 0U)) {
    return Status::kError;
  }
  for (std::size_t page = 0; page < page_count; ++page) {
    const std::size_t offset = 22 + (page * 2);
    const std::uint32_t start = std::uint32_t{info[offset]} | (std::uint32_t{info[offset + 1]} << 8U);
    if (start != 0xFFFF && start >= page_size) {
      return Status::kUnsupported;
    }
  }
  return Status::kOk;
}

/// Checks the chained-starts table; __TEXT must have no chains, excluding rebases and authenticated binds from code.
[[nodiscard]] Status check_chained_fixups(std::span<const std::uint8_t> bytes, const Segments& segments) {
  const auto starts_offset = util::read_little_endian(bytes, 4);
  if (bytes.size() < 28 || util::read_little_endian(bytes, 0) != 0U || !starts_offset.has_value() ||
      *starts_offset < 28 || !util::range_fits(*starts_offset, 4, bytes.size())) {
    return Status::kError;
  }
  const auto starts = bytes.subspan(*starts_offset);
  const auto count = util::read_little_endian(starts, 0);
  if (!count.has_value() || *count > segments.addresses.size() ||
      !util::range_fits(4, std::uint64_t{*count} * 4, starts.size())) {
    return Status::kError;
  }
  for (std::uint32_t index = 0; index < *count; ++index) {
    const auto info_offset = util::read_little_endian(starts, 4 + (std::size_t{index} * 4));
    if (!info_offset.has_value()) {
      return Status::kError;
    }
    if (*info_offset == 0) {
      continue;
    }
    if (*info_offset < 4 + (std::uint64_t{*count} * 4)) {
      return Status::kError;
    }
    const Status status = check_chain_segment(starts, *info_offset, segments, index);
    if (status != Status::kOk) {
      return status;
    }
  }
  return Status::kOk;
}

/// Reads a load-command offset/length pair only when both fields are present.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> command_payload(int file, const util::MachFile& mach_file,
                                                                       std::span<const std::uint8_t> command,
                                                                       std::size_t field) {
  const auto offset = util::read_little_endian(command, field);
  const auto length = util::read_little_endian(command, field + 4);
  if (!offset.has_value() || !length.has_value()) {
    return std::nullopt;
  }
  return read_payload(file, *offset, *length, mach_file.file_size);
}

/// Checks the four classic pointer-fixup streams; export metadata does not write runtime code.
[[nodiscard]] Status check_classic_fixups(int file, const util::MachFile& mach_file,
                                          std::span<const std::uint8_t> command, const Segments& segments) {
  if (command.size() != 48) {
    return Status::kError;
  }
  for (std::size_t stream = 0; stream < 4; ++stream) {
    const auto bytes = command_payload(file, mach_file, command, 8 + (stream * 8));
    if (!bytes.has_value()) {
      return Status::kError;
    }
    const DyldStream stream_data{
        .bytes = *bytes,
        .segment_sizes = segments.sizes,
        .text_index = segments.text_index,
    };
    const Status status = check_dyld_stream(stream_data, stream != 0);
    if (status != Status::kOk) {
      return status;
    }
  }
  return Status::kOk;
}

/// Checks one relocation command, leaving non-fixup load commands alone.
[[nodiscard]] Status check_fixup_command(int file, const util::MachFile& mach_file, const util::LoadCommand& command,
                                         const Segments& segments) {
  switch (command.command) {
    case 0xB:
      if (command.bytes.size() != 80) {
        return Status::kError;
      }
      return util::read_little_endian(command.bytes, 68) == 0U && util::read_little_endian(command.bytes, 76) == 0U
                 ? Status::kOk
                 : Status::kUnsupported;
    case 0x80000034: {
      if (command.bytes.size() != 16) {
        return Status::kError;
      }
      const auto bytes = command_payload(file, mach_file, command.bytes, 8);
      return bytes.has_value() ? check_chained_fixups(*bytes, segments) : Status::kError;
    }
    case 0x22:
    case 0x80000022:
      return check_classic_fixups(file, mach_file, command.bytes, segments);
    default:
      return Status::kOk;
  }
}

/// Rejects duplicate fixup commands so repeated forged commands cannot multiply the bounded I/O work.
[[nodiscard]] bool unique_fixup_command(std::uint32_t command, std::uint8_t& seen) {
  std::uint8_t bit = 0;
  switch (command) {
    case 0xB:
      bit = 1;
      break;
    case 0x80000034:
      bit = 2;
      break;
    case 0x22:
    case 0x80000022:
      bit = 4;
      break;
    default:
      return true;
  }
  const bool unique = (seen & bit) == 0;
  seen |= bit;
  return unique;
}

/// Rejects loader metadata that can mutate __TEXT, keeping data fixups outside the measured region.
[[nodiscard]] Status check_fixups(int file, const util::MachFile& mach_file) {
  const auto commands = util::load_commands(mach_file.header_and_commands);
  if (!commands.has_value()) {
    return Status::kError;
  }
  const auto segments = read_segments(*commands, mach_file.file_size);
  if (!segments.has_value()) {
    return Status::kError;
  }
  std::uint8_t seen = 0;
  for (const auto& command : *commands) {
    if (!unique_fixup_command(command.command, seen)) {
      return Status::kError;
    }
    const Status status = check_fixup_command(file, mach_file, command, *segments);
    if (status != Status::kOk) {
      return status;
    }
  }
  return Status::kOk;
}

/// What the check reads of the image's file: the layout and, when the image isn't encrypted, the section's bytes.
struct TextFile {
  /// The layout that find_text_layout gives for the file.
  TextLayout layout;
  /// Exact immutable header and load-command bytes expected in the mapped image.
  std::vector<std::uint8_t> header_and_commands;
  /// The bytes of the `__text` section in the file, empty when the image is encrypted.
  std::vector<std::uint8_t> code;
};

/// Reads the layout and the `__text` bytes of the Mach-O file open as `file`.
///
/// @param file The open file.
/// @return What the check reads of the file, or nothing when util::read_mach_file or find_text_layout gives nothing,
/// when the section is larger than kMaxTextSize bytes or reaches past the end of the file, or when the read fails.
[[nodiscard]] std::expected<TextFile, Status> read_text(int file) {
  const std::optional<util::MachFile> mach_file = util::read_mach_file(file);
  if (!mach_file.has_value()) {
    return std::unexpected(Status::kError);
  }
  const std::optional<TextLayout> layout = find_text_layout(mach_file->header_and_commands);
  if (!layout.has_value() || layout->section_size > kMaxTextSize ||
      !util::range_fits(layout->section_offset, layout->section_size, mach_file->file_size)) {
    return std::unexpected(Status::kError);
  }
  const Status fixups = check_fixups(file, *mach_file);
  if (fixups != Status::kOk) {
    return std::unexpected(fixups);
  }
  if (layout->encrypted) {
    return TextFile{.layout = *layout, .header_and_commands = mach_file->header_and_commands, .code = {}};
  }
  std::vector<std::uint8_t> code(static_cast<std::size_t>(layout->section_size));
  if (!util::read_exactly(file, static_cast<std::size_t>(layout->section_offset), code)) {
    return std::unexpected(Status::kError);
  }
  return TextFile{.layout = *layout, .header_and_commands = mach_file->header_and_commands, .code = std::move(code)};
}

/// Reads the layout and the `__text` bytes of the Mach-O file at `path`.
///
/// The file is opened with close-on-exec, so it never leaks into a process the app starts, and without blocking, so a
/// FIFO can't stall the open before the regular-file check refuses it.
///
/// @param path The Mach-O file to read.
/// @return What read_text reads, or nothing when the file can't be opened or closed, or read_text gives nothing.
[[nodiscard]] std::expected<TextFile, Status> read_text_file(const std::string& path) {
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): POSIX open has no non-variadic equivalent with O_NONBLOCK.
  const int file = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
  if (file < 0) {
    return std::unexpected(Status::kError);
  }
  std::expected<TextFile, Status> text = read_text(file);
  if (close(file) != 0) {
    return std::unexpected(Status::kError);
  }
  return text;
}

/// Copies a range only after checking both offset and absolute-address arithmetic.
[[nodiscard]] bool read_memory(ImageMemory memory, std::uint64_t offset, std::span<std::uint8_t> into) {
  const auto maximum = std::numeric_limits<std::uintptr_t>::max();
  return memory.header != 0 && memory.read != nullptr && util::range_fits(memory.header, offset, maximum) &&
         util::range_fits(memory.header + offset, into.size(), maximum) &&
         memory.read(memory.context, memory.header + static_cast<std::uintptr_t>(offset), into);
}

/// Copies code after checking the mapped metadata against the file's metadata.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> memory_text(ImageMemory memory, const TextFile& file) {
  std::vector<std::uint8_t> commands(file.header_and_commands.size());
  if (!read_memory(memory, 0, commands) || commands != file.header_and_commands) {
    return std::nullopt;
  }
  std::vector<std::uint8_t> code(static_cast<std::size_t>(file.layout.section_size));
  if (!read_memory(memory, file.layout.section_address - file.layout.segment_address, code)) {
    return std::nullopt;
  }
  return code;
}

/// Returns the integ.text_sha256 observation through `source` of the code `code`.
///
/// @param source The source of the observation.
/// @param code The bytes to hash.
/// @return The observation, the hash as 64 lowercase hex digits, or an error when TF-PSA-Crypto can't compute it.
[[nodiscard]] Observation hash_observation(std::string_view source, std::span<const std::uint8_t> code) {
  std::optional<std::string> hash = util::sha256_hex(code);
  return hash.has_value() ? observed(kTextHashSignal, source, std::move(*hash)) : failed(kTextHashSignal, source);
}

/// The unsupported integ.text_sha256 observations, for a system where the check can't run.
///
/// @return The file and memory observations, both with the unsupported status.
[[nodiscard]] std::vector<Observation> unsupported_hashes() {
  return {unsupported(kTextHashSignal, kFileSource), unsupported(kTextHashSignal, kMemorySource)};
}

#if defined(__APPLE__) && TARGET_OS_IOS && !TARGET_OS_SIMULATOR
/// Copies through the kernel so an unmapped, unreadable or concurrently unmapped range cannot fault the app.
[[nodiscard]] bool read_process(void*, std::uintptr_t address, std::span<std::uint8_t> into) {
  static_assert(sizeof(vm_address_t) == sizeof(std::uintptr_t) && sizeof(vm_address_t) == 8);
  static_assert(sizeof(vm_size_t) == sizeof(std::size_t) && sizeof(vm_size_t) == 8);
  vm_size_t copied = 0;
  const auto size = static_cast<vm_size_t>(into.size());
  return vm_read_overwrite(mach_task_self(), static_cast<vm_address_t>(address), size,
                           std::bit_cast<vm_address_t>(into.data()), &copied) == KERN_SUCCESS &&
         copied == size;
}

/// An object in the runtime's own image, used only for its address: dladdr on it names the framework's binary.
constexpr char kAnchor = 0;
#endif

/// Reports the hashes of the runtime's own `__text` section, found through dladdr on kAnchor. dladdr's `Dl_info` is
/// read only on Apple systems, so anywhere else both observations are unsupported.
///
/// @return The two observations, as observe_text_hashes reports them, or both with an error status when dladdr finds
/// no image or gives no path or header.
[[nodiscard]] std::vector<Observation> observe_own_image() {
#if defined(__APPLE__) && TARGET_OS_IOS && !TARGET_OS_SIMULATOR
  Dl_info info{};
  if (dladdr(&kAnchor, &info) == 0 || info.dli_fname == nullptr || info.dli_fbase == nullptr) {
    return {failed(kTextHashSignal, kFileSource), failed(kTextHashSignal, kMemorySource)};
  }
  return observe_text_hashes(
      info.dli_fname,
      {.header = std::bit_cast<std::uintptr_t>(info.dli_fbase), .context = nullptr, .read = read_process});
#else
  return unsupported_hashes();
#endif
}

}  // namespace

std::optional<TextLayout> find_text_layout(std::span<const std::uint8_t> header_and_commands) {
  const std::optional<util::MachHeader> header = util::read_mach_header(header_and_commands);
  const std::optional<std::vector<util::LoadCommand>> commands = util::load_commands(header_and_commands);
  if (!header.has_value() || !commands.has_value() || util::read_little_endian(header_and_commands, 4) != 0x100000CU ||
      (util::read_little_endian(header_and_commands, 12) != 2U &&
       util::read_little_endian(header_and_commands, 12) != 6U)) {
    return std::nullopt;
  }
  std::size_t consumed = 0;
  for (const auto& command : *commands) {
    if (command.bytes.size() % 8 != 0) {
      return std::nullopt;
    }
    consumed += command.bytes.size();
  }
  if (consumed != header->commands_size) {
    return std::nullopt;
  }
  const std::optional<TextSegment> segment = find_text_segment(*commands);
  const std::optional<bool> encrypted = is_encrypted(*commands);
  if (!segment.has_value() || !encrypted.has_value() ||
      !is_mapped_from_file(*segment, util::kMachHeaderSize + header->commands_size)) {
    return std::nullopt;
  }
  for (const auto& command : *commands) {
    if (command.command != kSegmentCommand) {
      continue;
    }
    const auto address = util::read_little_endian_64(command.bytes, 24);
    const auto size = util::read_little_endian_64(command.bytes, 32);
    if (!address.has_value() || !size.has_value() ||
        !util::range_fits(*address, *size, std::numeric_limits<std::uint64_t>::max())) {
      return std::nullopt;
    }
    if (!name_is(command.bytes.subspan(8, 16), kTextSegmentName) && *size != 0 &&
        *address < segment->address + segment->size && segment->address < *address + *size) {
      return std::nullopt;
    }
  }
  return TextLayout{
      .command_count = header->command_count,
      .commands_size = header->commands_size,
      .segment_address = segment->address,
      .segment_size = segment->size,
      .segment_file_size = segment->file_size,
      .section_address = segment->text.address,
      .section_offset = segment->text.file_offset,
      .section_size = segment->text.size,
      .encrypted = *encrypted,
  };
}

std::vector<Observation> observe_text_hashes(std::string_view image_path, ImageMemory memory) {
  const std::expected<TextFile, Status> file = read_text_file(std::string(image_path));
  if (!file.has_value()) {
    return file.error() == Status::kUnsupported
               ? unsupported_hashes()
               : std::vector<Observation>{failed(kTextHashSignal, kFileSource), failed(kTextHashSignal, kMemorySource)};
  }
  const std::optional<std::vector<std::uint8_t>> code = memory_text(memory, *file);
  return {
      file->layout.encrypted ? unsupported(kTextHashSignal, kFileSource) : hash_observation(kFileSource, file->code),
      code.has_value() ? hash_observation(kMemorySource, *code) : failed(kTextHashSignal, kMemorySource),
  };
}

std::vector<Observation> integrity() {
  if (!kPhysicalDevice) {
    return unsupported_hashes();
  }
  return observe_own_image();
}

}  // namespace rasp::ios::checks
