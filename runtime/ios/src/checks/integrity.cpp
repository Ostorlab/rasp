/// The iOS code-integrity check: the layout of the `__TEXT,__text` section, the file and memory hashes of the runtime's
/// own image, and their unsupported result off a physical device. The Mach-O image is read through util/macho.h, and
/// the segment, section and encryption load commands draw only on the standard layout of `<mach-o/loader.h>`.

#include "checks/integrity.h"

#include <algorithm>
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
#include <dlfcn.h>
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
    if (found.has_value() || !address || !size || !file_offset) {
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
  if (!address || !size || !file_offset || !file_size || !section_count ||
      (command.size() - kSegmentCommandSize) / kSectionSize < *section_count) {
    return std::nullopt;
  }
  const std::optional<Section> text = find_text_section(command, *section_count);
  if (!text) {
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
      segment.text.address < segment.address) {
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
    if (!found) {
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
    if (!crypt_id) {
      return std::nullopt;
    }
    encrypted = encrypted || *crypt_id != 0;
  }
  return encrypted;
}

/// What the check reads of the image's file: the layout and, when the image isn't encrypted, the section's bytes.
struct TextFile {
  /// The layout that find_text_layout gives for the file.
  TextLayout layout;
  /// The bytes of the `__text` section in the file, empty when the image is encrypted.
  std::vector<std::uint8_t> code;
};

/// Reads the layout and the `__text` bytes of the Mach-O file open as `file`.
///
/// @param file The open file.
/// @return What the check reads of the file, or nothing when util::read_mach_file or find_text_layout gives nothing,
/// when the section is larger than kMaxTextSize bytes or reaches past the end of the file, or when the read fails.
[[nodiscard]] std::optional<TextFile> read_text(int file) {
  const std::optional<util::MachFile> mach_file = util::read_mach_file(file);
  if (!mach_file) {
    return std::nullopt;
  }
  const std::optional<TextLayout> layout = find_text_layout(mach_file->header_and_commands);
  if (!layout || layout->section_size > kMaxTextSize ||
      !util::range_fits(layout->section_offset, layout->section_size, mach_file->file_size)) {
    return std::nullopt;
  }
  if (layout->encrypted) {
    return TextFile{.layout = *layout, .code = {}};
  }
  std::vector<std::uint8_t> code(static_cast<std::size_t>(layout->section_size));
  if (!util::read_exactly(file, static_cast<std::size_t>(layout->section_offset), code)) {
    return std::nullopt;
  }
  return TextFile{.layout = *layout, .code = std::move(code)};
}

/// Reads the layout and the `__text` bytes of the Mach-O file at `path`.
///
/// The file is opened with close-on-exec, so it never leaks into a process the app starts, and without blocking, so a
/// FIFO can't stall the open before the regular-file check refuses it.
///
/// @param path The Mach-O file to read.
/// @return What read_text reads, or nothing when the file can't be opened or closed, or read_text gives nothing.
[[nodiscard]] std::optional<TextFile> read_text_file(const std::string& path) {
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
  const int file = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
  if (file < 0) {
    return std::nullopt;
  }
  std::optional<TextFile> text = read_text(file);
  if (close(file) != 0) {
    return std::nullopt;
  }
  return text;
}

/// Finds the `__text` bytes of the image loaded at `image`, reading only what the file's layout `layout` says dyld
/// mapped there.
///
/// @param image The address of the image's Mach-O header in memory, or null.
/// @param layout The layout that find_text_layout gives for the image's file.
/// @return The section's bytes in memory, or nothing when `image` is null, when the header in memory has another
/// `ncmds` or `sizeofcmds` than `layout`, or when find_text_layout gives nothing or another layout for the load
/// commands in memory.
[[nodiscard]] std::optional<std::span<const std::uint8_t>> memory_text(const std::uint8_t* image,
                                                                       const TextLayout& layout) {
  if (image == nullptr) {
    return std::nullopt;
  }
  const std::optional<util::MachHeader> header =
      util::read_mach_header(std::span<const std::uint8_t>(image, util::kMachHeaderSize));
  if (!header || header->command_count != layout.command_count || header->commands_size != layout.commands_size) {
    return std::nullopt;
  }
  const std::optional<TextLayout> memory_layout =
      find_text_layout(std::span<const std::uint8_t>(image, util::kMachHeaderSize + layout.commands_size));
  if (!memory_layout || *memory_layout != layout) {
    return std::nullopt;
  }
  const std::span<const std::uint8_t> mapped(
      image, static_cast<std::size_t>(std::min(layout.segment_size, layout.segment_file_size)));
  return mapped.subspan(static_cast<std::size_t>(layout.section_address - layout.segment_address),
                        static_cast<std::size_t>(layout.section_size));
}

/// Returns the integ.text_sha256 observation through `source` of the code `code`.
///
/// @param source The source of the observation.
/// @param code The bytes to hash.
/// @return The observation, the hash as 64 lowercase hex digits, or an error when TF-PSA-Crypto can't compute it.
[[nodiscard]] Observation hash_observation(std::string_view source, std::span<const std::uint8_t> code) {
  std::optional<std::string> hash = util::sha256_hex(code);
  return hash ? observed(kTextHashSignal, source, std::move(*hash)) : failed(kTextHashSignal, source);
}

/// The unsupported integ.text_sha256 observations, for a system where the check can't run.
///
/// @return The file and memory observations, both with the unsupported status.
[[nodiscard]] std::vector<Observation> unsupported_hashes() {
  return {unsupported(kTextHashSignal, kFileSource), unsupported(kTextHashSignal, kMemorySource)};
}

#ifdef __APPLE__
/// An object in the runtime's own image, used only for its address: dladdr on it names the framework's binary.
constexpr char kAnchor = 0;
#endif

/// Reports the hashes of the runtime's own `__text` section, found through dladdr on kAnchor. dladdr's `Dl_info` is
/// read only on Apple systems, so anywhere else both observations are unsupported.
///
/// @return The two observations, as observe_text_hashes reports them, or both with an error status when dladdr finds
/// no image or gives no path or header.
[[nodiscard]] std::vector<Observation> observe_own_image() {
#ifdef __APPLE__
  Dl_info info{};
  if (dladdr(&kAnchor, &info) == 0 || info.dli_fname == nullptr || info.dli_fbase == nullptr) {
    return {failed(kTextHashSignal, kFileSource), failed(kTextHashSignal, kMemorySource)};
  }
  return observe_text_hashes(info.dli_fname, static_cast<const std::uint8_t*>(info.dli_fbase));
#else
  return unsupported_hashes();
#endif
}

}  // namespace

std::optional<TextLayout> find_text_layout(std::span<const std::uint8_t> header_and_commands) {
  const std::optional<util::MachHeader> header = util::read_mach_header(header_and_commands);
  const std::optional<std::vector<util::LoadCommand>> commands = util::load_commands(header_and_commands);
  if (!header || !commands) {
    return std::nullopt;
  }
  const std::optional<TextSegment> segment = find_text_segment(*commands);
  const std::optional<bool> encrypted = is_encrypted(*commands);
  if (!segment || !encrypted || !is_mapped_from_file(*segment, util::kMachHeaderSize + header->commands_size)) {
    return std::nullopt;
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

std::vector<Observation> observe_text_hashes(std::string_view image_path, const std::uint8_t* image) {
  const std::optional<TextFile> file = read_text_file(std::string(image_path));
  if (!file) {
    return {failed(kTextHashSignal, kFileSource), failed(kTextHashSignal, kMemorySource)};
  }
  const std::optional<std::span<const std::uint8_t>> memory = memory_text(image, file->layout);
  return {
      file->layout.encrypted ? unsupported(kTextHashSignal, kFileSource) : hash_observation(kFileSource, file->code),
      memory ? hash_observation(kMemorySource, *memory) : failed(kTextHashSignal, kMemorySource),
  };
}

std::vector<Observation> integrity() {
  if (!kPhysicalDevice) {
    return unsupported_hashes();
  }
  return observe_own_image();
}

}  // namespace rasp::ios::checks
