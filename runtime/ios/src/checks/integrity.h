/// The iOS code-integrity check: whether the runtime's own executable code is the same in memory as in the installed
/// framework file. It reports the SHA-256 of the `__TEXT,__text` section of `RaspRuntime.framework/RaspRuntime`,
/// read from the file and from the process's memory; the server compares the two with each other and with the value
/// of the build it shipped, and decides.

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "rasp/observation.h"

namespace rasp::ios::checks {

/// Runs the code-integrity check and returns what it observed.
///
/// On a physical iOS device it finds the runtime's own image with dladdr on an object in it, which gives the path of
/// the framework's binary and the address of its Mach-O header in memory, and reports the hashes of its `__text`
/// section as observe_text_hashes does. Anywhere else, on a simulator, a Mac or a Linux host, every observation is
/// unsupported instead, so the result still shows that the check ran.
///
/// @return Two observations, in this order: integ.text_sha256 through file, then through memory. Both have an error
/// status when dladdr can't find the image or gives no path or header.
[[nodiscard]] std::vector<Observation> integrity();

/// Where the `__TEXT,__text` section lies, as one Mach-O image's header and load commands give it.
///
/// The file and the memory copy of the same image give equal layouts, since dyld maps the header and load commands
/// unchanged as the start of the `__TEXT` segment.
struct TextLayout {
  /// The number of load commands, the header's `ncmds`.
  std::uint32_t command_count = 0;
  /// The total size of the load commands in bytes, the header's `sizeofcmds`.
  std::uint32_t commands_size = 0;
  /// The `__TEXT` segment's address before the slide, its `vmaddr`.
  std::uint64_t segment_address = 0;
  /// The `__TEXT` segment's size in memory, its `vmsize`.
  std::uint64_t segment_size = 0;
  /// The number of the `__TEXT` segment's bytes the file holds, its `filesize`.
  std::uint64_t segment_file_size = 0;
  /// The `__text` section's address before the slide, its `addr`.
  std::uint64_t section_address = 0;
  /// The offset of the `__text` section's bytes in the file, its `offset`.
  std::uint64_t section_offset = 0;
  /// The number of bytes in the `__text` section, its `size`.
  std::uint64_t section_size = 0;
  /// Whether an `LC_ENCRYPTION_INFO_64` load command marks the image as encrypted, with a `cryptid` other than 0, as
  /// the App Store's FairPlay encryption does. The file then holds encrypted code, which the kernel decrypts as it
  /// loads each page into memory.
  bool encrypted = false;

  /// Whether two layouts have the same values in every field.
  friend bool operator==(const TextLayout&, const TextLayout&) = default;
};

/// Finds the `__TEXT,__text` section of the thin 64-bit little-endian Mach-O image whose header and load commands
/// start at `header_and_commands`.
///
/// The load commands are split as util::load_commands splits them. The image must have exactly one `LC_SEGMENT_64`
/// load command named `__TEXT`, and in it exactly one section named `__text` whose segment name is `__TEXT`. Every
/// section must fit in the load command. As dyld requires of an image it loads, the segment must start at file offset
/// 0 and hold the header and the load commands. The section must not be empty, must lie wholly inside the part of the
/// segment that the file holds and that is mapped, the first `min(vmsize, filesize)` bytes from `vmaddr`, and its file
/// offset must be its offset in the segment, so its bytes in the file are the bytes dyld maps at its address. Every
/// sum is checked without an addition that could overflow.
///
/// @param header_and_commands The bytes that start with the Mach-O header and hold at least its load commands.
/// @return The layout, or nothing when util::load_commands gives nothing, which covers a universal file, a 32-bit
/// one, load commands larger than 1 MiB and a malformed load command; when there is no `__TEXT` segment or more than
/// one, or no `__text` section in it or more than one; when a segment or an `LC_ENCRYPTION_INFO_64` load command is
/// shorter than its fields or its sections; or when the segment or the section breaks one of the conditions above.
[[nodiscard]] std::optional<TextLayout> find_text_layout(std::span<const std::uint8_t> header_and_commands);

/// The integ.text_sha256 observations of the Mach-O image whose file is `image_path` and whose Mach-O header is loaded
/// at `image` in the process.
///
/// The file is opened with close-on-exec and without blocking, and must be a regular file. Its header and load commands
/// are read and find_text_layout finds its `__text` section, which must lie within the file and hold at most 64 MiB.
/// The file source is the SHA-256 of the section's bytes in the file, read with exactly its size, or the unsupported
/// status when the image is encrypted, since its bytes in the file are then not the code that runs.
///
/// The memory source reads the image in memory only within what the file's layout says dyld mapped. It first reads
/// the 32 bytes of the header at `image`, and its `ncmds` and `sizeofcmds` must equal the file's. It then reads that
/// many bytes of load commands, which the file's layout puts inside the mapped `__TEXT` segment, and find_text_layout
/// must give the same layout from them as from the file. The bytes hashed are then the section's, at `image` plus the
/// section's offset in the segment, which lie inside the segment's mapped bytes. The SHA-256 comes from TF-PSA-Crypto.
///
/// On a device that hasn't been tampered with, and an image that isn't encrypted, the two hashes are equal: nothing
/// writes into `__TEXT,__text` once dyld maps it. They differ when the code was patched in memory, as a hooking tool
/// does to a function it hooks.
///
/// @param image_path The path of the image's file.
/// @param image The address of the image's Mach-O header in memory, where the mapped `__TEXT` segment starts.
/// @return The file observation, then the memory observation, each a hash as 64 lowercase hex digits. Both have an
/// error status when the file can't be opened, read or closed, isn't a regular file, has no usable `__text` section,
/// or has a section past its end or larger than 64 MiB. The memory observation alone has an error status when `image`
/// is null, or when the header or the layout in memory differs from the file's. Either one has an error status when
/// TF-PSA-Crypto can't compute its hash.
[[nodiscard]] std::vector<Observation> observe_text_hashes(std::string_view image_path, const std::uint8_t* image);

}  // namespace rasp::ios::checks
