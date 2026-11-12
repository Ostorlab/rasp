/// Raw SHA-256 observations of the running RaspRuntime image's immutable `__TEXT,__text` bytes, from its installed
/// framework file and from process memory. They enable a future assessor to compare the sources and a trusted build
/// baseline. This check performs no comparison and produces no tampering verdict. Matching hashes are not attestation:
/// an attacker can patch both sources or forge their reads and reporting.

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
/// These fields describe parsed layout metadata, not verified image identity or provenance. The memory reader checks
/// the mapped header and commands against the file before hashing; the file remains an attacker-controlled source.
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

  /// Compares parsed metadata without asserting provenance.
  /// @param left The first parsed layout.
  /// @param right The second parsed layout.
  /// @return True when the fields match.
  [[nodiscard]] friend bool operator==(const TextLayout& left, const TextLayout& right) = default;
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

/// A checked reader of a mapped image; a failed or partial read must return false.
struct ImageMemory {
  /// The mapped Mach-O header address, not its preferred virtual address.
  std::uintptr_t header = 0;
  /// Reader-owned read-only state, kept only for this call.
  const void* context = nullptr;
  /// Copies the requested address range into a caller-owned bounded buffer.
  bool (*read)(const void*, std::uintptr_t, std::span<std::uint8_t>) = nullptr;
};

/// Reports SHA-256 strings through file then memory, without deciding whether they match.
/// Reads at most 1 MiB of commands, 1 MiB per fixup stream and 64 MiB of code from a regular thin arm64 image.
/// Only regular, pure-instruction __text in a read/execute __TEXT segment without relocations is supported.
/// Memory is copied through the checked reader; no image address is dereferenced directly. Addressing uses the
/// mapped header plus (section addr - __TEXT vmaddr), resolving the slide without signed arithmetic.
/// Encrypted disk code is unsupported; malformed/unreadable sources and differing mapped metadata are errors.
/// Layouts with possible text fixups are unsupported for both sources. Matching values are not attestation:
/// an attacker controlling both sources, the reader or the reporting code can forge them.
/// @param image_path Installed runtime binary, located through dladdr in production.
/// @param memory Bounded image reader (vm_read_overwrite on a physical device).
/// @return Two observations; failures carry no value, successful hashes are 64 lowercase hexadecimal digits.
[[nodiscard]] std::vector<Observation> observe_text_hashes(std::string_view image_path, ImageMemory memory);

}  // namespace rasp::ios::checks
