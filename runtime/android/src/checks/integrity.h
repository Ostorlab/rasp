/// The Android integrity check: whether librasp.so's own executable code is the same in memory as on disk.

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "rasp/observation.h"

namespace rasp::android::checks {

/// Runs the self-integrity check and returns what it observed.
///
/// It computes the SHA-256 of the executable code (the `.text` section) of librasp.so twice: once from the installed
/// file, under `lib/arm64-v8a/` inside the APK, and once from the same code in the process's memory. On a device that
/// hasn't been tampered with the two hashes are equal. They differ when the code was patched in memory, for example by
/// a tool such as Frida that rewrites a check to always report a safe value. The check only reports the two hashes;
/// the server compares them.
///
/// On Android it locates librasp.so through its own loaded image and reads both hashes. Anywhere else, such as on a
/// Linux host, every observation is unsupported instead, so the server still sees that the check ran.
///
/// @return One observation per source, in this order: integ.text_sha256 through file, then through memory.
[[nodiscard]] std::vector<Observation> integrity();

/// Where the `.text` section's bytes live: in the file and, once the segment is loaded, in memory.
///
/// Both ranges hold the same `size` bytes. `file_offset` is the section's offset in the file (its `sh_offset`).
/// `memory_address` is where those bytes sit in the running process, the library's load address plus the section's
/// virtual address (its `sh_addr`). Because `.text` is allocated, non-writable code, the loader maps it unchanged and
/// applies no relocation to it, so the file bytes and the memory bytes are identical when nothing patched them.
struct TextRegion {
  /// The offset of the section's bytes in the file.
  std::uint64_t file_offset = 0;
  /// The address of the section's bytes in the running process.
  std::uintptr_t memory_address = 0;
  /// The number of bytes in the section, the same in the file and in memory.
  std::uint64_t size = 0;
};

/// Finds the `.text` section of the ELF image whose file bytes are `image`, loaded at `load_bias`.
///
/// It reads the section headers from the file image to find `.text`, then checks, through the program headers, that the
/// section lies inside one loadable, executable, non-writable segment and does not reach past the bytes the file holds
/// for that segment. The last condition matters because a segment's last page is zero-filled in memory beyond the end
/// of the file it was read from, so a section that straddled that boundary would read zeros in memory that the file
/// doesn't hold. The in-memory address it reports is `load_bias + sh_addr`, which equals the address reached by
/// translating the file offset through the segment, since the loader keeps `sh_addr - sh_offset` equal to
/// `p_vaddr - p_offset` for every section of a segment.
///
/// @param image The bytes of the ELF file, read whole.
/// @param load_bias The difference between where the image is loaded and the virtual addresses in its headers. It is 0
/// for a non-relocated image and the load address for a position-independent one such as librasp.so.
/// @return Where the `.text` section's bytes live, or nothing when the image isn't a 64-bit little-endian ELF, has no
/// `.text` section with bytes in the file, or the section doesn't lie wholly inside the file part of one loadable,
/// executable, non-writable segment.
[[nodiscard]] std::optional<TextRegion> find_text_region(std::span<const std::uint8_t> image, std::uintptr_t load_bias);

/// The lowercase hexadecimal SHA-256 of `bytes`, or nothing when the crypto library can't compute it.
///
/// @param bytes The bytes to hash.
/// @return The 64-character hex digest, or nothing on a crypto error.
[[nodiscard]] std::optional<std::string> sha256_hex(std::span<const std::uint8_t> bytes);

/// The integ.text_sha256 observations for the library whose file is `library_path` and whose `.text` bytes are at
/// `text_memory` in the process.
///
/// It reads the file, finds its `.text` section, hashes those bytes from the file and the same count of bytes from
/// `text_memory`, and reports one observation per source. It is the part of the check that does not itself touch the
/// dynamic loader, so a test can drive it with a file and a span of its own choosing.
///
/// @param library_path The path of the installed library file.
/// @param text_memory The library's loaded image, starting at its load address. The function reads only the `.text`
/// bytes inside it, found from the file's section and program headers.
/// @return The file observation, then the memory observation. An observation has an error status when the file can't
/// be read, has no usable `.text` section, the section reaches past `text_memory`, or the hash can't be computed.
[[nodiscard]] std::vector<Observation> observe_text_hashes(std::string_view library_path,
                                                           std::span<const std::uint8_t> text_memory);

}  // namespace rasp::android::checks
