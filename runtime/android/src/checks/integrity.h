/// The Android integrity check: the expected and running plaintext digests of librasp.so's executable code.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "rasp/observation.h"

namespace rasp::android::checks {

/// The length of a SHA-256 digest, in bytes.
inline constexpr std::size_t kDigestSize = 32;

/// Runs the self-integrity check and returns what it observed.
///
/// The memory source is the SHA-256 of the running `.text` section. On packed builds, the file source is the expected
/// plaintext digest written into `.rasp_config` at pack time; the installed `.text` bytes are ciphertext and are not
/// hashed for this observation. On unpacked builds, the file source is computed from the installed `.text` bytes.
/// Equal values mean the running code matches that expectation. The digest slot is attacker-patchable in the file;
/// this observation does not authenticate it. The key schedule's fold binds the slot into payload-key recovery.
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
/// virtual address (its `sh_addr`). The loader applies no relocation to this allocated, non-writable code. On an
/// unpacked library the file and memory bytes match when unpatched; on a packed library the file holds ciphertext
/// and the bootstrap restores plaintext in memory.
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
/// @return Where the `.text` section's bytes live, or nothing when the image isn't a little-endian ELF32 or ELF64 file,
/// has no `.text` section with bytes in the file, has a `.text` address that doesn't fit the process's addresses, or
/// the section doesn't lie wholly inside the file part of one loadable, executable, non-writable segment.
[[nodiscard]] std::optional<TextRegion> find_text_region(std::span<const std::uint8_t> image, std::uintptr_t load_bias);

/// Where a named section's bytes live in an ELF file image.
///
/// Unlike find_text_region this makes no claim about the section's flags or which segment maps it: it only finds the
/// section by name and checks its bytes lie inside the image. The key schedule uses it to read the library's
/// `.rasp_config` section, which is allocated and writable, not code.
struct SectionRegion {
  /// The offset of the section's bytes in the file.
  std::uint64_t file_offset = 0;
  /// The number of bytes in the section.
  std::uint64_t size = 0;
};

/// Finds the section named `name` in the ELF image whose file bytes are `image`, or nothing when the image isn't a
/// little-endian ELF32 or ELF64 file, has no section with that name, or the section's bytes reach outside the image.
///
/// @param image The bytes of the ELF file, read whole.
/// @param name The section's name, such as `.rasp_config`.
/// @return Where the section's bytes live in the file.
[[nodiscard]] std::optional<SectionRegion> find_section_region(std::span<const std::uint8_t> image,
                                                               std::string_view name);

/// The lowercase hexadecimal SHA-256 of `bytes`, or nothing when the crypto library can't compute it.
///
/// @param bytes The bytes to hash.
/// @return The 64-character hex digest, or nothing on a crypto error.
[[nodiscard]] std::optional<std::string> sha256_hex(std::span<const std::uint8_t> bytes);

/// The SHA-256 digest of `bytes`, or nothing when the crypto library can't compute it.
///
/// The key schedule binds the payload's keys to digests of the library's own sections; this is the digest it folds
/// in.
///
/// @param bytes The bytes to hash.
/// @return The 32-byte digest, or nothing on a crypto error.
[[nodiscard]] std::optional<std::array<std::uint8_t, kDigestSize>> sha256(std::span<const std::uint8_t> bytes);

/// The integ.text_sha256 observations for the library whose file is `library_path` and whose `.text` bytes are at
/// `text_memory` in the process.
///
/// It reads the file, finds its `.text` section and hashes the same count of bytes from `text_memory`. For the file
/// source, a nonzero expected plaintext digest in `.rasp_config` is reported directly; otherwise it hashes the
/// installed
/// `.text` bytes. The slot is attacker-patchable: its binding is enforced by the key schedule's fold, not by this
/// observation. This function does not touch the dynamic loader, so tests can supply their own file and memory span.
///
/// @param library_path The path of the installed library file.
/// @param text_memory The library's loaded image, starting at its load address. The function reads only the `.text`
/// bytes inside it, found from the file's section and program headers.
/// @return The file observation, then the memory observation. An observation has an error status when the file can't
/// be read, has no usable `.text` section, the section reaches past `text_memory`, or the hash can't be computed.
[[nodiscard]] std::vector<Observation> observe_text_hashes(std::string_view library_path,
                                                           std::span<const std::uint8_t> text_memory);

}  // namespace rasp::android::checks
