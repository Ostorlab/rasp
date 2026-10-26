/// The Mach-O reader of the iOS checks: bounds-checked reads of a thin 64-bit little-endian Mach-O header and its load
/// commands, from bytes in memory or from an open file. It draws only on the standard Mach-O layout of
/// `<mach-o/loader.h>`.

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace rasp::ios::util {

/// The size of a 64-bit Mach-O header, `mach_header_64`, in bytes.
inline constexpr std::size_t kMachHeaderSize = 32;

/// The most bytes of load commands the reader accepts. A real image has well under this.
inline constexpr std::size_t kMaxCommandsSize = std::size_t{1} << 20U;

/// Whether the range of `length` bytes at `offset` lies within a container of `size` bytes, checked without an
/// addition that could overflow, so a forged offset can't wrap a sum past the end and still pass.
///
/// @param offset The start of the range.
/// @param length The length of the range.
/// @param size The size of the container the range must fit in.
/// @return `true` when `offset <= size` and `length <= size - offset`.
[[nodiscard]] constexpr bool range_fits(std::uint64_t offset, std::uint64_t length, std::uint64_t size) {
  return offset <= size && length <= size - offset;
}

/// Reads the little-endian 32-bit number at `offset` in `bytes`, the byte order of an arm64 Mach-O image.
///
/// @param bytes The bytes that hold the number.
/// @param offset The offset of the number's first byte.
/// @return The number, or nothing when its four bytes don't lie within `bytes`.
[[nodiscard]] std::optional<std::uint32_t> read_little_endian(std::span<const std::uint8_t> bytes, std::size_t offset);

/// Reads the little-endian 64-bit number at `offset` in `bytes`, the byte order of an arm64 Mach-O image.
///
/// @param bytes The bytes that hold the number.
/// @param offset The offset of the number's first byte.
/// @return The number, or nothing when its eight bytes don't lie within `bytes`.
[[nodiscard]] std::optional<std::uint64_t> read_little_endian_64(std::span<const std::uint8_t> bytes,
                                                                 std::size_t offset);

/// The fields of a 64-bit Mach-O header that the reader uses.
struct MachHeader {
  /// The number of load commands, `ncmds`.
  std::uint32_t command_count = 0;
  /// The total size of the load commands in bytes, `sizeofcmds`.
  std::uint32_t commands_size = 0;
};

/// Reads the Mach-O header at the start of `bytes`.
///
/// @param bytes The bytes that start with the header.
/// @return The header, or nothing when `bytes` is shorter than a `mach_header_64`, its magic number isn't
/// `MH_MAGIC_64` read as a little-endian number, as in a universal file or a 32-bit one, or its load commands are
/// larger than kMaxCommandsSize bytes.
[[nodiscard]] std::optional<MachHeader> read_mach_header(std::span<const std::uint8_t> bytes);

/// One load command of a Mach-O image.
struct LoadCommand {
  /// The load command's type, `cmd`, such as `LC_SEGMENT_64`.
  std::uint32_t command = 0;
  /// The load command's bytes, as long as its `cmdsize` says, starting with its `cmd`. They point into the bytes
  /// load_commands was given, and are only valid while those are.
  std::span<const std::uint8_t> bytes;
};

/// Splits the load commands of the Mach-O image that starts at `image`.
///
/// The header is read as read_mach_header reads it. Each load command must be at least as long as the part every load
/// command starts with, its `cmd` and `cmdsize`, and lie wholly within the header's `sizeofcmds`, so the walk always
/// moves forward and stops at the end of the bytes.
///
/// @param image The bytes that start with the Mach-O header and hold at least its load commands.
/// @return The load commands in order, or nothing when read_mach_header gives nothing, when `image` is shorter than
/// the header and its load commands, or when a load command is shorter than its first part or reaches past the end of
/// the load commands.
[[nodiscard]] std::optional<std::vector<LoadCommand>> load_commands(std::span<const std::uint8_t> image);

/// Reads exactly `into.size()` bytes of `file`, starting at `offset`. A read that stores only part of what is left, or
/// that a signal interrupts, is retried for the rest.
///
/// @param file The open file to read.
/// @param offset Where in the file the bytes start.
/// @param into Where to store the bytes.
/// @return `true` when every byte was read, `false` when a read fails or the file ends first.
[[nodiscard]] bool read_exactly(int file, std::size_t offset, std::span<std::uint8_t> into);

/// What read_mach_file reads of a Mach-O file.
struct MachFile {
  /// The size of the file in bytes, as fstat reports it.
  std::size_t file_size = 0;
  /// The file's header and load commands, its first `kMachHeaderSize + sizeofcmds` bytes.
  std::vector<std::uint8_t> header_and_commands;
};

/// Reads the header and the load commands of the Mach-O file open as `file`.
///
/// @param file The open file.
/// @return The file's size and its first bytes up to the end of its load commands, or nothing when the file can't be
/// inspected, isn't a regular file, or a read fails, or when read_mach_header gives nothing for its header.
[[nodiscard]] std::optional<MachFile> read_mach_file(int file);

}  // namespace rasp::ios::util
