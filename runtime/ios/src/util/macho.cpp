/// The Mach-O reader of the iOS checks: the header, load-command and file reads, each checked against the bytes that
/// hold it.

#include "util/macho.h"

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace rasp::ios::util {

namespace {

/// `MH_MAGIC_64`, the magic number of a 64-bit Mach-O image, read as a little-endian number.
constexpr std::uint32_t kMachMagic64 = 0xFEEDFACF;
/// The offset of the header's number of load commands, `ncmds`.
constexpr std::size_t kCommandCountOffset = 16;
/// The offset of the header's total size of the load commands, `sizeofcmds`.
constexpr std::size_t kCommandsSizeOffset = 20;
/// The size of the part every load command starts with, its `cmd` and `cmdsize`, in bytes.
constexpr std::size_t kCommandHeaderSize = 8;
/// The offset of a load command's size, `cmdsize`.
constexpr std::size_t kCommandSizeOffset = 4;

}  // namespace

std::optional<std::uint32_t> read_little_endian(std::span<const std::uint8_t> bytes, std::size_t offset) {
  if (!range_fits(offset, sizeof(std::uint32_t), bytes.size())) {
    return std::nullopt;
  }
  const std::span<const std::uint8_t> field = bytes.subspan(offset, sizeof(std::uint32_t));
  return std::uint32_t{field[0]} | (std::uint32_t{field[1]} << 8U) | (std::uint32_t{field[2]} << 16U) |
         (std::uint32_t{field[3]} << 24U);
}

std::optional<std::uint64_t> read_little_endian_64(std::span<const std::uint8_t> bytes, std::size_t offset) {
  if (!range_fits(offset, sizeof(std::uint64_t), bytes.size())) {
    return std::nullopt;
  }
  const std::optional<std::uint32_t> low = read_little_endian(bytes, offset);
  const std::optional<std::uint32_t> high = read_little_endian(bytes, offset + sizeof(std::uint32_t));
  if (!low || !high) {
    return std::nullopt;
  }
  return std::uint64_t{*low} | (std::uint64_t{*high} << 32U);
}

std::optional<MachHeader> read_mach_header(std::span<const std::uint8_t> bytes) {
  if (bytes.size() < kMachHeaderSize) {
    return std::nullopt;
  }
  const std::optional<std::uint32_t> magic = read_little_endian(bytes, 0);
  const std::optional<std::uint32_t> count = read_little_endian(bytes, kCommandCountOffset);
  const std::optional<std::uint32_t> commands_size = read_little_endian(bytes, kCommandsSizeOffset);
  if (!magic || !count || !commands_size || *magic != kMachMagic64 || *commands_size > kMaxCommandsSize) {
    return std::nullopt;
  }
  return MachHeader{.command_count = *count, .commands_size = *commands_size};
}

std::optional<std::vector<LoadCommand>> load_commands(std::span<const std::uint8_t> image) {
  const std::optional<MachHeader> header = read_mach_header(image);
  if (!header || !range_fits(kMachHeaderSize, header->commands_size, image.size())) {
    return std::nullopt;
  }
  const std::span<const std::uint8_t> commands = image.subspan(kMachHeaderSize, header->commands_size);
  std::vector<LoadCommand> result;
  std::size_t offset = 0;
  for (std::uint32_t index = 0; index < header->command_count; ++index) {
    const std::optional<std::uint32_t> command = read_little_endian(commands, offset);
    const std::optional<std::uint32_t> command_size = read_little_endian(commands, offset + kCommandSizeOffset);
    if (!command || !command_size || *command_size < kCommandHeaderSize ||
        !range_fits(offset, *command_size, commands.size())) {
      return std::nullopt;
    }
    result.push_back(LoadCommand{.command = *command, .bytes = commands.subspan(offset, *command_size)});
    offset += *command_size;
  }
  return result;
}

bool read_exactly(int file, std::size_t offset, std::span<std::uint8_t> into) {
  while (!into.empty()) {
    const ssize_t count = pread(file, into.data(), into.size(), static_cast<off_t>(offset));
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count <= 0) {
      return false;
    }
    offset += static_cast<std::size_t>(count);
    into = into.subspan(static_cast<std::size_t>(count));
  }
  return true;
}

std::optional<MachFile> read_mach_file(int file) {
  struct stat status{};
  if (fstat(file, &status) != 0 || !S_ISREG(status.st_mode) || status.st_size < 0) {
    return std::nullopt;
  }
  std::array<std::uint8_t, kMachHeaderSize> header_bytes{};
  if (!read_exactly(file, 0, header_bytes)) {
    return std::nullopt;
  }
  const std::optional<MachHeader> header = read_mach_header(header_bytes);
  if (!header) {
    return std::nullopt;
  }
  std::vector<std::uint8_t> header_and_commands(kMachHeaderSize + header->commands_size);
  if (!read_exactly(file, 0, header_and_commands)) {
    return std::nullopt;
  }
  return MachFile{
      .file_size = static_cast<std::size_t>(status.st_size),
      .header_and_commands = std::move(header_and_commands),
  };
}

}  // namespace rasp::ios::util
