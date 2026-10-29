/// The installation id: generate-or-load from a file, using /dev/urandom for randomness.

#include "rasp/install_id.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <fcntl.h>
#include <optional>
#include <string>
#include <string_view>
#include <unistd.h>

namespace rasp {

namespace {

/// The file name inside the app's data directory.
constexpr std::string_view kFileName = ".rasp_install_id";

/// Reads exactly `count` bytes from `fd`.
///
/// @return `true` when all bytes were read.
[[nodiscard]] bool read_exact(int fd, std::uint8_t* buffer, std::size_t count) {
  std::size_t done = 0;
  while (done < count) {
    const ssize_t n = read(fd, buffer + done, count - done);
    if (n <= 0) {
      return false;
    }
    done += static_cast<std::size_t>(n);
  }
  return true;
}

/// Fills `id` with random bytes from /dev/urandom and sets the UUID v4 version and variant bits.
[[nodiscard]] bool generate(InstallId& id) {
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,misc-include-cleaner)
  const int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return false;
  }
  const bool ok = read_exact(fd, id.data(), id.size());
  close(fd);
  if (!ok) {
    return false;
  }
  // UUID v4: version nibble = 0100, variant bits = 10.
  id[6] = static_cast<std::uint8_t>((id[6] & 0x0FU) | 0x40U);
  id[8] = static_cast<std::uint8_t>((id[8] & 0x3FU) | 0x80U);
  return true;
}

/// Tries to read an existing install id from `path`.
[[nodiscard]] std::optional<InstallId> load(const std::string& path) {
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,misc-include-cleaner)
  const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return std::nullopt;
  }
  InstallId id{};
  const bool ok = read_exact(fd, id.data(), id.size());
  close(fd);
  if (!ok) {
    return std::nullopt;
  }
  // A valid file holds exactly 16 bytes. If there is more, it is not ours.
  std::uint8_t extra = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,misc-include-cleaner)
  const int check_fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (check_fd < 0) {
    return id;
  }
  if (lseek(check_fd, static_cast<off_t>(kInstallIdBytes), SEEK_SET) >= 0 && read(check_fd, &extra, 1) > 0) {
    close(check_fd);
    return std::nullopt;
  }
  close(check_fd);
  return id;
}

/// Writes `id` to `path`, creating or replacing the file.
[[nodiscard]] bool save(const std::string& path, const InstallId& id) {
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,misc-include-cleaner)
  const int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0) {
    return false;
  }
  std::size_t done = 0;
  while (done < id.size()) {
    const ssize_t n = write(fd, id.data() + done, id.size() - done);
    if (n <= 0) {
      close(fd);
      return false;
    }
    done += static_cast<std::size_t>(n);
  }
  close(fd);
  return true;
}

}  // namespace

std::optional<InstallId> get_or_create_install_id(std::string_view dir) {
  std::string path(dir);
  if (!path.empty() && path.back() != '/') {
    path += '/';
  }
  path += kFileName;

  std::optional<InstallId> existing = load(path);
  if (existing.has_value()) {
    return existing;
  }

  InstallId id{};
  if (!generate(id)) {
    return std::nullopt;
  }
  if (!save(path, id)) {
    return std::nullopt;
  }
  return id;
}

}  // namespace rasp
