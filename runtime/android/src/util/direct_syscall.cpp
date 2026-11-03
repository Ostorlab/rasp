/// Reading a file and looking up a path through direct system calls, for the checks that read a signal a second way.

#include "util/direct_syscall.h"

#include <array>
#include <cerrno>
#include <cstddef>
// NOLINTNEXTLINE(misc-include-cleaner): bionic defines the AT_ and O_ flags in a header that <fcntl.h> includes.
#include <fcntl.h>
#include <optional>
#include <string>
#include <string_view>
// NOLINTNEXTLINE(misc-include-cleaner): bionic defines the SYS_ numbers in a header that <sys/syscall.h> includes.
#include <sys/syscall.h>
#include <unistd.h>

namespace rasp::android::util {

namespace {

/// The size of each chunk read.
constexpr std::size_t kChunkSize = 1024;

}  // namespace

std::optional<std::string> read_file_direct(std::string_view path, std::size_t limit) {
  const std::string name(path);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,misc-include-cleaner): syscall is variadic, and its SYS_ and flag macros come from the included <sys/syscall.h> and <fcntl.h>.
  const long descriptor = syscall(SYS_openat, AT_FDCWD, name.c_str(), O_RDONLY | O_CLOEXEC);
  if (descriptor < 0) {
    return std::nullopt;
  }
  std::optional<std::string> content = std::string();
  std::array<char, kChunkSize> chunk{};
  while (true) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,misc-include-cleaner): syscall is variadic, and its SYS_ and flag macros come from the included <sys/syscall.h> and <fcntl.h>.
    const long count = syscall(SYS_read, descriptor, chunk.data(), chunk.size());
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count == 0) {
      break;
    }
    if (count < 0 || static_cast<std::size_t>(count) > limit - content->size()) {
      content.reset();
      break;
    }
    content->append(chunk.data(), static_cast<std::size_t>(count));
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,misc-include-cleaner): syscall is variadic, and its SYS_ and flag macros come from the included <sys/syscall.h> and <fcntl.h>.
  if (syscall(SYS_close, descriptor) != 0) {
    return std::nullopt;
  }
  return content;
}

bool exists_direct(const std::string& path) {
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,misc-include-cleaner): syscall is variadic, and its SYS_ and flag macros come from the included <sys/syscall.h> and <fcntl.h>.
  return syscall(SYS_faccessat, AT_FDCWD, path.c_str(), F_OK) == 0;
}

}  // namespace rasp::android::util
