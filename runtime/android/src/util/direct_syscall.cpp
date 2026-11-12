/// Bounded file and path probes through the hookable libc syscall entry, not inline assembly.

#include "util/direct_syscall.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <unistd.h>
#include <utility>

#ifdef __BIONIC__
// NOLINTNEXTLINE(misc-include-cleaner): bionic's canonical syscall header populates the architecture's __NR_ names.
#include <sys/syscall.h>
#else
#include <sys/syscall.h>
#endif

#ifdef __BIONIC__
#include <asm-generic/fcntl.h>
#include <bits/glibc-syscalls.h>
#include <linux/fcntl.h>
#else
#include <fcntl.h>
#endif

namespace rasp::android::util {
namespace {

/// The maximum content accepted by any caller.
constexpr std::size_t kMaxFileSize = std::size_t{4} << 20U;
/// The maximum interrupted reads before the observation becomes unavailable.
constexpr std::size_t kMaxInterrupts = 8;

/// Whether a path can be passed to a C native interface without changing its meaning.
[[nodiscard]] bool valid_path(std::string_view path) { return !path.empty() && !path.contains('\0'); }

/// Reads until EOF, rejecting partial data on error and bounding both memory and interruptions.
[[nodiscard]] std::optional<std::string> read_all(long descriptor, SystemCall invoke, std::size_t limit) {
  std::string content;
  std::array<char, 1024> chunk{};
  std::size_t interrupts = 0;
  while (true) {
    const std::size_t requested = std::min(chunk.size(), limit - content.size() + 1);
    const SyscallResult result = invoke(
        SYS_read, {static_cast<std::uintptr_t>(descriptor), std::bit_cast<std::uintptr_t>(chunk.data()), requested, 0});
    if (result.value == -1 && result.error == EINTR && interrupts < kMaxInterrupts) {
      ++interrupts;
      continue;
    }
    if (result.value < 0 || std::cmp_greater(result.value, requested) ||
        static_cast<std::size_t>(result.value) > limit - content.size()) {
      return std::nullopt;
    }
    if (result.value == 0) {
      return content;
    }
    content.append(chunk.data(), static_cast<std::size_t>(result.value));
  }
}

}  // namespace

SyscallResult libc_syscall(long number, const std::array<std::uintptr_t, 4>& arguments) {
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): the libc syscall entry is variadic.
  const long value = syscall(number, arguments[0], arguments[1], arguments[2], arguments[3]);
  return {.value = value, .error = errno};
}

std::optional<std::string> read_file_direct(std::string_view path, std::size_t limit, SystemCall invoke) {
  if (!valid_path(path) || limit > kMaxFileSize) {
    return std::nullopt;
  }
  const std::string name(path);
  const SyscallResult descriptor = invoke(SYS_openat, {
                                                          static_cast<std::uintptr_t>(AT_FDCWD),
                                                          std::bit_cast<std::uintptr_t>(name.c_str()),
                                                          O_RDONLY | O_CLOEXEC | O_NONBLOCK,
                                                          0,
                                                      });
  if (descriptor.value < 0 || descriptor.value > std::numeric_limits<int>::max()) {
    return std::nullopt;
  }
  std::optional<std::string> content = read_all(descriptor.value, invoke, limit);
  if (invoke(SYS_close, {static_cast<std::uintptr_t>(descriptor.value), 0, 0, 0}).value != 0) {
    return std::nullopt;
  }
  return content;
}

std::optional<bool> exists_direct(const std::string& path, SystemCall invoke) {
  if (!valid_path(path)) {
    return std::nullopt;
  }
  const SyscallResult result = invoke(
      SYS_faccessat, {static_cast<std::uintptr_t>(AT_FDCWD), std::bit_cast<std::uintptr_t>(path.c_str()), F_OK, 0});
  if (result.value == 0) {
    return true;
  }
  if (result.value == -1 && (result.error == ENOENT || result.error == ENOTDIR)) {
    return false;
  }
  return std::nullopt;
}

}  // namespace rasp::android::util
