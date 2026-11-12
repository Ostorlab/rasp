/// Controlled libc syscall file boundary for second-source production probes.
#pragma once
#include <algorithm>
#include <array>
#include <bit>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <sys/syscall.h>

#include "util/direct_syscall.h"

namespace rasp::test_support {

/// A single-thread-local native file fixture, with real production read/parse/close logic above it.
struct SyscallFile {
  std::string_view content;
  std::size_t position = 0;
  int error = 0;
  int close_count = 0;
  static thread_local SyscallFile* active;

  /// Handles only the native boundary operations used by the probes.
  [[nodiscard]] static android::util::SyscallResult invoke(long number,
                                                           const std::array<std::uintptr_t, 4>& arguments) {
    if (number == SYS_openat) {
      return {.value = 42, .error = 0};
    }
    if (number == SYS_close) {
      ++active->close_count;
      return {.value = 0, .error = 0};
    }
    if (number == SYS_faccessat) {
      return {.value = -1, .error = active->error};
    }
    if (number != SYS_read || active->error != 0) {
      return {.value = -1, .error = active->error};
    }
    const std::size_t count = std::min(arguments[2], active->content.size() - active->position);
    if (count != 0) {
      std::memcpy(std::bit_cast<void*>(arguments[1]), active->content.substr(active->position).data(), count);
    }
    active->position += count;
    return {.value = static_cast<long>(count), .error = 0};
  }
};
inline thread_local SyscallFile* SyscallFile::active = nullptr;

}  // namespace rasp::test_support
