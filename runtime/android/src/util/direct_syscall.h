/// Bounded second reads through libc's syscall entry, which can itself be hooked.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace rasp::android::util {

/// The result and captured errno of a libc syscall entry invocation.
struct SyscallResult {
  /// The return value; -1 indicates a libc failure.
  long value;
  /// The errno captured immediately after the call; meaningful only on failure.
  int error;
};

/// A replaceable native boundary taking up to four machine-word arguments.
using SystemCall = SyscallResult (*)(long number, const std::array<std::uintptr_t, 4>& arguments);

/// Invokes Linux's hookable libc syscall entry and captures its errno; other hosts return ENOSYS.
/// @param number The Linux syscall number.
/// @param arguments Four machine-word arguments, zero for unused slots.
/// @return The syscall return value and errno, without interpreting either.
[[nodiscard]] SyscallResult libc_syscall(long number, const std::array<std::uintptr_t, 4>& arguments);

/// Reads a file using openat/read/close through libc's syscall entry, with nonblocking and close-on-exec flags.
/// @param path A nonempty path without embedded null bytes.
/// @param limit The largest accepted content, up to 4 MiB.
/// @param invoke The native syscall boundary.
/// @return Complete content, or nothing on open/read/close failure, oversized content, invalid counts or after
/// eight interrupted reads. Short reads continue to EOF. The descriptor is closed exactly once, even on failure.
[[nodiscard]] std::optional<std::string> read_file_direct(std::string_view path, std::size_t limit,
                                                          SystemCall invoke = libc_syscall);

/// Looks up a path through libc's faccessat syscall entry, which can itself be hooked.
/// @param path A nonempty path without embedded null bytes.
/// @param invoke The native syscall boundary.
/// @return True for existence, false only for ENOENT/ENOTDIR, or nothing on denial or any other error.
[[nodiscard]] std::optional<bool> exists_direct(const std::string& path, SystemCall invoke = libc_syscall);

}  // namespace rasp::android::util
