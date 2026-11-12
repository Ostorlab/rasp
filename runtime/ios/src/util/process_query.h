/// Validated opaque process-entry queries through the iOS arm64 native syscall boundary.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace rasp::ios::util {

/// The register result, or nothing when the native call sets the carry error flag.
using NativeSyscall = std::optional<std::uint64_t> (*)(std::uint64_t number,
                                                       const std::array<std::uint64_t, 6>& arguments);

/// Makes one arm64 Darwin syscall, returning unavailable on other architectures or Apple simulators.
/// @param number The native syscall number from the platform headers.
/// @param arguments Six native machine-word arguments.
/// @return The x0 result when carry is clear, or nothing on native error or unsupported architecture.
[[nodiscard]] std::optional<std::uint64_t> direct_syscall(std::uint64_t number,
                                                          const std::array<std::uint64_t, 6>& arguments);

/// The syscall numbers selected from the platform headers.
struct ProcessCalls {
  /// The native getpid syscall number.
  std::uint64_t getpid;
  /// The native sysctl syscall number.
  std::uint64_t sysctl;
};

/// Queries the current process and accepts only a complete native entry after successful calls.
/// @param name The four-element process MIB; its final element is replaced with the validated native getpid result.
/// @param entry The native entry's writable bytes, initialized by the caller.
/// @param calls The native getpid and sysctl syscall numbers.
/// @param invoke The system-call instruction boundary.
/// @return True only for a positive signed-32-bit PID, zero sysctl result and exact returned byte count.
[[nodiscard]] bool query_process(std::array<int, 4> name, std::span<std::byte> entry, ProcessCalls calls,
                                 NativeSyscall invoke = direct_syscall);

}  // namespace rasp::ios::util
