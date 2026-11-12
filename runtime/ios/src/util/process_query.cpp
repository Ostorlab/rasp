/// Native syscall transport and complete-entry validation for the iOS debugger's second sources.
#include "util/process_query.h"

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#ifdef __APPLE__
#include <TargetConditionals.h>
#endif

namespace rasp::ios::util {
namespace {
/// Encodes a writable native argument without hiding its mutability from static analysis.
[[nodiscard]] std::uint64_t native_address(void* pointer) {
  return static_cast<std::uint64_t>(std::bit_cast<std::uintptr_t>(pointer));
}
}  // namespace

/// Makes the BSD system call `number` with `arguments` directly, through the `svc` instruction, so that no libc
/// function, and no hook on one, is in the way. It gives the call's result, or nothing when the kernel reports an
/// error. The kernel sets the carry flag on an error, and the registers the call may change are all marked as changed.
std::optional<std::uint64_t> direct_syscall(std::uint64_t number, const std::array<std::uint64_t, 6>& arguments) {
#if defined(__APPLE__) && defined(__aarch64__) && !TARGET_OS_SIMULATOR
  std::uint64_t result = 0;
  std::uint64_t carry = 0;
  // NOLINTNEXTLINE(portability-no-assembler): the direct system call is the point, so that no libc function is used.
  asm volatile(
      "mov x0, %[a0]\n"
      "mov x1, %[a1]\n"
      "mov x2, %[a2]\n"
      "mov x3, %[a3]\n"
      "mov x4, %[a4]\n"
      "mov x5, %[a5]\n"
      "mov x16, %[number]\n"
      "svc #0x80\n"
      "cset %[carry], cs\n"
      "mov %[result], x0\n"
      : [result] "=&r"(result), [carry] "=&r"(carry)
      : [number] "r"(number), [a0] "r"(arguments[0]), [a1] "r"(arguments[1]), [a2] "r"(arguments[2]),
        [a3] "r"(arguments[3]), [a4] "r"(arguments[4]), [a5] "r"(arguments[5])
      : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16",
        "x17", "memory", "cc");
  if (carry != 0) {
    return std::nullopt;
  }
  return result;
#else
  static_cast<void>(number);
  static_cast<void>(arguments);
  return std::nullopt;
#endif
}

bool query_process(std::array<int, 4> name, std::span<std::byte> entry, ProcessCalls calls, NativeSyscall invoke) {
  const std::optional<std::uint64_t> pid = invoke(calls.getpid, {});
  if (!pid.has_value() || *pid == 0 || *pid > static_cast<std::uint64_t>(std::numeric_limits<std::int32_t>::max()) ||
      entry.empty()) {
    return false;
  }
  name[3] = static_cast<int>(*pid);
  std::size_t size = entry.size();
  const std::optional<std::uint64_t> result = invoke(calls.sysctl, {
                                                                       native_address(name.data()),
                                                                       name.size(),
                                                                       native_address(entry.data()),
                                                                       native_address(&size),
                                                                       0,
                                                                       0,
                                                                   });
  return result.has_value() && *result == 0 && size == entry.size();
}

}  // namespace rasp::ios::util
