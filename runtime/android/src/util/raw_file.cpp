/// read_proc_file, which reads a whole kernel-generated file through direct system calls.

#include "raw_file.h"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

#if defined(__linux__) && (defined(__x86_64__) || defined(__aarch64__))

#include <array>
#include <fcntl.h>
#include <sys/syscall.h>

namespace rasp::util {

namespace {

// NOLINTBEGIN(portability-no-assembler, misc-const-correctness): this reader exists to issue raw system calls through
// inline assembler, and the result register it writes through an output operand can't be declared const.
#ifdef __aarch64__
/// An aarch64 syscall: number in x8, arguments in x0..x5, result in x0.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
long raw_syscall(long nr, long a0, long a1, long a2, long a3, long a4, long a5) {
  register const long x8 __asm__("x8") = nr;
  register long x0 __asm__("x0") = a0;
  register const long x1 __asm__("x1") = a1;
  register const long x2 __asm__("x2") = a2;
  register const long x3 __asm__("x3") = a3;
  register const long x4 __asm__("x4") = a4;
  register const long x5 __asm__("x5") = a5;
  __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5) : "memory", "cc");
  return x0;
}
#elifdef __x86_64__
/// An x86_64 syscall: number in rax, arguments in rdi/rsi/rdx/r10/r8/r9, result in rax.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
long raw_syscall(long nr, long a0, long a1, long a2, long a3, long a4, long a5) {
  long ret = 0;
  register const long r10 __asm__("r10") = a3;
  register const long r8 __asm__("r8") = a4;
  register const long r9 __asm__("r9") = a5;
  __asm__ volatile("syscall"
                   : "=a"(ret)
                   : "a"(nr), "D"(a0), "S"(a1), "d"(a2), "r"(r10), "r"(r8), "r"(r9)
                   : "rcx", "r11", "memory");
  return ret;
}
#endif
// NOLINTEND(portability-no-assembler, misc-const-correctness)

/// The kernel returns errors as the negative errno in [-4095, -1], as libc's wrappers see too.
constexpr long kErrnoRange = 4095;

/// EINTR, the errno a direct system call reports when a signal whose handler wasn't installed with SA_RESTART
/// interrupts it — several of the handlers ART and bionic install aren't. stdio's readers retry these silently; a raw
/// one reports them, so the open and the read retry it, and the close ignores it (the kernel has already freed the
/// descriptor), or a random signal would turn a sensor fact into an error observation, which the key schedule's gates
/// fold as a cleared gate and a wrong key.
constexpr long kEintr = 4;

/// lseek's whence values, named here so the reader needs no libc header for them: the start of the file, and its end.
constexpr long kSeekSet = 0;
constexpr long kSeekEnd = 2;

/// Whether `r` is the kernel's encoding of an error, rather than a result or a return address.
[[nodiscard]] bool failed(long r) { return r < 0 && r >= -kErrnoRange; }

/// Opens `path` read-only with close-on-exec, as read_file's "re" mode does, but through a direct system call. An open
/// the kernel reports as interrupted is retried, the way the read loop below retries; an interrupted open creates no
/// descriptor, so the retry leaks none.
[[nodiscard]] long raw_open(std::string_view path) {
  const std::string name(path);
  long fd = 0;
  do {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    fd = raw_syscall(__NR_openat, static_cast<long>(AT_FDCWD), reinterpret_cast<long>(name.c_str()),
                     O_RDONLY | O_CLOEXEC, 0, 0, 0);
  } while (fd == -kEintr);
  return fd;
}

/// Whether the open file `fd` names is a copy someone wrote, not a file the kernel generates at read time.
///
/// Kernel-generated files — /proc and /sys — report no size, because their bytes don't exist until they are read. A
/// regular file or a memfd holds its bytes, so seeking to its end answers a size. The kernel refuses the seek on some
/// of its generated files instead, which names the same fact: nothing is stored to seek to.
///
/// @param fd The open file to test.
/// @return `true` when the file reports stored bytes, so its content can't be the kernel's answer.
[[nodiscard]] bool is_redirected(long fd) {
  const long end = raw_syscall(__NR_lseek, fd, 0, kSeekEnd, 0, 0, 0);
  if (!failed(end) && end > 0) {
    return true;
  }
  raw_syscall(__NR_lseek, fd, 0, kSeekSet, 0, 0, 0);
  return false;
}

}  // namespace

std::optional<std::string> read_proc_file(std::string_view path, std::size_t limit) {
  const long fd = raw_open(path);
  if (failed(fd)) {
    return std::nullopt;
  }
  std::string content;
  std::array<char, 1024> chunk{};
  bool ok = !is_redirected(fd);
  while (ok) {
    const long count =
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        raw_syscall(__NR_read, fd, reinterpret_cast<long>(chunk.data()), static_cast<long>(chunk.size()), 0, 0, 0);
    if (count == -kEintr) {
      continue;
    }
    if (failed(count) || static_cast<std::size_t>(count) > limit - content.size()) {
      ok = false;
      break;
    }
    content.append(chunk.data(), static_cast<std::size_t>(count));
    if (count == 0) {
      break;
    }
  }
  // close can report EINTR, but the kernel has already freed the descriptor, so a read that finished is still kept.
  const long closed = raw_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
  if (!ok || (failed(closed) && closed != -kEintr)) {
    return std::nullopt;
  }
  return content;
}

}  // namespace rasp::util

#else

#include "rasp/util/read_file.h"

namespace rasp::util {

std::optional<std::string> read_proc_file(std::string_view path, std::size_t limit) {
  // A host that isn't Linux on x86_64 or aarch64 runs the portable reader, so the checks' tests build and run
  // everywhere; the device build is the one that matters, and it takes the direct-system-call path above.
  return read_file(path, limit);
}

}  // namespace rasp::util

#endif
