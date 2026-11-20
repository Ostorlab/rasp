/// read_proc_file and first_proc_line_matching, which read kernel-generated files through direct system calls.

#include "raw_file.h"

#include <array>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#if defined(__linux__) && (defined(__x86_64__) || defined(__aarch64__))
#ifdef __ANDROID__
// Bionic takes AT_FDCWD from the kernel's uapi <linux/fcntl.h> and declares struct statfs in <sys/vfs.h>; glibc
// declares both in <fcntl.h> and <sys/statfs.h>.
#include <linux/fcntl.h>
#include <sys/vfs.h>
#else
#include <fcntl.h>
#include <sys/statfs.h>
#endif
#include <sys/syscall.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>

#include "rasp/util/read_file.h"
#endif

namespace rasp::util {

namespace {

/// The kernel returns errors as the negative errno in [-4095, -1], as libc's wrappers see too.
constexpr long kErrnoRange = 4095;

/// EINTR, the errno a direct system call reports when a signal whose handler wasn't installed with SA_RESTART
/// (https://man7.org/linux/man-pages/man7/signal.7.html) interrupts it — several of the handlers ART and bionic
/// install aren't. stdio's readers retry these silently; a raw
/// one reports them, so the open and the read retry it, and the close ignores it (the kernel has already freed the
/// descriptor), or a random signal would turn a sensor fact into an error observation, which the key schedule's gates
/// fold as a cleared gate and a wrong key.
constexpr long kEintr = 4;

/// Whether `r` is the kernel's encoding of an error, rather than a result or a return address.
[[nodiscard]] bool failed(long r) { return r < 0 && r >= -kErrnoRange; }

/// Feeds one chunk of a file to the line being assembled in `line`: each line the chunk completes is tested with
/// `matches`, and the first that matches is returned. The chunk's trailing part, with no line break yet, stays in
/// `line` for the next chunk.
[[nodiscard]] std::optional<std::string> first_completed_line_matching(std::string_view bytes, std::string& line,
                                                                       LinePredicate matches) {
  std::size_t start = 0;
  while (start < bytes.size()) {
    const std::size_t newline = bytes.find('\n', start);
    if (newline == std::string_view::npos) {
      line.append(bytes.substr(start));
      return std::nullopt;
    }
    line.append(bytes.substr(start, newline - start));
    if (matches(line)) {
      return line;
    }
    line.clear();
    start = newline + 1;
  }
  return std::nullopt;
}

#if defined(__linux__) && (defined(__x86_64__) || defined(__aarch64__))

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

/// EXDEV, the errno open_proc_file reports for a file that opened but doesn't live on one of the kernel's own
/// filesystems: the cross-device error, since the file sits on a device other than the ones the kernel generates
/// files on.
constexpr long kExdev = 18;

/// Opens `path` read-only with close-on-exec, as read_file's "re" mode does, but through a direct system call. An open
/// the kernel reports as interrupted is retried, the way the read loop below retries; an interrupted open creates no
/// descriptor, so the retry leaks none.
[[nodiscard]] long raw_open(std::string_view path) {
  const std::string name(path);
  long fd = -kEintr;
  while (fd == -kEintr) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    fd = raw_syscall(__NR_openat, static_cast<long>(AT_FDCWD), reinterpret_cast<long>(name.c_str()),
                     O_RDONLY | O_CLOEXEC, 0, 0, 0);
  }
  return fd;
}

/// Reads up to `size` bytes of `fd` into `data` through a direct system call: the count read, 0 at the end of the
/// file, or the negative errno.
// NOLINTNEXTLINE(misc-const-correctness): the kernel writes through `data`, which reaches it as an integer register.
[[nodiscard]] long read_some(long fd, char* data, std::size_t size) {
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  return raw_syscall(__NR_read, fd, reinterpret_cast<long>(data), static_cast<long>(size), 0, 0, 0);
}

/// Closes `fd` through a direct system call: 0, or the negative errno.
[[nodiscard]] long close_file(long fd) { return raw_syscall(__NR_close, fd, 0, 0, 0, 0, 0); }

/// Whether the open file `fd` lives on a filesystem whose files the kernel generates at read time.
///
/// The sensor files this reader serves come from procfs, sysfs and selinuxfs. Their bytes are built at read time:
/// sysfs attributes report the page size rather than any content length (the kernel's sysfs documentation,
/// https://docs.kernel.org/filesystems/sysfs.html, specifies "the buffer will always be PAGE_SIZE bytes in
/// length"), and a seq_file's seek handles only the start and the current position (fs/seq_file.c, seq_lseek:
/// https://github.com/torvalds/linux/blob/master/fs/seq_file.c), so an end-of-file size is not a fact these files
/// carry. A file someone wrote — a copy on storage, a memfd — holds its bytes elsewhere, so the filesystem the
/// descriptor sits on, not any size it claims, names a copy: an empty regular file reports no size and still isn't
/// the kernel's answer.
///
/// The magics are the uapi's stable numbers, from include/uapi/linux/magic.h
/// (https://github.com/torvalds/linux/blob/master/include/uapi/linux/magic.h), measured on the kernel this runtime
/// was verified against: procfs 0x9fa0, sysfs 0x62656572, selinuxfs 0xf97cff8c. The selinux magic matters wherever
/// /sys/fs/selinux/enforce is readable at all — the shell domain, platform builds and userdebug images read it.
///
/// @param fd The open file to test.
/// @return 0 when the file is one the kernel generates, so its content can be the kernel's answer; -EXDEV when it
/// opened but lives on a filesystem whose files hold stored bytes; and the negative errno fstatfs reported when the
/// kernel couldn't answer the question at all (statfs(2): EIO, EBADF, EFAULT, ENOMEM, ENOSYS), kept verbatim so a
/// caller reports the failure it had rather than one it didn't.
[[nodiscard]] long kernel_filesystem_verdict(long fd) {
  // The magics as the signed type statfs reports f_type in, so each comparison is between like integers.
  constexpr long kProcfsMagic = 0x9fa0;
  constexpr long kSysfsMagic = 0x62656572;
  constexpr long kSelinuxfsMagic = 0xf97cff8c;
  struct statfs filesystem{};
  const long stated =
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      raw_syscall(__NR_fstatfs, fd, reinterpret_cast<long>(&filesystem), 0, 0, 0, 0);
  if (failed(stated)) {
    return stated;
  }
  if (filesystem.f_type == kProcfsMagic || filesystem.f_type == kSysfsMagic || filesystem.f_type == kSelinuxfsMagic) {
    return 0;
  }
  return -kExdev;
}

#else

/// Reads up to `size` bytes of `fd` into `data` through libc, on a host the direct system calls don't serve: the count
/// read, 0 at the end of the file, or the negative errno, the way the direct call reports it.
[[nodiscard]] long read_some(long fd, char* data, std::size_t size) {
  const auto count = ::read(static_cast<int>(fd), data, size);
  return count < 0 ? -static_cast<long>(errno) : static_cast<long>(count);
}

/// Closes `fd` through libc: 0, or the negative errno.
[[nodiscard]] long close_file(long fd) { return ::close(static_cast<int>(fd)) == 0 ? 0 : -static_cast<long>(errno); }

#endif

}  // namespace

#if defined(__linux__) && (defined(__x86_64__) || defined(__aarch64__))

long open_proc_file(std::string_view path) {
  const long fd = raw_open(path);
  if (failed(fd)) {
    return fd;
  }
  // The verdict keeps its three cases apart: a file the kernel generates is handed out, a file that holds stored
  // bytes is closed and refused as -EXDEV, and a check the kernel couldn't make is closed and reported as the errno
  // it returned, so -EXDEV names only the stored-bytes refusal it documents.
  const long verdict = kernel_filesystem_verdict(fd);
  if (verdict != 0) {
    static_cast<void>(close_file(fd));
    return verdict;
  }
  return fd;
}

std::optional<std::string> read_proc_file(std::string_view path, std::size_t limit) {
  const long fd = open_proc_file(path);
  if (failed(fd)) {
    return std::nullopt;
  }
  std::string content;
  // read(2) may return fewer bytes than requested
  // (https://man7.org/linux/man-pages/man2/read.2.html), and a seq_file-backed /proc file returns at most one page
  // per read (Chromium's maps reader documents reading /proc/self/maps atomically as "next-to-impossible":
  // https://chromium.googlesource.com/chromium/src/+/main/base/debug/proc_maps_linux.cc), so the loop reads to the
  // end rather than trusting one call.
  std::array<char, 1024> chunk{};
  bool ok = true;
  while (true) {
    const long count = read_some(fd, chunk.data(), chunk.size());
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
  const long closed = close_file(fd);
  if (!ok || (failed(closed) && closed != -kEintr)) {
    return std::nullopt;
  }
  return content;
}

#else

long open_proc_file(std::string_view path) {
  // A host that isn't Linux on x86_64 or aarch64 opens through libc, so the code that scans the kernel's files builds
  // and runs everywhere; the device build is the one that matters, and it takes the direct-system-call path above.
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
  const int fd = ::open(std::string(path).c_str(), O_RDONLY | O_CLOEXEC);
  return fd < 0 ? -static_cast<long>(errno) : fd;
}

std::optional<std::string> read_proc_file(std::string_view path, std::size_t limit) {
  // A host that isn't Linux on x86_64 or aarch64 runs the portable reader, so the checks' tests build and run
  // everywhere; the device build is the one that matters, and it takes the direct-system-call path above.
  return read_file(path, limit);
}

#endif

std::optional<std::string> first_proc_line_matching(std::string_view path, LinePredicate matches, std::size_t cap,
                                                    ProcOpener open_file) {
  const long fd = open_file(path);
  // Any negative result is a failure, not only the kernel's errno range: the opener is pluggable, and no descriptor
  // is negative.
  if (fd < 0) {
    return std::nullopt;
  }
  std::array<char, 1024> chunk{};
  std::string line;
  std::size_t scanned = 0;
  std::optional<std::string> found;
  bool ok = true;
  // The same page-per-read behavior read_proc_file's comment names is why the scan carries a partial line between
  // chunks instead of assuming one read returns one line.
  while (scanned < cap) {
    const long count = read_some(fd, chunk.data(), chunk.size());
    if (count == -kEintr) {
      continue;
    }
    if (failed(count)) {
      ok = false;
      break;
    }
    if (count == 0) {
      // The file's last line counts even without a line break after it; a line the cap cut short never does.
      if (!line.empty() && matches(line)) {
        found = line;
      }
      break;
    }
    // The cap is a hard bound on the bytes examined: the last chunk is sliced to what remains of it, the way Go's
    // io.LimitedReader and Chromium's ReadFileToStringWithMaxSize clamp their final read, and a line the cap cuts
    // short never matches, the same way the file's end cuts one.
    const std::size_t room = cap - scanned;
    const bool capped = std::cmp_greater(count, room);
    const std::string_view bytes(chunk.data(), capped ? room : static_cast<std::size_t>(count));
    scanned += bytes.size();
    found = first_completed_line_matching(bytes, line, matches);
    // When the cap ended the scan mid-chunk, the partial line it leaves is never evaluated, exactly as a line the
    // file's end cuts short is not.
    if (found.has_value() || capped) {
      break;
    }
  }
  // close can report EINTR, but the kernel has already freed the descriptor, so a scan that finished is still kept.
  const long closed = close_file(fd);
  if (!ok || (failed(closed) && closed != -kEintr)) {
    return std::nullopt;
  }
  return found;
}

}  // namespace rasp::util
