/// Reading a file and looking up a path through direct system calls, for the checks that read a signal a second way.
///
/// The checks' first source reads through libc functions such as `fopen`, `read` and `access`, which a hooking tool
/// can replace to hide what the check looks for. These helpers make the same requests through libc's `syscall`
/// function instead, which goes straight to the kernel, so a hook on the usual libc functions doesn't change what
/// they return.

#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace rasp::android::util {

/// Reads the file at `path` to its end, through the openat, read and close system calls.
///
/// The file is read in chunks, so files under /proc, whose size stat reports as 0, are read whole too. It is opened
/// with close-on-exec, so it never leaks into a process the app starts. A read that a signal interrupts is retried.
///
/// @param path The file to read.
/// @param limit The largest content accepted, in bytes.
/// @return The content of the file, or nothing when it can't be opened, read or closed, or is longer than `limit`
/// bytes.
[[nodiscard]] std::optional<std::string> read_file_direct(std::string_view path, std::size_t limit);

/// Whether a file exists at `path`, through the faccessat system call.
///
/// It asks the same question as `access(path, F_OK)`, which bionic answers with this same system call.
///
/// @param path The path to look up.
/// @return `true` when the kernel finds a file at `path`, and `false` when it doesn't or can't look the path up.
[[nodiscard]] bool exists_direct(const std::string& path);

}  // namespace rasp::android::util
