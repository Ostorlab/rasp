/// read_file, which reads a whole file up to a size limit, for the Android checks that read files under /proc and
/// /sys.

#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace rasp::android::util {

/// Reads the file at `path` to its end.
///
/// The file is read in chunks, so files under /proc and /sys, whose size stat reports as 0, are read whole too. It is
/// opened with close-on-exec, so it never leaks into a process the app starts.
///
/// @param path The file to read.
/// @param limit The largest content accepted, in bytes.
/// @return The content of the file, or nothing when it can't be opened, read or closed, or is longer than `limit`
/// bytes.
[[nodiscard]] std::optional<std::string> read_file(std::string_view path, std::size_t limit);

}  // namespace rasp::android::util
