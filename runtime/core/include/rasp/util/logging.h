/// Development logging. Release builds write no log at all.

#pragma once

#include <string_view>

namespace rasp {

/// Whether this build writes development logs. Only development builds do: a release build writes nothing to any log.
inline constexpr bool kLoggingEnabled = RASP_LOGGING_ENABLED;

/// Writes one line to the platform's log, in a development build.
///
/// Call it only inside `if constexpr (kLoggingEnabled)`. Release builds don't define this function, so neither the
/// call nor its text ends up in the binary. On iOS, the line goes to the system log through os_log, after the prefix
/// `RaspRuntime`. On Android, it goes to the system log through __android_log_write, with the tag `RaspRuntime`.
///
/// @param message The text of the line.
void log(std::string_view message) noexcept;

}  // namespace rasp
