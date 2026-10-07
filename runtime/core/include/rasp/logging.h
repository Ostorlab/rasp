#pragma once

#include <string_view>

namespace rasp {

/// Whether this build writes development logs. Only development builds do: a release build writes nothing to any log.
inline constexpr bool kLoggingEnabled = RASP_LOGGING_ENABLED;

/// Writes one line to the platform's log. Call it only inside `if constexpr (kLoggingEnabled)`: release builds don't
/// define it, so neither the call nor its text ends up in the binary.
void log(std::string_view message) noexcept;

}  // namespace rasp
