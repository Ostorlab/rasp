/// When the checks run: the random wait between two runs of the monitoring thread.

#pragma once

#include <chrono>

namespace rasp {

/// The shortest wait between two runs of the monitoring thread.
inline constexpr std::chrono::seconds kMinCheckInterval{30};
/// The longest wait between two runs of the monitoring thread.
inline constexpr std::chrono::seconds kMaxCheckInterval{90};

/// Picks how long the monitoring thread waits before its next run.
///
/// Each call draws a new wait, from a source of randomness that can't fail.
///
/// @return A random wait, from kMinCheckInterval to kMaxCheckInterval, in whole milliseconds.
[[nodiscard]] std::chrono::milliseconds check_interval() noexcept;

}  // namespace rasp
