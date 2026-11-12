/// POSIX boundary for the private Android suspend-inclusive gate clock.
#pragma once
#include <cstdint>
#include <optional>
#include <time.h>
#ifndef __ANDROID__
#include <bits/time.h>
#endif
#include "rasp/posix/cycle_clock.h"
namespace rasp::android {
/// Returns checked CLOCK_BOOTTIME nanoseconds; errors never synthesize time.
[[nodiscard]] inline std::optional<std::int64_t> read_suspend_clock() {
  timespec sample{};
  if (clock_gettime(CLOCK_BOOTTIME, &sample) != 0) {
    return std::nullopt;
  }
  return posix::monotonic_ticks(sample);
}
}  // namespace rasp::android
