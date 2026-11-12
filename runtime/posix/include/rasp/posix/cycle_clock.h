/// Shared POSIX clock implementation used by both actual platform clock adapters.
#pragma once
#include <cstdint>
#include <limits>
#include <optional>
#include <time.h>
#include <utility>

#include "rasp/cycle.h"
namespace rasp::posix {
/// Converts a validated monotonic timespec without overflow or negative pseudo-time.
/// @param sample Platform monotonic seconds and nanoseconds.
/// @return Nonnegative ticks, or unavailable for invalid/overflowing samples.
[[nodiscard]] inline std::optional<std::int64_t> monotonic_ticks(const timespec& sample) {
  constexpr std::uint64_t kNanosecondsPerSecond = 1000000000;
  constexpr auto kMaxTicks = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
  if (sample.tv_sec < 0 || sample.tv_nsec < 0 || std::cmp_greater_equal(sample.tv_nsec, kNanosecondsPerSecond)) {
    return std::nullopt;
  }
  const auto seconds = static_cast<std::uint64_t>(sample.tv_sec);
  if (seconds > kMaxTicks / kNanosecondsPerSecond) {
    return std::nullopt;
  }
  const std::uint64_t ticks = (seconds * kNanosecondsPerSecond) + static_cast<std::uint64_t>(sample.tv_nsec);
  return ticks <= kMaxTicks ? std::optional(static_cast<std::int64_t>(ticks)) : std::nullopt;
}
/// Samples checked monotonic and wall-clock values shared by Android and iOS.
/// @tparam Reader Platform clock reader; injectable for failure tests.
/// @param reader Checked POSIX clock API, normally clock_gettime.
/// @return Available readings only; errors and invalid/overflowing times are absent.
template <typename Reader = decltype(&clock_gettime)>
[[nodiscard]] CycleClockReading read_cycle_clock(Reader reader = clock_gettime) {
  CycleClockReading reading;
  timespec monotonic{};
  if (reader(CLOCK_MONOTONIC, &monotonic) == 0) {
    reading.monotonic_ns = monotonic_ticks(monotonic);
  }
  timespec wall{};
  constexpr std::int64_t kMinWallSeconds = 946684800;
  constexpr std::int64_t kMaxWallSeconds = 4102444800;
  if (reader(CLOCK_REALTIME, &wall) == 0 && wall.tv_sec >= kMinWallSeconds && wall.tv_sec < kMaxWallSeconds &&
      wall.tv_nsec >= 0 && wall.tv_nsec < 1000000000) {
    reading.unix_ms =
        (static_cast<std::int64_t>(wall.tv_sec) * 1000) + (static_cast<std::int64_t>(wall.tv_nsec) / 1000000);
  }
  return reading;
}
}  // namespace rasp::posix
