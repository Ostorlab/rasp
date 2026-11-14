/// When the checks run: the random wait between two runs of the monitoring thread, and RateLimit, which lets a check
/// that runs on the app's own threads run at most once per interval.

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <limits>

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

/// Lets an action run at most once per interval, whichever thread asks.
///
/// Many threads may ask at the same time, and at most one of them is let through per interval. It has a `constexpr`
/// constructor and no destructor of its own, so a `constinit` variable of this type runs no code when the library loads
/// or when the process exits.
class RateLimit {
 public:
  /// Creates a limit that has let nothing through yet, so the first call to try_acquire is let through.
  ///
  /// @param interval The shortest time between two calls that are let through.
  constexpr explicit RateLimit(std::chrono::nanoseconds interval) noexcept : interval_(interval.count()) {}

  /// Asks to run the action now.
  ///
  /// @param now The current time of the steady clock.
  /// @return `true` for the one caller that is let through: the first call, then the first call at least the interval
  /// after the last call that was let through. `false` for every other call.
  [[nodiscard, gnu::always_inline]] bool try_acquire(std::chrono::steady_clock::time_point now) noexcept {
    const std::int64_t at = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
    std::int64_t next = next_.load(std::memory_order_relaxed);
    if (at < next) {
      return false;
    }
    return next_.compare_exchange_strong(next, at + interval_, std::memory_order_relaxed);
  }

 private:
  /// The shortest time between two calls that are let through, in nanoseconds.
  std::int64_t interval_;
  /// The earliest time, in nanoseconds of the steady clock, at which the next call is let through.
  std::atomic<std::int64_t> next_{std::numeric_limits<std::int64_t>::min()};
};

}  // namespace rasp
