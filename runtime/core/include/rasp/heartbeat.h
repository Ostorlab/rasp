/// Heartbeat: the record that the monitoring thread is still running, and the integ.monitor_alive observation that
/// tells when it stopped.

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <limits>

#include "rasp/observation.h"
#include "rasp/schedule.h"

namespace rasp {

/// How long the monitoring thread may go without a beat before the heartbeat is stale: three of its longest waits.
inline constexpr std::chrono::seconds kHeartbeatBound = 3 * kMaxCheckInterval;
/// How long a heartbeat must have been seen stale before it is reported as stopped.
inline constexpr std::chrono::seconds kStaleConfirmation{10};

/// The record that a thread is still running: the thread beats, and any thread can observe whether it stopped.
///
/// A heartbeat is reported as stopped only when two observations, at least kStaleConfirmation apart, both find that the
/// last beat is older than kHeartbeatBound, and no beat came between them. The first such observation is only recorded.
/// So when the whole process is suspended and resumed, and the beating thread beats right after it resumes, the
/// heartbeat is never reported as stopped, however long the suspension lasted.
///
/// Every member function is safe to call from several threads at once. It has a `constexpr` constructor and no
/// destructor of its own, so a `constinit` variable of this type runs no code when the library loads or when the
/// process exits.
class Heartbeat {
 public:
  /// Records that the thread is running now.
  ///
  /// @param now The current time of the steady clock.
  void beat(std::chrono::steady_clock::time_point now) noexcept;

  /// Observes whether the thread that beats is still running.
  ///
  /// @param now The current time of the steady clock.
  /// @return One integ.monitor_alive observation read through heartbeat: `false` when the heartbeat is reported as
  /// stopped, as the class describes; `true` otherwise, including when it never beat.
  [[nodiscard]] Observation observe(std::chrono::steady_clock::time_point now) noexcept;

 private:
  /// The value of a time that hasn't happened.
  static constexpr std::int64_t kNever = std::numeric_limits<std::int64_t>::min();

  /// The time of the last beat, in nanoseconds of the steady clock, or kNever.
  std::atomic<std::int64_t> last_beat_{kNever};
  /// The time an observation first found the heartbeat stale, in nanoseconds of the steady clock, or kNever. It counts
  /// only while it is more than kHeartbeatBound after the last beat.
  std::atomic<std::int64_t> stale_since_{kNever};
};

/// The heartbeat of the runtime's monitoring thread.
///
/// @return The same heartbeat on every call, which lives as long as the process.
[[nodiscard]] Heartbeat& monitor_heartbeat() noexcept;

}  // namespace rasp
