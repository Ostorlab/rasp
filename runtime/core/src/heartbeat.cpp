/// Heartbeat: the monitoring thread's beats, and the integ.monitor_alive observation that judges them.

#include "rasp/heartbeat.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <string_view>

#include "rasp/observation.h"

namespace rasp {

namespace {

/// The signal of the observation.
constexpr std::string_view kMonitorAliveSignal = "integ.monitor_alive";
/// The source of the observation.
constexpr std::string_view kHeartbeatSource = "heartbeat";

/// The time `now`, in nanoseconds of the steady clock.
[[nodiscard]] std::int64_t nanoseconds_of(std::chrono::steady_clock::time_point now) {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
}

/// kHeartbeatBound in nanoseconds.
constexpr std::int64_t kBound = std::chrono::nanoseconds(kHeartbeatBound).count();
/// kStaleConfirmation in nanoseconds.
constexpr std::int64_t kConfirmation = std::chrono::nanoseconds(kStaleConfirmation).count();

/// The observation that the thread is running, when `alive`, or stopped.
[[nodiscard]] Observation alive_observation(bool alive) {
  return observed(kMonitorAliveSignal, kHeartbeatSource, alive);
}

}  // namespace

void Heartbeat::beat(std::chrono::steady_clock::time_point now) noexcept {
  last_beat_.store(nanoseconds_of(now), std::memory_order_release);
}

Observation Heartbeat::observe(std::chrono::steady_clock::time_point now) noexcept {
  const std::int64_t at = nanoseconds_of(now);
  const std::int64_t last = last_beat_.load(std::memory_order_acquire);
  if (last == kNever || at - last <= kBound) {
    return alive_observation(true);
  }
  std::int64_t since = stale_since_.load(std::memory_order_acquire);
  if (since == kNever || since - last <= kBound) {
    static_cast<void>(stale_since_.compare_exchange_strong(since, at, std::memory_order_acq_rel));
    return alive_observation(true);
  }
  return alive_observation(at - since < kConfirmation);
}

Heartbeat& monitor_heartbeat() noexcept {
  static constinit Heartbeat heartbeat;
  return heartbeat;
}

}  // namespace rasp
