/// Primitive-only UIKit capture handoff; no platform objects cross this boundary.
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <pthread.h>
#include <string_view>

#include "rasp/cycle.h"

namespace rasp::ios::capture {
/// Actual build/OS capability, independent of host opt-in.
enum class Platform : std::uint8_t { kUnsupported, kLegacy, kScene };
/// Checked UIKit adapter availability, separate from an observed negative value.
enum class Availability : std::uint8_t {
  kUnsupported,
  kNeverStarted,
  kNotRequested,
  kExhausted,
  kTeardownError,
  kRegistrationError,
  kError,
  kDeactivated,
  kNoSelection,
  kDisconnected,
  kOwnerGone,
  kInactive,
  kClockUnavailable,
  kStale,
  kUnavailableState,
  kNotSelected,
  kActive,
};
/// One selected scene or display, never a device-wide recording claim.
enum class Scope : std::uint8_t { kNone, kScene, kScreen };
/// Initial/resume sample, actual platform callback, or explicit/timer read.
enum class SampleKind : std::uint8_t { kInitial, kCallback, kResample };
/// Owned scalar snapshot of one source, with counters since its last selected drain.
struct SourceSnapshot {
  Availability availability = Availability::kNeverStarted;
  Scope scope = Scope::kNone;
  std::int64_t epoch = 0;
  int state = -1;
  bool registered = false;
  std::optional<std::int64_t> sampled_ns;
  std::int64_t serial = 0;
  std::int64_t callbacks = 0;
  std::int64_t ignored = 0;
  std::int64_t lost = 0;
  std::int64_t initial = 0;
  std::int64_t changes = 0;
  std::int64_t resamples = 0;
  bool overflow = false;
  std::int64_t interval_ms = -1;
  std::int64_t age_ms = -1;
};
/// One atomic cut of independently selected reducers.
struct Snapshot {
  std::array<SourceSnapshot, 2> sources{};
  bool valid = true;
};
/// Fixed counters and current state shared by main-thread UIKit and the monitor.
class CaptureEvents {
 public:
  /// Constructs bounded primitive state with a checked clock and optional finite saturation ceiling.
  /// @param clock The same monotonic domain on producer and consumer; must be non-null.
  /// @param ceiling Counter/epoch ceiling, INT64_MAX in production.
  explicit constexpr CaptureEvents(CycleClockReading (*clock)() = read_cycle_clock, std::int64_t ceiling = INT64_MAX)
      : clock_(clock), ceiling_(ceiling) {}
  /// Starts opt-in without claiming observer ownership; pending deltas survive.
  /// @param screenshots Screenshot opt-in.
  /// @param recording Capture-state opt-in.
  /// @return Positive session epoch, zero for invalid/conflicting options or exhaustion.
  [[nodiscard]] std::int64_t start(bool screenshots, bool recording);
  /// Invalidates all current ownership before adapter cleanup.
  /// @param session Exact session to stop.
  void stop(std::int64_t session);
  /// Confirms successful adapter cleanup after stop, clearing only retained failure state.
  /// @param session Exact stopped session whose owned slots were actually removed.
  void cleanup_complete(std::int64_t session);
  /// Confirms actual screenshot registration and current application activity on main.
  /// @param session Current session.
  /// @param active Whether the application is currently active.
  void screenshot_ready(std::int64_t session, bool active);
  /// Counts a delivered notification using primitive session/activity state only.
  /// @param session Registration session captured by the block.
  void screenshot(std::int64_t session);
  /// Opens a new selection/resume generation, unavailable until registration and sample both succeed.
  /// @param session Current session.
  /// @param scope Actual selected API scope.
  /// @return Positive generation, zero on invalid session/exhaustion.
  [[nodiscard]] std::int64_t open(std::int64_t session, Scope scope);
  /// Confirms the exact actual registration; cannot manufacture a sample.
  /// @param session Current session.
  /// @param generation Current selection generation.
  void registered(std::int64_t session, std::int64_t generation);
  /// Reserves sample order before reading UIKit, so reentrant newer reads cannot be overwritten.
  /// @param session Current session.
  /// @param generation Current selection generation.
  /// @return Positive order ticket, zero if invalid/exhausted.
  [[nodiscard]] std::int64_t ticket(std::int64_t session, std::int64_t generation);
  /// Publishes a current primitive sample after the main-thread read.
  /// @param session Current session.
  /// @param generation Exact selected registration.
  /// @param serial Ticket reserved before reading.
  /// @param kind Sample reason, not inferred recording duration.
  /// @param state Scene inactive=0/active=1/unspecified=2; screen false=0/true=1.
  void sample(std::int64_t session, std::int64_t generation, std::int64_t serial, SampleKind kind, int state);
  /// Closes recording ownership before any UIKit cleanup, retaining pending counters.
  /// @param session Current session.
  /// @param reason Exact unavailable reason; active is forbidden.
  void invalidate(std::int64_t session, Availability reason);
  /// Reports source setup/cleanup failure without touching the other source.
  /// @param session Current or just-stopped session.
  /// @param source Screenshot=0, capture=1.
  /// @param reason Registration, cleanup or other failure.
  void failure(std::int64_t session, int source, Availability reason);
  /// Rejects old/invalid callback ingress; current off-main ingress invalidates its source.
  /// @param session Captured session.
  /// @param source Screenshot=0, capture=1.
  /// @param generation Captured capture generation, zero for screenshot.
  /// @param fault Current callback violated thread/input contract.
  void reject(std::int64_t session, int source, std::int64_t generation, bool fault);
  /// Copies one common cut, resetting only selected deltas and interval boundaries.
  /// @param screenshots Whether screenshot group is enabled.
  /// @param recording Whether recording group is enabled.
  /// @return Owned primitive state with effective freshness, no UIKit access.
  [[nodiscard]] Snapshot drain(bool screenshots, bool recording);

 private:
  /// Fallible primitive-only mutex guard.
  class Lock {
   public:
    explicit Lock(pthread_mutex_t& mutex) : mutex_(mutex), acquired_(pthread_mutex_lock(&mutex_) == 0) {}
    ~Lock() {
      if (acquired_) {
        static_cast<void>(pthread_mutex_unlock(&mutex_));
      }
    }
    Lock(const Lock&) = delete;
    Lock& operator=(const Lock&) = delete;
    Lock(Lock&&) = delete;
    Lock& operator=(Lock&&) = delete;
    [[nodiscard]] bool acquired() const { return acquired_; }

   private:
    pthread_mutex_t& mutex_;
    bool acquired_;
  };
  /// Adds one or marks explicit saturation.
  void increment(std::int64_t& value, SourceSnapshot& source) const;
  /// Returns a checked nonnegative producer/consumer tick.
  [[nodiscard]] std::optional<std::int64_t> tick() const;
  /// Tests exact active session/request ownership under the lock.
  [[nodiscard]] bool current(std::int64_t session, std::size_t source) const;
  /// Removes only current validity, preserving the interval and identity.
  static void clear(SourceSnapshot& source, Availability reason);
  /// Computes effective freshness without mutating UIKit ownership.
  void freshness(std::size_t index, SourceSnapshot& snapshot, std::optional<std::int64_t> now, bool ordered);
  pthread_mutex_t mutex_ = PTHREAD_MUTEX_INITIALIZER;
  std::array<SourceSnapshot, 2> sources_{};
  std::array<bool, 2> requested_{};
  std::array<std::optional<std::int64_t>, 2> boundaries_{};
  std::array<std::int64_t, 2> freshness_barriers_{-1, -1};
  CycleClockReading (*clock_)();
  std::int64_t ceiling_;
  std::int64_t session_ = 0;
  std::int64_t generation_ = 0;
  std::int64_t issued_ = 0;
  std::int64_t live_generation_ = 0;
  std::array<Availability, 2> barrier_reasons_{Availability::kClockUnavailable, Availability::kClockUnavailable};
  bool running_ = false;
};
/// Returns process-lifetime primitive state, without UIKit or a global constructor.
[[nodiscard]] CaptureEvents& capture_events();
/// Reads actual compile target/OS support without host initialization or UIKit access.
[[nodiscard]] Platform capture_platform();
/// Returns the finite public availability spelling.
[[nodiscard]] std::string_view availability_name(Availability availability);
}  // namespace rasp::ios::capture
