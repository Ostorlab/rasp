/// Bounded public capture notification handoff; no platform objects or captured content.
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <pthread.h>

#include "rasp/cycle.h"

namespace rasp::android::events {
/// Availability values shared with the version-gated Java adapter.
enum class CaptureState : std::uint8_t {
  kNeverStarted,
  kNotRequested,
  kUnsupported,
  kNoApplication,
  kPermissionAbsent,
  kPermissionDenied,
  kNoActiveActivity,
  kActive,
  kPartial,
  kRegistrationError,
  kTeardownError,
  kError,
  kDeactivated,
};
/// Primitive ingress operations, independent of selected measurement groups.
enum class CaptureKind : std::uint8_t {
  kInvalid = 0,
  kOpen,
  kClose,
  kCallback,
  kInitial,
  kState,
  kPermission,
  kLoss,
};
/// One source's current registration metadata and owned interval counters.
struct CaptureSnapshot {
  CaptureState state = CaptureState::kNeverStarted;
  int permission = 0;
  int visibility = -1;
  std::int64_t active_activities = 0;
  std::int64_t callbacks = 0;
  std::int64_t initial_samples = 0;
  std::int64_t changes = 0;
  std::int64_t lost = 0;
  std::int64_t invalid = 0;
  bool overflow = false;
  std::int64_t interval_ms = -1;
};
/// Fixed 32-Activity reducer. No queue allocation; each selected source drains independently.
class CaptureEvents {
 public:
  /// Creates bounded state with an optional checked clock and finite counter/epoch ceiling for boundary tests.
  /// @param clock Checked monotonic sampler, not retained platform objects.
  /// @param ceiling Saturation ceiling; production uses INT64_MAX.
  explicit constexpr CaptureEvents(CycleClockReading (*clock)() = read_cycle_clock, std::int64_t ceiling = INT64_MAX)
      : clock_(clock), ceiling_(ceiling) {}
  /// Sets actual platform availability before observation starts, without host opt-in.
  /// @param sdk Public platform API level; unknown is zero.
  void platform(int sdk);
  /// Starts a fresh non-wrapping epoch, preserving pending deltas.
  /// @param screenshots Host requested screenshot observation.
  /// @param recording Host requested recording observation.
  /// @return Positive epoch, zero on exhaustion.
  [[nodiscard]] std::int64_t start(bool screenshots, bool recording);
  /// Invalidates only the current epoch, retaining pending interval evidence.
  /// @param epoch Epoch to disable.
  void stop(std::int64_t epoch);
  /// Publishes an unavailable source state without an active epoch.
  /// @param state Failure availability shared by supported sources.
  void unavailable(CaptureState state);
  /// Validates and applies fixed primitive ingress; rejected events count explicit source loss.
  /// @param epoch Current positive epoch.
  /// @param source Screenshot=0, recording=1.
  /// @param token Ephemeral Activity token, zero for source metadata operations.
  /// @param kind Finite operation enum.
  /// @param value Callback/initial recording state, availability or permission enum; otherwise zero.
  /// @return Whether ingress was accepted.
  [[nodiscard]] bool push(std::int64_t epoch, int source, int token, CaptureKind kind, int value);
  /// Copies both source snapshots and resets only selected source intervals.
  /// @param screenshots Drain screenshot deltas.
  /// @param recording Drain recording deltas.
  /// @return Owned source values, with no live reducer backing.
  [[nodiscard]] std::array<CaptureSnapshot, 2> drain(bool screenshots, bool recording);

 private:
  /// Fixed lock; no Java calls or allocation occur while it is held.
  class Lock {
   public:
    explicit Lock(pthread_mutex_t& mutex) : mutex_(mutex) { static_cast<void>(pthread_mutex_lock(&mutex_)); }
    ~Lock() { static_cast<void>(pthread_mutex_unlock(&mutex_)); }
    Lock(const Lock&) = delete;
    Lock& operator=(const Lock&) = delete;
    Lock(Lock&&) = delete;
    Lock& operator=(Lock&&) = delete;

   private:
    pthread_mutex_t& mutex_;
  };
  /// Adds one without wrapping or silently losing saturation.
  void increment(std::int64_t& counter, CaptureSnapshot& source) const;
  /// Records rejected primitive ingress without accepting its state.
  [[nodiscard]] bool reject(CaptureSnapshot& snapshot) const;
  /// Reduces source availability, retaining healthy screenshot Activities for local failures.
  [[nodiscard]] bool availability(int source, CaptureSnapshot& snapshot, int value);
  /// Applies source-wide permission/loss/availability metadata.
  [[nodiscard]] bool metadata(int source, CaptureSnapshot& snapshot, CaptureKind kind, int value);
  /// Opens one source membership after successful public registration.
  [[nodiscard]] bool open(int source, CaptureSnapshot& snapshot, int token);
  /// Applies a close or callback only to an existing source membership.
  [[nodiscard]] bool activity(int source, CaptureSnapshot& snapshot, int token, CaptureKind kind, int value);
  /// Applies initial/changed UID visibility to the one recording owner.
  [[nodiscard]] bool recording(CaptureSnapshot& snapshot, int token, CaptureKind kind, int value);
  /// Clears source ownership while retaining interval counters.
  void clear(int source);
  struct Entry {
    int token = 0;
    unsigned int sources = 0;
  };
  pthread_mutex_t mutex_ = PTHREAD_MUTEX_INITIALIZER;
  std::array<Entry, 32> entries_{};
  std::array<CaptureSnapshot, 2> sources_{};
  std::array<std::optional<std::int64_t>, 2> boundaries_{};
  std::array<bool, 2> requested_{};
  CycleClockReading (*clock_)();
  std::int64_t ceiling_;
  std::int64_t epoch_ = 0;
  int recording_owner_ = 0;
  int sdk_ = 0;
  bool active_ = false;
};
/// Returns the Android process reducer shared by JNI and the actual builtin dispatcher.
/// @return Fixed process-lifetime state.
[[nodiscard]] CaptureEvents& capture_events();
}  // namespace rasp::android::events
