/// Fixed process-local handoff for public Android window callbacks. No platform object or input content is stored.
#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <pthread.h>

namespace rasp::android::events {

/// Adapter availability is independent of whether any touches were delivered.
enum class ObserverState : std::uint8_t { kNeverStarted, kActive, kDeactivated, kError, kUnsupported };

/// Snapshot availability/window count and interval deltas, consumed atomically by one selected monitor drain.
struct WindowSnapshot {
  ObserverState state = ObserverState::kNeverStarted;
  std::int64_t active_windows = 0;
  std::int64_t touch_events = 0;
  std::int64_t obscured_touch_events = 0;
  std::int64_t partially_obscured_touch_events = 0;
  std::int64_t dropped_events = 0;
  std::int64_t lost_windows = 0;
  std::int64_t invalid_events = 0;
  std::int64_t interval_ms = 0;
};

/// Thread-safe fixed 32-window table and 128-record FIFO. All counters saturate at INT64_MAX.
class WindowEvents {
 public:
  /// Creates an inactive queue; its mutex and session state cannot be copied or moved.
  WindowEvents() = default;
  ~WindowEvents() = default;
  WindowEvents(const WindowEvents&) = delete;
  WindowEvents& operator=(const WindowEvents&) = delete;
  WindowEvents(WindowEvents&&) = delete;
  WindowEvents& operator=(WindowEvents&&) = delete;

  /// Starts a fresh session; preserves pending interval deltas and invalidates previous tokens.
  /// @return Positive session token, or zero when token space is exhausted.
  [[nodiscard]] std::int64_t start();
  /// Stops only the matching session; disables all its window tokens without discarding pending deltas.
  /// @param session The token returned by start.
  /// @param state Deactivated, error or unsupported.
  void stop(std::int64_t session, ObserverState state);
  /// Marks an inactive bridge error/unsupported; never overwrites a running session's availability.
  /// @param state The inactive availability.
  void unavailable(ObserverState state);
  /// Validates primitive JNI input and updates current state even when the event FIFO is full.
  /// @param session Positive session token.
  /// @param window Positive opaque window token; zero only for adapter fault kind 5.
  /// @param kind Open=1, close=2, touch=3, lost ownership=4, adapter fault=5.
  /// @param flags Only touch permits bits 1 and 2; all other kinds require zero.
  /// @return False for invalid/stale input, with an explicit interval error count.
  [[nodiscard]] bool push(std::int64_t session, int window, int kind, int flags);
  /// Drains the FIFO once, resets interval counters and advances the monotonic interval boundary.
  /// @return Owned fixed-size snapshot; window identifiers never leave the handoff.
  [[nodiscard]] WindowSnapshot drain();

 private:
  /// Scoped access to the process-owned pthread mutex; no exit-time destructor on queue storage.
  class EventLock {
   public:
    explicit EventLock(pthread_mutex_t& mutex) : mutex_(mutex) { static_cast<void>(pthread_mutex_lock(&mutex_)); }
    ~EventLock() noexcept { static_cast<void>(pthread_mutex_unlock(&mutex_)); }
    EventLock(EventLock&&) = delete;
    EventLock& operator=(EventLock&&) = delete;
    EventLock(const EventLock&) = delete;
    EventLock& operator=(const EventLock&) = delete;

   private:
    pthread_mutex_t& mutex_;
  };

  struct Record {
    int kind = 0;
    unsigned int flags = 0;
  };
  pthread_mutex_t mutex_ = PTHREAD_MUTEX_INITIALIZER;
  ObserverState state_ = ObserverState::kNeverStarted;
  std::int64_t session_ = 0;
  std::array<int, 32> windows_{};
  std::array<Record, 128> records_{};
  std::size_t size_ = 0;
  std::int64_t dropped_ = 0;
  std::int64_t lost_ = 0;
  std::int64_t invalid_ = 0;
  std::chrono::steady_clock::time_point boundary_;
};

/// Process singleton shared by registered JNI and the production builtin.
/// @return The finite handoff; no JNIEnv or Java reference is stored.
[[nodiscard]] WindowEvents& window_events();

}  // namespace rasp::android::events
