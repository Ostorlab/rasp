#include "events/window_events.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <limits>
#include <span>

namespace rasp::android::events {
namespace {

void increment(std::int64_t& counter) {
  if (counter < std::numeric_limits<std::int64_t>::max()) {
    ++counter;
  }
}

}  // namespace

std::int64_t WindowEvents::start() {
  const EventLock lock(mutex_);
  if (session_ == std::numeric_limits<std::int64_t>::max()) {
    state_ = ObserverState::kError;
    windows_.fill(0);
    return 0;
  }
  ++session_;
  windows_.fill(0);
  state_ = ObserverState::kActive;
  return session_;
}

void WindowEvents::stop(std::int64_t session, ObserverState state) {
  const EventLock lock(mutex_);
  if (session == session_ && session > 0 && state != ObserverState::kActive && state != ObserverState::kNeverStarted) {
    state_ = state;
    windows_.fill(0);
  }
}

void WindowEvents::unavailable(ObserverState state) {
  const EventLock lock(mutex_);
  if (state_ != ObserverState::kActive) {
    state_ = state;
  }
}

bool WindowEvents::push(std::int64_t session, int window, int kind, int flags) {
  const EventLock lock(mutex_);
  if (session <= 0 || session != session_ || state_ != ObserverState::kActive || kind < 1 || kind > 5 ||
      (kind == 3 ? (flags < 0 || flags > 3) : flags != 0) || (kind == 5 ? window != 0 : window <= 0)) {
    increment(invalid_);
    return false;
  }
  auto* entry = std::ranges::find(windows_, window);
  if (kind == 1) {
    if (entry != windows_.end()) {
      increment(invalid_);
      return false;
    }
    entry = std::ranges::find(windows_, 0);
    if (entry == windows_.end()) {
      increment(lost_);
      return false;
    }
    *entry = window;
  } else if (kind == 5) {
    increment(lost_);
  } else {
    if (entry == windows_.end()) {
      increment(invalid_);
      return false;
    }
    if (kind == 2 || kind == 4) {
      *entry = 0;
    }
    if (kind == 4) {
      increment(lost_);
    }
  }
  if (size_ == records_.size()) {
    increment(dropped_);
  } else {
    const std::span records(records_);
    records[size_] = {.kind = kind, .flags = static_cast<unsigned int>(flags)};
    ++size_;
  }
  return true;
}

WindowSnapshot WindowEvents::drain() {
  const EventLock lock(mutex_);
  const auto now = std::chrono::steady_clock::now();
  WindowSnapshot snapshot{
      .state = state_,
      .active_windows = static_cast<std::int64_t>(std::ranges::count_if(windows_, [](int token) { return token > 0; })),
      .dropped_events = dropped_,
      .lost_windows = lost_,
      .invalid_events = invalid_,
      .interval_ms = boundary_ == std::chrono::steady_clock::time_point{}
                         ? -1
                         : std::chrono::duration_cast<std::chrono::milliseconds>(now - boundary_).count(),
  };
  for (const Record& record : std::span(records_).first(size_)) {
    if (record.kind == 3) {
      ++snapshot.touch_events;
      snapshot.obscured_touch_events += (record.flags & 1U) != 0 ? 1 : 0;
      snapshot.partially_obscured_touch_events += (record.flags & 2U) != 0 ? 1 : 0;
    }
  }
  size_ = 0;
  dropped_ = 0;
  lost_ = 0;
  invalid_ = 0;
  boundary_ = now;
  return snapshot;
}

WindowEvents& window_events() {
  static constinit WindowEvents events;
  return events;
}

}  // namespace rasp::android::events
