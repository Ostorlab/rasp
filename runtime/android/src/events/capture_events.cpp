/// Primitive-only capture state reduction and independent owning interval drains.
#include "events/capture_events.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace rasp::android::events {
void CaptureEvents::increment(std::int64_t& counter, CaptureSnapshot& source) const {
  if (counter < ceiling_) {
    ++counter;
  } else {
    source.overflow = true;
  }
}

void CaptureEvents::clear(int source) {
  const auto index = static_cast<std::size_t>(source);
  const unsigned int mask = 1U << static_cast<unsigned int>(source);
  for (auto& entry : entries_) {
    entry.sources &= ~mask;
    if (entry.sources == 0) {
      entry.token = 0;
    }
  }
  std::span(sources_)[index].active_activities = 0;
  if (source == 1) {
    recording_owner_ = 0;
    std::span(sources_)[index].visibility = -1;
  }
}

void CaptureEvents::platform(int sdk) {
  const Lock lock(mutex_);
  sdk_ = sdk;
  for (std::size_t index = 0; index < sources_.size(); ++index) {
    if (sdk_ <= 0) {
      clear(static_cast<int>(index));
      std::span(sources_)[index].state = CaptureState::kError;
      std::span(sources_)[index].permission = 0;
      continue;
    }
    if (sdk_ < (index == 0 ? 34 : 35)) {
      clear(static_cast<int>(index));
      std::span(sources_)[index].state = CaptureState::kUnsupported;
      std::span(sources_)[index].permission = 1;
    } else if (std::span(sources_)[index].state == CaptureState::kUnsupported) {
      std::span(sources_)[index].state = CaptureState::kNeverStarted;
      std::span(sources_)[index].permission = 0;
    }
  }
}

std::int64_t CaptureEvents::start(bool screenshots, bool recording) {
  const Lock lock(mutex_);
  active_ = false;
  clear(0);
  clear(1);
  if (epoch_ == ceiling_) {
    for (auto& source : sources_) {
      source.state = CaptureState::kError;
      increment(source.lost, source);
    }
    return 0;
  }
  ++epoch_;
  requested_ = {screenshots, recording};
  for (std::size_t index = 0; index < sources_.size(); ++index) {
    auto& source = std::span(sources_)[index];
    const bool supported = sdk_ >= (index == 0 ? 34 : 35);
    source.state = CaptureState::kNoActiveActivity;
    if (!supported) {
      source.state = CaptureState::kUnsupported;
    } else if (!std::span(requested_)[index]) {
      source.state = CaptureState::kNotRequested;
    }
    source.permission = supported ? 0 : 1;
  }
  active_ = true;
  return epoch_;
}

void CaptureEvents::stop(std::int64_t epoch) {
  const Lock lock(mutex_);
  if (epoch != epoch_ || epoch <= 0) {
    return;
  }
  active_ = false;
  clear(0);
  clear(1);
  for (std::size_t index = 0; index < sources_.size(); ++index) {
    if (std::span(requested_)[index] && std::span(sources_)[index].state != CaptureState::kUnsupported) {
      std::span(sources_)[index].state = CaptureState::kDeactivated;
    }
  }
}

void CaptureEvents::unavailable(CaptureState state) {
  const Lock lock(mutex_);
  if (active_) {
    return;
  }
  for (auto& source : sources_) {
    if (source.state != CaptureState::kUnsupported) {
      source.state = state;
    }
  }
}

bool CaptureEvents::reject(CaptureSnapshot& snapshot) const {
  increment(snapshot.invalid, snapshot);
  return false;
}

bool CaptureEvents::availability(int source, CaptureSnapshot& snapshot, int value) {
  if (value < 3 || value > 12 || value == 4 || value == 5) {
    return reject(snapshot);
  }
  if (((value == 7 || value == 8) && snapshot.active_activities == 0) || (source == 1 && value == 8)) {
    return reject(snapshot);
  }
  snapshot.state = static_cast<CaptureState>(value);
  if (source == 0 && snapshot.active_activities > 0 &&
      (snapshot.state == CaptureState::kRegistrationError || snapshot.state == CaptureState::kTeardownError)) {
    snapshot.state = CaptureState::kPartial;
  }
  if (snapshot.state != CaptureState::kActive && snapshot.state != CaptureState::kPartial) {
    clear(source);
  }
  return true;
}

bool CaptureEvents::metadata(int source, CaptureSnapshot& snapshot, CaptureKind kind, int value) {
  if (kind == CaptureKind::kState) {
    return availability(source, snapshot, value);
  }
  if (kind == CaptureKind::kLoss) {
    if (value != 0) {
      return reject(snapshot);
    }
    increment(snapshot.lost, snapshot);
    return true;
  }
  if (value < 0 || value > 4 || value == 1) {
    return reject(snapshot);
  }
  snapshot.permission = value;
  if (value == 0) {
    clear(source);
    snapshot.state = CaptureState::kError;
    return true;
  }
  if (value == 2 || value == 3) {
    clear(source);
    snapshot.state = value == 2 ? CaptureState::kPermissionAbsent : CaptureState::kPermissionDenied;
  }
  return true;
}

bool CaptureEvents::open(int source, CaptureSnapshot& snapshot, int token) {
  const unsigned int mask = 1U << static_cast<unsigned int>(source);
  auto* entry = std::ranges::find(entries_, token, &Entry::token);
  if (entry != entries_.end() && (entry->sources & mask) != 0) {
    return reject(snapshot);
  }
  if (entry == entries_.end()) {
    entry = std::ranges::find(entries_, 0, &Entry::token);
  }
  if (entry == entries_.end()) {
    increment(snapshot.lost, snapshot);
    return false;
  }
  entry->token = token;
  entry->sources |= mask;
  ++snapshot.active_activities;
  if (source == 0) {
    snapshot.state = CaptureState::kActive;
  }
  return true;
}

bool CaptureEvents::recording(CaptureSnapshot& snapshot, int token, CaptureKind kind, int value) {
  if (value < 0 || value > 1 || (kind == CaptureKind::kCallback && recording_owner_ != token) ||
      (kind == CaptureKind::kInitial && recording_owner_ != 0)) {
    increment(snapshot.invalid, snapshot);
    increment(snapshot.lost, snapshot);
    clear(1);
    snapshot.state = CaptureState::kError;
    return false;
  }
  if (kind == CaptureKind::kInitial) {
    recording_owner_ = token;
    increment(snapshot.initial_samples, snapshot);
    snapshot.state = CaptureState::kActive;
  } else {
    increment(snapshot.callbacks, snapshot);
    if (snapshot.visibility != value) {
      increment(snapshot.changes, snapshot);
    }
  }
  snapshot.visibility = value;
  return true;
}

bool CaptureEvents::activity(int source, CaptureSnapshot& snapshot, int token, CaptureKind kind, int value) {
  const unsigned int mask = 1U << static_cast<unsigned int>(source);
  auto* entry = std::ranges::find(entries_, token, &Entry::token);
  if (entry == entries_.end() || (entry->sources & mask) == 0) {
    return reject(snapshot);
  }
  if (kind == CaptureKind::kClose) {
    if (value != 0) {
      return reject(snapshot);
    }
    entry->sources &= ~mask;
    if (entry->sources == 0) {
      entry->token = 0;
    }
    --snapshot.active_activities;
    if (source == 1 && token == recording_owner_) {
      recording_owner_ = 0;
      snapshot.visibility = -1;
    }
    if (snapshot.active_activities == 0) {
      snapshot.state = CaptureState::kNoActiveActivity;
    }
    return true;
  }
  if (kind != CaptureKind::kCallback && kind != CaptureKind::kInitial) {
    return reject(snapshot);
  }
  if (source == 0) {
    if (kind != CaptureKind::kCallback || value != 0) {
      return reject(snapshot);
    }
    increment(snapshot.callbacks, snapshot);
    return true;
  }
  return recording(snapshot, token, kind, value);
}

bool CaptureEvents::push(std::int64_t epoch, int source, int token, CaptureKind kind, int value) {
  const Lock lock(mutex_);
  if (source < 0 || source > 1) {
    for (auto& snapshot : sources_) {
      increment(snapshot.invalid, snapshot);
    }
    return false;
  }
  auto& snapshot = std::span(sources_)[static_cast<std::size_t>(source)];
  const bool cleanup = kind == CaptureKind::kLoss || (kind == CaptureKind::kState && value >= 9 && value <= 11);
  if ((!active_ && !cleanup) || epoch <= 0 || epoch != epoch_ ||
      !std::span(requested_)[static_cast<std::size_t>(source)] || snapshot.state == CaptureState::kUnsupported) {
    return reject(snapshot);
  }
  if (kind == CaptureKind::kState || kind == CaptureKind::kPermission || kind == CaptureKind::kLoss) {
    if (token != 0) {
      return reject(snapshot);
    }
    return metadata(source, snapshot, kind, value);
  }
  if (token <= 0 || snapshot.permission != 4) {
    return reject(snapshot);
  }
  if (kind == CaptureKind::kOpen) {
    if (value != 0) {
      return reject(snapshot);
    }
    return open(source, snapshot, token);
  }
  return activity(source, snapshot, token, kind, value);
}

std::array<CaptureSnapshot, 2> CaptureEvents::drain(bool screenshots, bool recording) {
  const Lock lock(mutex_);
  const auto now = clock_().monotonic_ns;
  const std::array selected{screenshots, recording};
  auto result = sources_;
  const std::span boundaries(boundaries_);
  for (std::size_t index = 0; index < sources_.size(); ++index) {
    if (!std::span(selected)[index]) {
      continue;
    }
    const auto previous = std::span(boundaries_)[index];
    std::span(result)[index].interval_ms =
        now.has_value() && *now >= 0 && previous.has_value() && *now >= *previous ? (*now - *previous) / 1000000 : -1;
    const bool valid = now.has_value() && *now >= 0 && (!previous.has_value() || *now >= *previous);
    boundaries[index] = valid ? now : std::nullopt;
    auto& source = std::span(sources_)[index];
    source.callbacks = 0;
    source.initial_samples = 0;
    source.changes = 0;
    source.lost = 0;
    source.invalid = 0;
    source.overflow = false;
  }
  return result;
}

CaptureEvents& capture_events() {
  static constinit CaptureEvents events;
  return events;
}
}  // namespace rasp::android::events
