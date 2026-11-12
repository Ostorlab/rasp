/// Bounded capture reduction, registration generations and independent immutable cuts.
#include "capture/capture_events.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#ifdef __APPLE__
#include <TargetConditionals.h>
#endif

namespace rasp::ios::capture {
void CaptureEvents::increment(std::int64_t& value, SourceSnapshot& source) const {
  if (value < ceiling_) {
    ++value;
  } else {
    source.overflow = true;
  }
}
std::optional<std::int64_t> CaptureEvents::tick() const {
  const auto value = clock_().monotonic_ns;
  return value.has_value() && *value >= 0 ? value : std::nullopt;
}
bool CaptureEvents::current(std::int64_t session, std::size_t source) const {
  return running_ && session > 0 && session == session_ && std::span{requested_}[source];
}
void CaptureEvents::clear(SourceSnapshot& source, Availability reason) {
  source.availability = reason;
  source.registered = false;
  source.state = -1;
  source.sampled_ns = std::nullopt;
}
std::int64_t CaptureEvents::start(bool screenshots, bool recording) {
  const Lock lock(mutex_);
  if (!lock.acquired() || (!screenshots && !recording)) {
    return 0;
  }
  if (running_) {
    return requested_ == std::array{screenshots, recording} ? session_ : 0;
  }
  if (session_ >= ceiling_) {
    for (auto& source : sources_) {
      clear(source, Availability::kExhausted);
      increment(source.lost, source);
    }
    return 0;
  }
  ++session_;
  requested_ = {screenshots, recording};
  running_ = true;
  live_generation_ = 0;
  for (std::size_t index = 0; index < sources_.size(); ++index) {
    auto& source = std::span{sources_}[index];
    Availability initial = Availability::kNotRequested;
    if (std::span{requested_}[index]) {
      initial = index == 0 ? Availability::kUnavailableState : Availability::kNoSelection;
    }
    clear(source, initial);
    source.scope = Scope::kNone;
  }
  sources_[0].epoch = session_;
  return session_;
}
void CaptureEvents::stop(std::int64_t session) {
  const Lock lock(mutex_);
  if (!lock.acquired() || session <= 0 || session != session_ || !running_) {
    return;
  }
  running_ = false;
  live_generation_ = 0;
  for (std::size_t index = 0; index < sources_.size(); ++index) {
    auto& source = std::span{sources_}[index];
    if (std::span{requested_}[index]) {
      clear(source, Availability::kDeactivated);
      increment(source.lost, source);
    }
    source.scope = Scope::kNone;
  }
}
void CaptureEvents::cleanup_complete(std::int64_t session) {
  const Lock lock(mutex_);
  if (!lock.acquired() || running_ || session <= 0 || session != session_) {
    return;
  }
  for (std::size_t index = 0; index < sources_.size(); ++index) {
    if (std::span{requested_}[index]) {
      clear(std::span{sources_}[index], Availability::kDeactivated);
    }
  }
}
void CaptureEvents::screenshot_ready(std::int64_t session, bool active) {
  const Lock lock(mutex_);
  if (!lock.acquired() || !current(session, 0)) {
    return;
  }
  auto& source = sources_[0];
  if (source.availability == Availability::kTeardownError || source.availability == Availability::kExhausted) {
    return;
  }
  if (issued_ >= ceiling_) {
    clear(source, Availability::kExhausted);
    increment(source.lost, source);
    return;
  }
  ++issued_;
  if (!active && source.availability == Availability::kActive) {
    increment(source.lost, source);
  }
  source.serial = issued_;
  source.registered = true;
  source.sampled_ns = tick();
  source.availability = !active ? Availability::kInactive : Availability::kActive;
}
void CaptureEvents::screenshot(std::int64_t session) {
  const Lock lock(mutex_);
  if (!lock.acquired()) {
    return;
  }
  auto& source = sources_[0];
  if (!current(session, 0) || !source.registered || source.availability != Availability::kActive) {
    increment(source.ignored, source);
    return;
  }
  increment(source.callbacks, source);
}
std::int64_t CaptureEvents::open(std::int64_t session, Scope scope) {
  const Lock lock(mutex_);
  if (!lock.acquired() || !current(session, 1) || scope == Scope::kNone) {
    return 0;
  }
  auto& source = sources_[1];
  if (source.availability == Availability::kTeardownError) {
    return 0;
  }
  live_generation_ = 0;
  if (generation_ >= ceiling_) {
    clear(source, Availability::kExhausted);
    increment(source.lost, source);
    return 0;
  }
  if (source.epoch > 0 && source.availability != Availability::kInactive) {
    increment(source.lost, source);
  }
  ++generation_;
  live_generation_ = generation_;
  clear(source, Availability::kUnavailableState);
  source.scope = scope;
  source.epoch = generation_;
  return generation_;
}
void CaptureEvents::registered(std::int64_t session, std::int64_t generation) {
  const Lock lock(mutex_);
  if (!lock.acquired() || !current(session, 1) || generation <= 0 || generation != live_generation_) {
    return;
  }
  sources_[1].registered = true;
}
std::int64_t CaptureEvents::ticket(std::int64_t session, std::int64_t generation) {
  const Lock lock(mutex_);
  if (!lock.acquired() || !current(session, 1) || generation <= 0 || generation != live_generation_) {
    return 0;
  }
  if (issued_ >= ceiling_) {
    clear(sources_[1], Availability::kExhausted);
    live_generation_ = 0;
    increment(sources_[1].lost, sources_[1]);
    return 0;
  }
  return ++issued_;
}
void CaptureEvents::sample(std::int64_t session, std::int64_t generation, std::int64_t serial, SampleKind kind,
                           int state) {
  const Lock lock(mutex_);
  if (!lock.acquired()) {
    return;
  }
  auto& source = sources_[1];
  if (!current(session, 1) || generation <= 0 || generation != live_generation_ || serial <= 0 || serial > issued_ ||
      serial <= source.serial) {
    increment(source.ignored, source);
    return;
  }
  if (kind != SampleKind::kInitial && kind != SampleKind::kCallback && kind != SampleKind::kResample) {
    increment(source.ignored, source);
    increment(source.lost, source);
    clear(source, Availability::kError);
    return;
  }
  source.serial = serial;
  if (state < 0 || state > (source.scope == Scope::kScene ? 2 : 1)) {
    increment(source.ignored, source);
    increment(source.lost, source);
    source.state = -1;
    source.sampled_ns = std::nullopt;
    source.availability = Availability::kUnavailableState;
    return;
  }
  if (kind == SampleKind::kInitial) {
    increment(source.initial, source);
  }
  if (kind == SampleKind::kCallback) {
    increment(source.callbacks, source);
  }
  if (kind == SampleKind::kResample) {
    increment(source.resamples, source);
  }
  if (kind != SampleKind::kInitial && source.state >= 0 && source.state <= 1 && state <= 1 && source.state != state) {
    increment(source.changes, source);
    if (kind == SampleKind::kResample) {
      increment(source.lost, source);
    }
  }
  source.state = state;
  source.sampled_ns = tick();
  source.availability = state == 2 ? Availability::kUnavailableState : Availability::kActive;
}
void CaptureEvents::invalidate(std::int64_t session, Availability reason) {
  const Lock lock(mutex_);
  if (!lock.acquired() || !current(session, 1) || reason == Availability::kActive) {
    return;
  }
  auto& source = sources_[1];
  if (live_generation_ > 0) {
    increment(source.lost, source);
  }
  live_generation_ = 0;
  clear(source, reason);
  if (reason == Availability::kNoSelection || reason == Availability::kDisconnected ||
      reason == Availability::kOwnerGone) {
    source.scope = Scope::kNone;
  }
}
void CaptureEvents::failure(std::int64_t session, int source, Availability reason) {
  const Lock lock(mutex_);
  if (!lock.acquired() || session <= 0 || session != session_ || source < 0 || source > 1 ||
      !std::span{requested_}[static_cast<std::size_t>(source)] ||
      (reason != Availability::kRegistrationError && reason != Availability::kTeardownError &&
       reason != Availability::kError)) {
    return;
  }
  auto& snapshot = std::span{sources_}[static_cast<std::size_t>(source)];
  clear(snapshot, reason);
  increment(snapshot.lost, snapshot);
  if (source == 1) {
    live_generation_ = 0;
  }
}
void CaptureEvents::reject(std::int64_t session, int source, std::int64_t generation, bool fault) {
  const Lock lock(mutex_);
  if (!lock.acquired() || source < 0 || source > 1) {
    return;
  }
  const auto index = static_cast<std::size_t>(source);
  auto& snapshot = std::span{sources_}[index];
  increment(snapshot.ignored, snapshot);
  if (fault && current(session, index) &&
      (source == 0 || (generation == 0 || (generation > 0 && generation == live_generation_)))) {
    clear(snapshot, Availability::kError);
    increment(snapshot.lost, snapshot);
    if (source == 1) {
      live_generation_ = 0;
    }
  }
}
void CaptureEvents::freshness(std::size_t index, SourceSnapshot& snapshot, std::optional<std::int64_t> now,
                              bool ordered) {
  if ((snapshot.availability == Availability::kActive || snapshot.availability == Availability::kUnavailableState) &&
      (index == 0 || snapshot.state >= 0 || !snapshot.registered)) {
    if (!snapshot.registered) {
      snapshot.availability = Availability::kUnavailableState;
    } else if (!ordered || !now.has_value() || !snapshot.sampled_ns.has_value() || *now < *snapshot.sampled_ns) {
      snapshot.availability = Availability::kClockUnavailable;
      std::span{freshness_barriers_}[index] = snapshot.serial;
      std::span{barrier_reasons_}[index] = Availability::kClockUnavailable;
    } else {
      const auto age = *now - *snapshot.sampled_ns;
      snapshot.age_ms = age / 1000000;
      if (age > 15000000000LL) {
        snapshot.availability = Availability::kStale;
        std::span{freshness_barriers_}[index] = snapshot.serial;
        std::span{barrier_reasons_}[index] = Availability::kStale;
      } else if (snapshot.serial <= std::span{freshness_barriers_}[index]) {
        snapshot.availability = std::span{barrier_reasons_}[index];
      }
    }
  }
}
Snapshot CaptureEvents::drain(bool screenshots, bool recording) {
  const Lock lock(mutex_);
  if (!lock.acquired()) {
    return {.valid = false};
  }
  Snapshot result{.sources = sources_};
  if (!screenshots && !recording) {
    return result;
  }
  const auto now = tick();
  const std::array selected{screenshots, recording};
  for (std::size_t index = 0; index < sources_.size(); ++index) {
    if (!std::span{selected}[index]) {
      continue;
    }
    auto& snapshot = std::span{result.sources}[index];
    const auto previous = std::span{boundaries_}[index];
    const bool ordered = now.has_value() && (!previous.has_value() || *now >= *previous);
    snapshot.interval_ms = ordered && previous.has_value() ? (*now - *previous) / 1000000 : -1;
    std::span{boundaries_}[index] = ordered ? now : std::nullopt;
    freshness(index, snapshot, now, ordered);
    auto& source = std::span{sources_}[index];
    source.callbacks = 0;
    source.ignored = 0;
    source.lost = 0;
    source.initial = 0;
    source.changes = 0;
    source.resamples = 0;
    source.overflow = false;
  }
  return result;
}
CaptureEvents& capture_events() {
  static constinit CaptureEvents events;
  return events;
}
Platform capture_platform() {
#if defined(__APPLE__) && TARGET_OS_IOS && !TARGET_OS_SIMULATOR && !TARGET_OS_MACCATALYST
  if (__builtin_available(iOS 17.0, *)) {
    return Platform::kScene;
  }
  return Platform::kLegacy;
#else
  return Platform::kUnsupported;
#endif
}
std::string_view availability_name(Availability availability) {
  switch (availability) {
    case Availability::kUnsupported:
      return "unsupported";
    case Availability::kNeverStarted:
      return "never_started";
    case Availability::kNotRequested:
      return "not_requested";
    case Availability::kExhausted:
      return "exhausted";
    case Availability::kTeardownError:
      return "teardown_error";
    case Availability::kRegistrationError:
      return "registration_error";
    case Availability::kError:
      return "error";
    case Availability::kDeactivated:
      return "deactivated";
    case Availability::kNoSelection:
      return "no_selection";
    case Availability::kDisconnected:
      return "disconnected";
    case Availability::kOwnerGone:
      return "owner_gone";
    case Availability::kInactive:
      return "inactive";
    case Availability::kClockUnavailable:
      return "clock_unavailable";
    case Availability::kStale:
      return "stale";
    case Availability::kUnavailableState:
      return "unavailable_state";
    case Availability::kNotSelected:
      return "not_selected";
    case Availability::kActive:
      return "active";
  }
  return "error";
}
}  // namespace rasp::ios::capture
