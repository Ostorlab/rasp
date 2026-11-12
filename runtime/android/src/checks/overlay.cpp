#include "checks/overlay.h"

#include <array>
#include <string_view>
#include <vector>

#include "rasp/observation.h"

#ifdef __ANDROID__
#include <string>

#include "events/window_events.h"
#endif

namespace rasp::android::checks {
namespace {

constexpr std::array<std::string_view, 10> kSignals{
    "overlay.observer_state",        "overlay.coverage",
    "overlay.active_windows",        "overlay.touch_events",
    "overlay.obscured_touch_events", "overlay.partially_obscured_touch_events",
    "overlay.dropped_events",        "overlay.lost_windows",
    "overlay.invalid_events",        "overlay.interval_ms",
};

#ifdef __ANDROID__
[[nodiscard]] std::string_view observer_state(events::ObserverState state) {
  switch (state) {
    case events::ObserverState::kNeverStarted:
      return "never_started";
    case events::ObserverState::kActive:
      return "active";
    case events::ObserverState::kDeactivated:
      return "deactivated";
    case events::ObserverState::kError:
      return "error";
    case events::ObserverState::kUnsupported:
      return "unsupported";
  }
  return "error";
}
#endif

}  // namespace

std::vector<Observation> overlay() {
  std::vector<Observation> observations;
  observations.reserve(kSignals.size());
#ifdef __ANDROID__
  const events::WindowSnapshot snapshot = events::window_events().drain();
  std::string coverage = "unknown";
  if (snapshot.dropped_events > 0 || snapshot.lost_windows > 0 || snapshot.invalid_events > 0) {
    coverage = "loss_detected";
  } else if (snapshot.state == events::ObserverState::kActive && snapshot.active_windows > 0) {
    coverage = "best_effort";
  }
  observations.push_back(observed(kSignals[0], "window_callback", std::string(observer_state(snapshot.state))));
  observations.push_back(observed(kSignals[1], "window_callback", coverage));
  observations.push_back(observed(kSignals[2], "window_callback", snapshot.active_windows));
  observations.push_back(observed(kSignals[3], "window_callback", snapshot.touch_events));
  observations.push_back(observed(kSignals[4], "window_callback", snapshot.obscured_touch_events));
  observations.push_back(observed(kSignals[5], "window_callback", snapshot.partially_obscured_touch_events));
  observations.push_back(observed(kSignals[6], "window_callback", snapshot.dropped_events));
  observations.push_back(observed(kSignals[7], "window_callback", snapshot.lost_windows));
  observations.push_back(observed(kSignals[8], "window_callback", snapshot.invalid_events));
  observations.push_back(observed(kSignals[9], "window_callback", snapshot.interval_ms));
#else
  for (const std::string_view signal : kSignals) {
    observations.push_back(unsupported(signal, "window_callback"));
  }
#endif
  return observations;
}

}  // namespace rasp::android::checks
