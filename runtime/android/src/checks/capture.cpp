/// Scalar capture availability and interval evidence, consumed only by the owning cycle.
#include "checks/capture.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "rasp/observation.h"

#ifdef __ANDROID__
#include <android/api-level.h>
#endif

#include "events/capture_events.h"

namespace rasp::android::checks {
namespace {
constexpr std::array<std::string_view, 13> kStates{
    "never_started",     "not_requested",      "unsupported",        "no_application",
    "permission_absent", "permission_denied",  "no_active_activity", "active",
    "partial",           "registration_error", "teardown_error",     "error",
    "deactivated",
};
constexpr std::array<std::string_view, 5> kPermissions{"unknown", "not_applicable", "absent", "denied", "granted"};
/// Appends a fixed source snapshot in the approved catalogue order, preserving unsupported data.
void append(std::vector<Observation>& rows, const events::CaptureSnapshot& snapshot, bool recording) {
  const std::string prefix = recording ? "capture.recording." : "capture.screenshot.";
  const std::string_view source = recording ? "window_manager_recording" : "activity_screen_capture";
#ifdef __ANDROID__
  constexpr bool kAndroid = true;
#else
  constexpr bool kAndroid = false;
#endif
  const bool supported = kAndroid && snapshot.state != events::CaptureState::kUnsupported;
  const auto add = [&](std::string_view suffix, Value value, bool metadata = false) {
    const std::string signal = prefix + std::string(suffix);
    const bool available = metadata ? kAndroid : supported;
    rows.push_back(available ? observed(signal, source, std::move(value)) : unsupported(signal, source));
  };
  add("observer_state", std::string(std::span(kStates)[static_cast<std::size_t>(snapshot.state)]), true);
  add("permission", std::string(std::span(kPermissions)[static_cast<std::size_t>(snapshot.permission)]), true);
  std::string coverage = "unknown";
  if (snapshot.lost > 0 || snapshot.invalid > 0 || snapshot.overflow) {
    coverage = "loss_detected";
  } else if (snapshot.state == events::CaptureState::kActive && snapshot.active_activities > 0) {
    coverage = "best_effort";
  }
  add("coverage", coverage, true);
  const bool current = !recording || snapshot.state == events::CaptureState::kActive;
  add("active_activities", current ? snapshot.active_activities : std::int64_t{0});
  if (recording) {
    std::string visibility = "unknown";
    if (snapshot.visibility == 1) {
      visibility = "visible";
    } else if (snapshot.visibility == 0) {
      visibility = "not_visible";
    }
    add("visibility", visibility);
    add("initial_samples", snapshot.initial_samples);
  }
  add("callback_events", snapshot.callbacks);
  if (recording) {
    add("visibility_changes", snapshot.changes);
  }
  add("lost_registrations", snapshot.lost);
  add("invalid_events", snapshot.invalid);
  add("counter_overflow", snapshot.overflow);
  add("interval_ms", snapshot.interval_ms);
}
}  // namespace
std::vector<Observation> capture(bool screenshots, bool recording) {
  std::vector<Observation> rows;
  rows.reserve((screenshots ? 9U : 0U) + (recording ? 12U : 0U));
#ifdef __ANDROID__
  events::capture_events().platform(android_get_device_api_level());
  const auto snapshots = events::capture_events().drain(screenshots, recording);
#else
  const std::array<events::CaptureSnapshot, 2> snapshots{};
#endif
  if (screenshots) {
    append(rows, snapshots[0], false);
  }
  if (recording) {
    append(rows, snapshots[1], true);
  }
  return rows;
}
}  // namespace rasp::android::checks
