/// Platform capability, ownership and measured-state observations, with explicit absence.
#include "checks/capture.h"

#include <array>
#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "capture/capture_events.h"
#include "rasp/observation.h"

namespace rasp::ios::checks {
namespace {
/// One exact builtin identity; order matches the canonical manifest.
struct Row {
  std::string_view signal;
  std::string_view source;
};
constexpr std::array<Row, 9> kScreenshotRows{
    {
        {.signal = "capture.screenshot.observer_state", .source = "uiapplication_screenshot"},
        {.signal = "capture.screenshot.coverage", .source = "uiapplication_screenshot"},
        {.signal = "capture.screenshot.session_epoch", .source = "uiapplication_screenshot"},
        {.signal = "capture.screenshot.callback_events", .source = "uiapplication_screenshot"},
        {.signal = "capture.screenshot.ignored_events", .source = "uiapplication_screenshot"},
        {.signal = "capture.screenshot.loss_events", .source = "uiapplication_screenshot"},
        {.signal = "capture.screenshot.counter_overflow", .source = "uiapplication_screenshot"},
        {.signal = "capture.screenshot.interval_ms", .source = "uiapplication_screenshot"},
        {.signal = "capture.screenshot.heartbeat_age_ms", .source = "uiapplication_screenshot"},
    },
};
constexpr std::array<Row, 17> kRecordingRows{
    {
        {.signal = "capture.recording.observer_state", .source = "uikit_capture_observer"},
        {.signal = "capture.recording.coverage", .source = "uikit_capture_observer"},
        {.signal = "capture.recording.scope", .source = "uikit_capture_observer"},
        {.signal = "capture.recording.scene_availability", .source = "uikit_scene_trait"},
        {.signal = "capture.recording.state", .source = "uikit_scene_trait"},
        {.signal = "capture.recording.screen_availability", .source = "uikit_screen_capture"},
        {.signal = "capture.recording.state", .source = "uikit_screen_capture"},
        {.signal = "capture.recording.selection_epoch", .source = "uikit_capture_observer"},
        {.signal = "capture.recording.sample_age_ms", .source = "uikit_capture_observer"},
        {.signal = "capture.recording.initial_samples", .source = "uikit_capture_observer"},
        {.signal = "capture.recording.callback_events", .source = "uikit_capture_observer"},
        {.signal = "capture.recording.state_changes", .source = "uikit_capture_observer"},
        {.signal = "capture.recording.resamples", .source = "uikit_capture_observer"},
        {.signal = "capture.recording.ignored_events", .source = "uikit_capture_observer"},
        {.signal = "capture.recording.loss_events", .source = "uikit_capture_observer"},
        {.signal = "capture.recording.counter_overflow", .source = "uikit_capture_observer"},
        {.signal = "capture.recording.interval_ms", .source = "uikit_capture_observer"},
    },
};
/// Keeps loss separate from structural cycle coverage.
[[nodiscard]] std::string_view coverage(const capture::SourceSnapshot& source) {
  if (source.ignored > 0 || source.lost > 0 || source.overflow) {
    return "loss_detected";
  }
  return source.availability == capture::Availability::kActive ? "best_effort" : "unknown";
}
/// Appends one owned scalar value.
void append(std::vector<Observation>& outputs, const Row& row, Value value) {
  outputs.push_back(observed(row.signal, row.source, std::move(value)));
}
/// Renders the screenshot source from the same cut as its interval metadata.
void screenshot_rows(std::vector<Observation>& outputs, const capture::SourceSnapshot& source) {
  append(outputs, kScreenshotRows[0], std::string(capture::availability_name(source.availability)));
  append(outputs, kScreenshotRows[1], std::string(coverage(source)));
  append(outputs, kScreenshotRows[2], source.epoch);
  append(outputs, kScreenshotRows[3], source.callbacks);
  append(outputs, kScreenshotRows[4], source.ignored);
  append(outputs, kScreenshotRows[5], source.lost);
  append(outputs, kScreenshotRows[6], source.overflow);
  append(outputs, kScreenshotRows[7], source.interval_ms);
  append(outputs, kScreenshotRows[8], source.age_ms);
}
/// Describes scope without widening display evidence to scene evidence.
[[nodiscard]] std::string_view scope_name(capture::Scope scope) {
  if (scope == capture::Scope::kScene) {
    return "selected_scene";
  }
  if (scope == capture::Scope::kScreen) {
    return "selected_screen";
  }
  return "none";
}
/// Preserves the actually sampled three-state UIKit enum.
[[nodiscard]] std::string_view scene_state_name(int state) {
  if (state == 2) {
    return "unspecified";
  }
  return state == 1 ? "active" : "inactive";
}
/// Gives the unused source an honest reason without declaring its public API absent.
[[nodiscard]] capture::Availability scene_reason(capture::Platform platform, capture::Scope scope,
                                                 capture::Availability availability) {
  if (platform == capture::Platform::kLegacy) {
    return capture::Availability::kUnsupported;
  }
  return scope == capture::Scope::kScreen ? capture::Availability::kNotSelected : availability;
}
/// Appends every fixed row with no value on unsupported target or failed primitive acquisition.
template <std::size_t Count>
void absent_rows(std::vector<Observation>& outputs, const std::array<Row, Count>& rows, bool supported) {
  for (const auto& row : rows) {
    outputs.push_back(supported ? failed(row.signal, row.source) : unsupported(row.signal, row.source));
  }
}
/// Renders actual scene or display state without aliasing their scopes.
void recording_rows(std::vector<Observation>& outputs, const capture::SourceSnapshot& source,
                    capture::Platform platform) {
  using capture::Availability;
  using capture::Scope;
  const bool scene = source.scope == Scope::kScene;
  const bool screen = source.scope == Scope::kScreen;
  const bool fresh = source.registered && (source.availability == Availability::kActive ||
                                           source.availability == Availability::kUnavailableState);
  const auto scene_availability = scene_reason(platform, source.scope, source.availability);
  const auto screen_availability = scene ? Availability::kNotSelected : source.availability;
  append(outputs, kRecordingRows[0], std::string(capture::availability_name(source.availability)));
  append(outputs, kRecordingRows[1], std::string(coverage(source)));
  append(outputs, kRecordingRows[2], std::string(scope_name(source.scope)));
  append(outputs, kRecordingRows[3], std::string(capture::availability_name(scene_availability)));
  const auto& scene_row = kRecordingRows[4];
  if (platform == capture::Platform::kLegacy) {
    outputs.push_back(unsupported(scene_row.signal, scene_row.source));
  } else if (scene && fresh && source.state >= 0 && source.state <= 2) {
    append(outputs, scene_row, std::string(scene_state_name(source.state)));
  } else {
    outputs.push_back(failed(scene_row.signal, scene_row.source));
  }
  append(outputs, kRecordingRows[5], std::string(capture::availability_name(screen_availability)));
  const auto& screen_row = kRecordingRows[6];
  if (screen && fresh && source.state >= 0 && source.state <= 1) {
    append(outputs, screen_row, source.state == 1);
  } else {
    outputs.push_back(failed(screen_row.signal, screen_row.source));
  }
  append(outputs, kRecordingRows[7], source.epoch);
  append(outputs, kRecordingRows[8], source.age_ms);
  append(outputs, kRecordingRows[9], source.initial);
  append(outputs, kRecordingRows[10], source.callbacks);
  append(outputs, kRecordingRows[11], source.changes);
  append(outputs, kRecordingRows[12], source.resamples);
  append(outputs, kRecordingRows[13], source.ignored);
  append(outputs, kRecordingRows[14], source.lost);
  append(outputs, kRecordingRows[15], source.overflow);
  append(outputs, kRecordingRows[16], source.interval_ms);
}
}  // namespace
std::vector<Observation> capture(bool screenshots, bool recording, const capture::Input* input) {
  std::vector<Observation> outputs;
  if (!screenshots && !recording) {
    return outputs;
  }
  const auto platform = input == nullptr ? capture::capture_platform() : input->platform;
  if (platform == capture::Platform::kUnsupported) {
    if (screenshots) {
      absent_rows(outputs, kScreenshotRows, false);
    }
    if (recording) {
      absent_rows(outputs, kRecordingRows, false);
    }
    return outputs;
  }
  auto* events = input == nullptr ? &capture::capture_events() : input->events;
  const auto cut = events == nullptr ? capture::Snapshot{.valid = false} : events->drain(screenshots, recording);
  if (!cut.valid) {
    if (screenshots) {
      absent_rows(outputs, kScreenshotRows, true);
    }
    if (recording) {
      absent_rows(outputs, kRecordingRows, true);
    }
    return outputs;
  }
  if (screenshots) {
    screenshot_rows(outputs, cut.sources[0]);
  }
  if (recording) {
    recording_rows(outputs, cut.sources[1], platform);
  }
  return outputs;
}
}  // namespace rasp::ios::checks
