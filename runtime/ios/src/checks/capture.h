/// Scalar iOS capture observations from one bounded primitive cut.
#pragma once
#include <vector>

#include "capture/capture_events.h"
#include "rasp/observation.h"

namespace rasp::ios::capture {
/// Optional finite production-dispatch boundary; no UIKit is replaced by host tests.
struct Input {
  CaptureEvents* events;
  Platform platform;
};
}  // namespace rasp::ios::capture
namespace rasp::ios::checks {
/// Drains only selected capture sources and renders their complete fixed scalar schema.
/// @param screenshots Selected screenshot group.
/// @param recording Selected capture-state group.
/// @param input Optional primitive state and target capability, normally actual process state.
/// @return Exactly nine and/or seventeen observations, with unavailable measured values absent.
[[nodiscard]] std::vector<Observation> capture(bool screenshots, bool recording, const capture::Input* input = nullptr);
}  // namespace rasp::ios::checks
