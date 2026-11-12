/// Independently selected screenshot and recording interval observations.
#pragma once
#include <vector>

#include "rasp/observation.h"
namespace rasp::android::checks {
/// Drains selected source counters once; never registers a platform listener.
/// @param screenshots Select the screenshot source.
/// @param recording Select the recording source.
/// @return Exact ordered scalar identities for selected groups.
[[nodiscard]] std::vector<Observation> capture(bool screenshots, bool recording);
}  // namespace rasp::android::checks
