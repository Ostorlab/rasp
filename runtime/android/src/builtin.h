/// The Android built-in check dispatch.

#pragma once

#include <vector>

#include "rasp/config.h"
#include "rasp/observation.h"

namespace rasp::android {

/// Runs enabled built-in groups, preserving their observation identities and statuses.
/// @param config The config whose checks select groups; absent groups do not run.
/// @return The observations from the selected groups, before plugin processing.
[[nodiscard]] std::vector<Observation> run_checks(const Config& config);

}  // namespace rasp::android
