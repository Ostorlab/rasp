/// Selection and dispatch of Android built-in check groups.

#pragma once

#include <vector>

#include "rasp/config.h"
#include "rasp/observation.h"

namespace rasp::android {
/// Runs each explicitly selected built-in group once in catalogue order.
/// @param config Embedded check selection; an absent or empty list runs no groups.
/// @return Typed observations, including unknown, error and unsupported results.
[[nodiscard]] std::vector<Observation> run_checks(const Config& config);
}  // namespace rasp::android
