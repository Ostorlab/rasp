/// Selection and dispatch of the iOS built-in checks.

#pragma once

#include <string_view>
#include <vector>

#include "rasp/config.h"
#include "rasp/observation.h"

namespace rasp::ios {

/// Runs each selected check group once, in catalogue order, preserving typed source observations.
/// @param config The embedded config; an absent or empty check list runs no checks.
/// @param inserted_libraries DYLD_INSERT_LIBRARIES captured at process load.
/// @return The selected groups' observations, including unsupported and failed results.
[[nodiscard]] std::vector<Observation> run_checks(const Config& config, std::string_view inserted_libraries);

}  // namespace rasp::ios
