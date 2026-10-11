/// The example check, a placeholder until the first real check ships.

#pragma once

#include <vector>

#include "rasp/observation.h"

namespace rasp::android::checks {

/// The example check. It always reports the same observation, to show how a check reports its observations.
///
/// @return One observation: signal `example.loaded`, source `runtime`, status Status::kOk and value `true`.
[[nodiscard]] std::vector<Observation> example();

}  // namespace rasp::android::checks
