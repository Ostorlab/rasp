/// kUndeliveredRun: the key of the run the reporting plugin did not deliver, in the context the plugins share.

#pragma once

#include <vector>

#include "rasp/context.h"
#include "rasp/observation.h"

namespace rasp::plugins::reporting {

/// All the observations of the newest run the reporting plugin did not deliver: its post failed, it was too large to
/// post, or the plugin could not start its sender. Only the newest such run is kept.
inline constexpr Key<std::vector<Observation>> kUndeliveredRun{.name = "reporting.undelivered_run"};

}  // namespace rasp::plugins::reporting
