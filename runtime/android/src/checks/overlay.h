/// Public host-window observation deltas, selected independently from static checks.
#pragma once

#include <vector>

#include "rasp/observation.h"

namespace rasp::android::checks {

/// Atomically drains bounded received-event deltas; no touches never proves absence of overlays.
/// @return Ten fixed identities; off Android all are unsupported. See docs/android-window-observations.md.
[[nodiscard]] std::vector<Observation> overlay();

}  // namespace rasp::android::checks
