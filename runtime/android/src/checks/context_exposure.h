/// Opt-in fixed-package visibility, default proxy and truthful developer-settings availability.
#pragma once
#include <vector>

#include "rasp/observation.h"
namespace rasp::android::checks {
/// Queries only three selected manager identifiers via the retained Application.
/// @return One bounded visibility observation; negative lookups never prove absence.
[[nodiscard]] std::vector<Observation> root_packages();
/// Reads the public default HTTP proxy without fetching or copying PAC URLs.
/// @return One mode/host/port observation, error when unavailable, unsupported off Android.
[[nodiscard]] std::vector<Observation> proxy();
/// Reports unsupported settings truth for third-party callers; sanitized zero is never disabled.
/// @return Exactly two unsupported observations with no boolean value.
[[nodiscard]] std::vector<Observation> developer_settings();
}  // namespace rasp::android::checks
