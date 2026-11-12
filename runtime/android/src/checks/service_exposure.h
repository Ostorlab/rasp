/// Public Android service metadata observations; no service content is accessed.

#pragma once

#include <vector>

#include "rasp/observation.h"

namespace rasp::android::checks {
/// Reports enabled accessibility components with capability/request flags.
/// @return One observation; absent Context or failed/bounded reads report error, off Android unsupported.
[[nodiscard]] std::vector<Observation> accessibility();
/// Reports enabled IMEs and the API34+ selected IME independently.
/// @return Two observations; current IME is unsupported below API34; null/failed reads are errors.
[[nodiscard]] std::vector<Observation> input_method();
/// Reports enabled notification listener components through the AndroidX-compatible secure setting.
/// @return One observation; a missing setting is unknown/error, an explicit empty string is an empty list.
[[nodiscard]] std::vector<Observation> notification_access();
}  // namespace rasp::android::checks
