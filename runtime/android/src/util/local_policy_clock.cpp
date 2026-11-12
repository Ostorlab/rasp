/// Suspend-inclusive gate clock, separate from telemetry clock semantics.
#include "util/local_policy_clock.h"

#include <cstdint>
#include <optional>

#include "local_policy_state.h"
namespace rasp {
std::optional<std::int64_t> read_local_policy_clock() { return android::read_suspend_clock(); }
}  // namespace rasp
