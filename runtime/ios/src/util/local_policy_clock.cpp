/// Private suspend-inclusive operation-gate clock; no wire or telemetry clock change.
#include "local_policy_clock.h"

#include <cstdint>
#include <mach/kern_return.h>
#include <mach/mach_time.h>
#include <optional>

#include "local_policy_state.h"

namespace rasp {
std::optional<std::int64_t> read_local_policy_clock() {
  mach_timebase_info_data_t base{};
  if (mach_timebase_info(&base) != KERN_SUCCESS || base.numer == 0 || base.denom == 0) {
    return std::nullopt;
  }
  return policy_internal::clock_nanoseconds(mach_continuous_time(),
                                            {.numerator = base.numer, .denominator = base.denom});
}
}  // namespace rasp
