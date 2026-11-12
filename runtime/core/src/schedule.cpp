/// check_interval: the random wait between two runs of the monitoring thread.

#include "rasp/schedule.h"

#include <chrono>
#include <cstdint>
#include <cstdlib>

namespace rasp {

std::chrono::milliseconds check_interval() noexcept {
  const auto span = static_cast<std::uint32_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(kMaxCheckInterval - kMinCheckInterval).count());
  return kMinCheckInterval + std::chrono::milliseconds{arc4random_uniform(span + 1)};
}

}  // namespace rasp
