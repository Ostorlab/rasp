/// run_startup_checks: the checks that run synchronously while the framework loads.

#include "startup.h"

#include <algorithm>
#include <chrono>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

#include "checks/debugger.h"
#include "checks/hooks.h"
#include "panic/end_process.h"
#include "rasp/observation.h"
#include "rasp/panic.h"
#include "rasp/util/logging.h"

namespace rasp::ios {

namespace {

/// Runs the debugger checks and the hooking checks of fast_hooks.
///
/// @param inserted_libraries The value of `DYLD_INSERT_LIBRARIES` when the runtime loaded.
/// @return What they observed, in that order.
[[nodiscard]] std::vector<Observation> startup_observations(std::string_view inserted_libraries) {
  std::vector<Observation> observations = checks::debugger();
  std::ranges::move(checks::fast_hooks(inserted_libraries), std::back_inserter(observations));
  return observations;
}

}  // namespace

void run_startup_checks(std::string_view inserted_libraries) noexcept {
  if constexpr (kLoggingEnabled) {
    const std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
    const std::vector<Observation> observations = startup_observations(inserted_libraries);
    const auto took =
        std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count();
    rasp::log("start-up checks took " + std::to_string(took) + " us");
    for (const Observation& observation : observations) {
      rasp::log("start-up " + describe(observation));
    }
    static_cast<void>(panic_on_detection(observations, end_process));
  } else {
    static_cast<void>(panic_on_detection(startup_observations(inserted_libraries), end_process));
  }
}

}  // namespace rasp::ios
