/// run_startup_checks: the checks that run synchronously while librasp.so loads.

#include "startup.h"

#include <algorithm>
#include <chrono>
#include <iterator>
#include <string>
#include <vector>

#include "checks/debugger.h"
#include "checks/emulator.h"
#include "checks/hooks.h"
#include "checks/integrity.h"
#include "checks/root.h"
#include "panic/end_process.h"
#include "rasp/observation.h"
#include "rasp/panic.h"
#include "rasp/util/logging.h"

namespace rasp::android {

namespace {

/// Runs the debugger, hooking, self-integrity, root and emulator checks.
///
/// @return What they observed, in that order.
[[nodiscard]] std::vector<Observation> startup_observations() {
  std::vector<Observation> observations = checks::debugger();
  std::ranges::move(checks::hooks(), std::back_inserter(observations));
  std::ranges::move(checks::integrity(), std::back_inserter(observations));
  std::ranges::move(checks::root(), std::back_inserter(observations));
  std::ranges::move(checks::emulator(), std::back_inserter(observations));
  return observations;
}

}  // namespace

void run_startup_checks() noexcept {
  if constexpr (kLoggingEnabled) {
    const std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
    const std::vector<Observation> observations = startup_observations();
    const auto took =
        std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count();
    rasp::log("start-up checks took " + std::to_string(took) + " us");
    for (const Observation& observation : observations) {
      rasp::log("start-up " + describe(observation));
    }
    static_cast<void>(panic_on_detection(observations, end_process));
  } else {
    static_cast<void>(panic_on_detection(startup_observations(), end_process));
  }
}

}  // namespace rasp::android
