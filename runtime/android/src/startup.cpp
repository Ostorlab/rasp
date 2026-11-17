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
#include "rasp/config.h"
#include "rasp/embedded_config.h"
#include "rasp/observation.h"
#include "rasp/panic.h"
#include "rasp/util/logging.h"

namespace rasp::android {

namespace {

/// Runs the check groups the runtime's config enables among the debugger, hooking, self-integrity, root and emulator
/// checks, so a group the operator did not choose never runs here either — the same rule the monitoring thread's
/// dispatch follows.
///
/// @param config The runtime's config, which the packer wrote.
/// @return What they observed: the enabled groups among the debugger, hooking, self-integrity, root and emulator
/// checks, in that order.
[[nodiscard]] std::vector<Observation> startup_observations(const rasp::Config& config) {
  std::vector<Observation> observations;
  // The mask's bits are the groups' positions in the packer's CHECKS order, which this dispatch's order keeps in step
  // with: new groups append at both ends.
  if (is_check_enabled(config, 1, "debugger")) {
    std::ranges::move(checks::debugger(), std::back_inserter(observations));
  }
  if (is_check_enabled(config, 2, "hooks")) {
    std::ranges::move(checks::hooks(), std::back_inserter(observations));
  }
  if (is_check_enabled(config, 3, "integrity")) {
    std::ranges::move(checks::integrity(), std::back_inserter(observations));
  }
  if (is_check_enabled(config, 0, "root")) {
    std::ranges::move(checks::root(), std::back_inserter(observations));
  }
  if (is_check_enabled(config, 6, "emulator")) {
    std::ranges::move(checks::emulator(), std::back_inserter(observations));
  }
  return observations;
}

}  // namespace

void run_startup_checks() noexcept {
  const rasp::Config config = read_embedded_config();
  if constexpr (kLoggingEnabled) {
    const std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
    const std::vector<Observation> observations = startup_observations(config);
    const auto took =
        std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count();
    rasp::log("start-up checks took " + std::to_string(took) + " us");
    for (const Observation& observation : observations) {
      rasp::log("start-up " + describe(observation));
    }
    static_cast<void>(panic_on_detection(observations, end_process));
  } else {
    static_cast<void>(panic_on_detection(startup_observations(config), end_process));
  }
}

}  // namespace rasp::android
