/// The entry point of RaspRuntime.framework. iOS runs it when it loads the framework, on the app's main thread,
/// before the app's own code.

#include <string>
#include <vector>

#include "checks/example.h"
#include "rasp/observation.h"
#include "rasp/util/logging.h"
#include "rasp/version.h"

namespace {

/// Runs the checks and, in a development build, logs the runtime version and each observation.
__attribute__((constructor)) void rasp_start() noexcept {
  const std::vector<rasp::Observation> observations = rasp::ios::checks::example();
  if constexpr (rasp::kLoggingEnabled) {
    rasp::log(std::string(rasp::kRuntimeVersion) + " loaded");
    for (const rasp::Observation& observation : observations) {
      rasp::log(rasp::describe(observation));
    }
  }
}

}  // namespace
