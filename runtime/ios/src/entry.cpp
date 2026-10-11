/// The entry point of RaspRuntime.framework. iOS runs it when it loads the framework, on the app's main thread,
/// before the app's own code.

#include <string>
#include <utility>
#include <vector>

#include "checks/jailbreak.h"
#include "rasp/observation.h"
#include "rasp/util/logging.h"
#include "rasp/version.h"
#include "reporting/thread.h"

namespace {

/// Runs the checks, logs them in a development build, and starts the thread that reports them to the ADR server.
__attribute__((constructor)) void rasp_start() noexcept {
  std::vector<rasp::Observation> observations = rasp::ios::checks::jailbreak();
  if constexpr (rasp::kLoggingEnabled) {
    rasp::log(std::string(rasp::kRuntimeVersion) + " loaded");
    for (const rasp::Observation& observation : observations) {
      rasp::log(rasp::describe(observation));
    }
  }
  rasp::ios::start_reporting(std::move(observations));
}

}  // namespace
