#include <string>
#include <vector>

#include "rasp/checks/ios/jailbreak.h"
#include "rasp/logging.h"
#include "rasp/observation.h"
#include "rasp/version.h"

namespace {

__attribute__((constructor)) void rasp_start() noexcept {
  const std::vector<rasp::Observation> observations = rasp::checks::ios::jailbreak();
  if constexpr (rasp::kLoggingEnabled) {
    rasp::log(std::string(rasp::kRuntimeVersion) + " loaded");
    for (const rasp::Observation& observation : observations) {
      rasp::log(rasp::describe(observation));
    }
  }
}

}  // namespace
