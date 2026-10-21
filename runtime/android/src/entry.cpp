/// The entry point of librasp.so. A load-time constructor runs the checks when the linker loads the library, before
/// the app's own code, the way iOS starts from a constructor. The library exposes no JNI method by name.

#include <string>
#include <vector>

#include "checks/example.h"
#include "rasp/observation.h"
#include "rasp/util/logging.h"
#include "rasp/version.h"

namespace {

/// Runs the checks when the dynamic linker loads librasp.so. In a development build, it logs the runtime version and
/// each observation.
__attribute__((constructor)) void rasp_start() noexcept {
  const std::vector<rasp::Observation> observations = rasp::android::checks::example();
  if constexpr (rasp::kLoggingEnabled) {
    rasp::log(std::string(rasp::kRuntimeVersion) + " loaded");
    for (const rasp::Observation& observation : observations) {
      rasp::log(rasp::describe(observation));
    }
  }
}

}  // namespace
