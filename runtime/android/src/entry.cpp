/// The load-time entry of librasp.so. A constructor runs when the dynamic linker loads the library, the way iOS starts
/// from a constructor: it runs the checks on the loading thread, before the app's own code. It does not load the app's
/// code; that is the on-demand loader's job (loader.cpp), which the platform's `JNI_OnLoad` installs moments later. The
/// library exports no `Java_...` entry, only the JVM's `JNI_OnLoad`.

#include <algorithm>
#include <iterator>
#include <jni.h>
#include <string>
#include <vector>

#include "checks/debugger.h"
#include "checks/hooks.h"
#include "checks/integrity.h"
#include "checks/root.h"
#include "rasp/observation.h"
#include "rasp/util/logging.h"
#include "rasp/version.h"

namespace {

/// Whether the library is loaded inside a running JVM. On API 31 and newer, `JNI_GetCreatedJavaVMs` is part of the
/// platform's public native API, so a load-time constructor can tell without an exported JNI entry point.
[[nodiscard]] bool running_in_jvm() noexcept {
  JavaVM* vm = nullptr;
  jsize count = 0;
  return JNI_GetCreatedJavaVMs(&vm, 1, &count) == JNI_OK && count > 0;
}

/// Logs the runtime version and each observation, in a development build only.
void log_observations(const std::vector<rasp::Observation>& observations) {
  if constexpr (rasp::kLoggingEnabled) {
    rasp::log(std::string(rasp::kRuntimeVersion) + " loaded");
    for (const rasp::Observation& observation : observations) {
      rasp::log(rasp::describe(observation));
    }
  }
}

/// Runs the checks when the dynamic linker loads librasp.so, on the app's main thread, before the app's own code. The
/// on-demand loader serves the app's own code later, so this does nothing with the app's dex files.
__attribute__((constructor)) void rasp_start() noexcept {
  if (!running_in_jvm()) {
    return;
  }
  std::vector<rasp::Observation> observations = rasp::android::checks::root();
  std::ranges::move(rasp::android::checks::debugger(), std::back_inserter(observations));
  std::ranges::move(rasp::android::checks::hooks(), std::back_inserter(observations));
  std::ranges::move(rasp::android::checks::integrity(), std::back_inserter(observations));
  log_observations(observations);
}

}  // namespace
