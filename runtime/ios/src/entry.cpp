/// The entry point of RaspRuntime.framework. iOS runs it when it loads the framework, on the app's main thread,
/// before the app's own code.

#include <string>

#include "monitoring.h"
#include "rasp/util/logging.h"
#include "rasp/version.h"

namespace {

/// Logs the runtime's version in a development build, and starts the thread that runs the checks.
__attribute__((constructor)) void rasp_start() noexcept {
  if constexpr (rasp::kLoggingEnabled) {
    rasp::log(std::string(rasp::kRuntimeVersion) + " loaded");
  }
  rasp::ios::start_monitoring();
}

}  // namespace
