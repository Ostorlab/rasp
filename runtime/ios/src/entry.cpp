/// The entry point of RaspRuntime.framework. iOS runs it when it loads the framework, on the app's main thread,
/// before the app's own code.

#include <string>
#include <utility>

#include "checks/hooks.h"
#include "monitoring.h"
#include "rasp/util/logging.h"
#include "rasp/version.h"
#include "startup.h"

namespace {

/// Logs the runtime's version in a development build, reads `DYLD_INSERT_LIBRARIES` once, runs the start-up checks,
/// and starts the thread that runs the checks from then on.
__attribute__((constructor)) void rasp_start() noexcept {
  if constexpr (rasp::kLoggingEnabled) {
    rasp::log(std::string(rasp::kRuntimeVersion) + " loaded");
  }
  std::string inserted_libraries = rasp::ios::checks::read_inserted_libraries();
  rasp::ios::run_startup_checks(inserted_libraries);
  rasp::ios::start_monitoring(std::move(inserted_libraries));
}

}  // namespace
