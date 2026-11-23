/// The entry point of RaspRuntime.framework. iOS runs it when it loads the framework, on the app's main thread,
/// before the app's own code.

#include <string>
#include <utility>

#include "checks/hooks.h"
#include "monitoring.h"
#include "rasp/util/logging.h"
#include "rasp/version.h"
#include "selfdecrypt/guard.h"
#include "startup.h"

namespace {

/// Logs the runtime's version in a development build, reads `DYLD_INSERT_LIBRARIES` once, checks the at-rest guard,
/// runs the start-up checks, and starts the thread that runs the checks from then on.
///
/// The at-rest guard is checked for its result only (logged in a development build); it does not yet gate anything, so
/// a build where the packer has not written the guard blob still runs. Gating real behaviour on it is the next step,
/// once the decrypt is confirmed on a device.
__attribute__((constructor)) void rasp_start() noexcept {
  if constexpr (rasp::kLoggingEnabled) {
    rasp::log(std::string(rasp::kRuntimeVersion) + " loaded");
    const bool intact = rasp::ios::selfdecrypt::at_rest_guard_intact();
    rasp::log(std::string("at-rest guard ") + (intact ? "intact" : "not intact"));
  }
  std::string inserted_libraries = rasp::ios::checks::read_inserted_libraries();
  rasp::ios::run_startup_checks(inserted_libraries);
  rasp::ios::start_monitoring(std::move(inserted_libraries));
}

}  // namespace
