/// The entry point of RaspRuntime.framework. iOS runs it when it loads the framework, on the app's main thread,
/// before the app's own code.

#include <string>
#include <utility>

#include "checks/hooks.h"
#include "monitoring.h"
#include "panic/end_process.h"
#include "rasp/util/logging.h"
#include "rasp/version.h"
#include "selfdecrypt/guard.h"
#include "startup.h"

namespace {

/// Ends the process when the at-rest guard was written by the packer but does not decrypt: the runtime's code or the
/// embedded seed changed after packing, which a patched or stripped runtime produces. An unpacked build (kAbsent) and
/// an intact one (kIntact) run on. This is what couples the app to the runtime: tamper with the runtime and it ends.
void enforce_at_rest_guard() noexcept {
  if (rasp::ios::selfdecrypt::at_rest_guard_status() == rasp::ios::selfdecrypt::GuardStatus::kTampered) {
    rasp::ios::end_process();
  }
}

/// Logs the runtime's version in a development build, reads `DYLD_INSERT_LIBRARIES` once, enforces the at-rest guard,
/// runs the start-up checks, and starts the thread that runs the checks from then on.
__attribute__((constructor)) void rasp_start() noexcept {
  if constexpr (rasp::kLoggingEnabled) {
    rasp::log(std::string(rasp::kRuntimeVersion) + " loaded");
  }
  enforce_at_rest_guard();
  std::string inserted_libraries = rasp::ios::checks::read_inserted_libraries();
  rasp::ios::run_startup_checks(inserted_libraries);
  rasp::ios::start_monitoring(std::move(inserted_libraries));
}

}  // namespace
