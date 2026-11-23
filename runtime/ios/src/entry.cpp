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

/// Runs the at-rest guard. The guard's decision now lives in a byte-code program the guard VM interprets (see
/// selfdecrypt/vm.h): on the tamper path the program itself ends the process, through the VM's kill opcode, so there is
/// no native "if tampered then end" branch here for an attacker to patch out. The status is still checked on return as
/// a fallback -- if the kill opcode were somehow bypassed, a kTampered result still ends the process -- but the primary
/// enforcement is inside the virtualized program. An unpacked build (kAbsent) and an intact one (kIntact) run on.
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
