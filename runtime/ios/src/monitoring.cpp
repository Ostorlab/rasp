/// start_monitoring: the runtime's own thread on iOS, which runs the checks and the plugins.

#include "monitoring.h"

#include <algorithm>
#include <chrono>
#include <iterator>
#include <memory>
#include <pthread.h>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "checks/debugger.h"
#include "checks/emulator.h"
#include "checks/hooks.h"
#include "checks/identity.h"
#include "checks/jailbreak.h"
#include "checks/mitm.h"
#include "checks/virtualizer.h"
#include "panic/end_process.h"
#include "rasp/context.h"
#include "rasp/embedded_config.h"
#include "rasp/observation.h"
#include "rasp/panic.h"
#include "rasp/plugins/registry.h"
#include "rasp/util/logging.h"

namespace rasp::ios {

namespace {

/// How long the thread waits between two runs of the checks.
constexpr std::chrono::seconds kCheckInterval{60};

/// The thread: initialises the plugins, then runs the jailbreak, debugger, hooking, app-identity, emulator, virtualizer
/// and network-interception checks, arms a panic when they detect something, and runs the plugins, then again every
/// kCheckInterval, until the process exits. The context the plugins share is a local of this thread, which never
/// returns, so it lives as long as the process.
///
/// @param argument The value of `DYLD_INSERT_LIBRARIES` when the runtime loaded, a `std::string` allocated with `new`
/// that the thread takes and keeps until the process exits.
/// @return Never returns.
void* monitor(void* argument) {
  const std::unique_ptr<const std::string> inserted_libraries(static_cast<std::string*>(argument));
  rasp::plugins::Context context;
  rasp::plugins::init_plugins(rasp::plugins::compiled_in(), read_embedded_config(), context);
  while (true) {
    std::vector<Observation> builtin = checks::jailbreak();
    std::ranges::move(checks::debugger(), std::back_inserter(builtin));
    std::ranges::move(checks::hooks(*inserted_libraries), std::back_inserter(builtin));
    std::ranges::move(checks::identity(), std::back_inserter(builtin));
    std::ranges::move(checks::emulator(), std::back_inserter(builtin));
    std::ranges::move(checks::virtualizer(), std::back_inserter(builtin));
    std::ranges::move(checks::mitm(), std::back_inserter(builtin));
    static_cast<void>(panic_on_detection(builtin, end_process));
    const std::vector<Observation> observations =
        rasp::plugins::run_plugins(rasp::plugins::compiled_in(), std::move(builtin), context);
    if constexpr (kLoggingEnabled) {
      for (const Observation& observation : observations) {
        rasp::log(describe(observation));
      }
    }
    std::this_thread::sleep_for(kCheckInterval);
  }
}

}  // namespace

void start_monitoring() noexcept {
  auto inserted_libraries = std::make_unique<std::string>(checks::read_inserted_libraries());
  pthread_attr_t attributes{};
  if (pthread_attr_init(&attributes) != 0) {
    return;
  }
  if (pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED) == 0) {
    pthread_t thread{};
    if (pthread_create(&thread, &attributes, monitor, inserted_libraries.get()) == 0) {
      static_cast<void>(inserted_libraries.release());
    }
  }
  static_cast<void>(pthread_attr_destroy(&attributes));
}

}  // namespace rasp::ios
