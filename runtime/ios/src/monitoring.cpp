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
#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/embedded_config.h"
#include "rasp/observation.h"
#include "rasp/plugins/registry.h"
#include "rasp/util/logging.h"

namespace rasp::ios {

namespace {

/// How long the thread waits between two runs of the checks.
constexpr std::chrono::seconds kCheckInterval{60};

/// The thread: reads the runtime's config and initialises the plugins with it, then runs the jailbreak, debugger,
/// hooking, app-identity, emulator, virtualizer and network-interception checks, each only when the config enables its
/// group, and the plugins, then again every kCheckInterval, until the process exits. The config and the context the
/// plugins share are locals of this thread, which never returns, so they live as long as the process.
///
/// @param argument The value of `DYLD_INSERT_LIBRARIES` when the runtime loaded, a `std::string` allocated with `new`
/// that the thread takes and keeps until the process exits.
/// @return Never returns.
void* monitor(void* argument) {
  const std::unique_ptr<const std::string> inserted_libraries(static_cast<std::string*>(argument));
  const Config config = read_embedded_config();
  rasp::plugins::Context context;
  rasp::plugins::init_plugins(rasp::plugins::compiled_in(), config, context);
  while (true) {
    std::vector<Observation> builtin;
    if (is_check_enabled(config, "jailbreak")) {
      std::ranges::move(checks::jailbreak(), std::back_inserter(builtin));
    }
    if (is_check_enabled(config, "debugger")) {
      std::ranges::move(checks::debugger(), std::back_inserter(builtin));
    }
    if (is_check_enabled(config, "hooks")) {
      std::ranges::move(checks::hooks(*inserted_libraries), std::back_inserter(builtin));
    }
    if (is_check_enabled(config, "identity")) {
      std::ranges::move(checks::identity(), std::back_inserter(builtin));
    }
    if (is_check_enabled(config, "emulator")) {
      std::ranges::move(checks::emulator(), std::back_inserter(builtin));
    }
    if (is_check_enabled(config, "virtualizer")) {
      std::ranges::move(checks::virtualizer(), std::back_inserter(builtin));
    }
    if (is_check_enabled(config, "mitm")) {
      std::ranges::move(checks::mitm(), std::back_inserter(builtin));
    }
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
