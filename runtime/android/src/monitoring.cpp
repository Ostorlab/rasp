/// start_monitoring: the runtime's own thread on Android, which runs the checks and the plugins.

#include "monitoring.h"

#include <algorithm>
#include <chrono>
#include <iterator>
#include <optional>
#include <pthread.h>
#include <string>
#include <thread>
#include <vector>

#include "checks/debugger.h"
#include "checks/emulator.h"
#include "checks/hooks.h"
#include "checks/identity.h"
#include "checks/integrity.h"
#include "checks/mitm.h"
#include "checks/root.h"
#include "data_dir.h"
#include "rasp/embedded_config.h"
#include "rasp/install_id.h"
#include "rasp/observation.h"
#include "rasp/plugins/registry.h"
#include "rasp/util/logging.h"

namespace rasp::android {

namespace {

/// How long the thread waits between two runs of the checks.
constexpr std::chrono::seconds kCheckInterval{60};

/// Runs the built-in checks.
///
/// @return What they observed: the root, debugger, hooking, integrity and network-interception checks, in that order.
[[nodiscard]] std::vector<Observation> run_checks() {
  std::vector<Observation> observations = checks::root();
  std::ranges::move(checks::debugger(), std::back_inserter(observations));
  std::ranges::move(checks::hooks(), std::back_inserter(observations));
  std::ranges::move(checks::integrity(), std::back_inserter(observations));
  std::ranges::move(checks::mitm(), std::back_inserter(observations));
  std::ranges::move(checks::identity(), std::back_inserter(observations));
  std::ranges::move(checks::emulator(), std::back_inserter(observations));
  return observations;
}

/// The thread: initialises the plugins, then runs the built-in checks and the plugins, then again every kCheckInterval,
/// until the process exits.
///
/// @return Never returns.
void* monitor(void* /*argument*/) {
  Config config = read_embedded_config();
  const std::optional<std::string> dir = data_dir();
  if (dir.has_value()) {
    const std::optional<InstallId> id = get_or_create_install_id(*dir);
    if (id.has_value()) {
      config.install_id = *id;
    }
  }
  if constexpr (kLoggingEnabled) {
    rasp::log(config.install_id != InstallId{} ? "install_id loaded" : "install_id unavailable");
  }
  rasp::plugins::init_plugins(rasp::plugins::compiled_in(), config);
  while (true) {
    const std::vector<Observation> observations =
        rasp::plugins::run_plugins(rasp::plugins::compiled_in(), run_checks());
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
  pthread_attr_t attributes{};
  if (pthread_attr_init(&attributes) != 0) {
    return;
  }
  if (pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED) == 0) {
    pthread_t thread{};
    static_cast<void>(pthread_create(&thread, &attributes, monitor, nullptr));
  }
  static_cast<void>(pthread_attr_destroy(&attributes));
}

}  // namespace rasp::android
