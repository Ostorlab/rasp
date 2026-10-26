/// start_monitoring: the runtime's own thread on Android, which runs the checks and the plugins.

#include "monitoring.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <iterator>
#include <pthread.h>
#include <thread>
#include <vector>

#include "checks/debugger.h"
#include "checks/hooks.h"
#include "checks/integrity.h"
#include "checks/mitm.h"
#include "checks/root.h"
#include "plugins/load.h"
#include "rasp/observation.h"
#include "rasp/plugins/host.h"
#include "rasp/util/logging.h"

namespace rasp::android {

namespace {

/// The stack size of the thread, a whole number of pages.
constexpr std::size_t kThreadStackSize = std::size_t{256} * 1024;

/// How long the thread waits between two passes.
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
  return observations;
}

/// The thread: loads the plugins, then runs a pass every kCheckInterval, until the process exits.
///
/// @return Never returns.
void* monitor(void* /*argument*/) {
  const std::vector<rasp::plugins::Listed> listed = plugins::load_plugins();
  rasp::plugins::Host host(listed);
  while (true) {
    const std::vector<Observation> observations = host.run_pass(run_checks());
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
  if (pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED) == 0 &&
      pthread_attr_setstacksize(&attributes, kThreadStackSize) == 0) {
    pthread_t thread{};
    static_cast<void>(pthread_create(&thread, &attributes, monitor, nullptr));
  }
  static_cast<void>(pthread_attr_destroy(&attributes));
}

}  // namespace rasp::android
