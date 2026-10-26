/// start_monitoring: the runtime's own thread on iOS, which runs the checks and the plugins.

#include "monitoring.h"

#include <chrono>
#include <cstddef>
#include <pthread.h>
#include <thread>
#include <vector>

#include "checks/jailbreak.h"
#include "plugins/load.h"
#include "rasp/observation.h"
#include "rasp/plugins/host.h"
#include "rasp/util/logging.h"

namespace rasp::ios {

namespace {

/// The stack size of the thread, a whole number of pages.
constexpr std::size_t kThreadStackSize = std::size_t{256} * 1024;

/// How long the thread waits between two passes.
constexpr std::chrono::seconds kCheckInterval{60};

/// The thread: loads the plugins, then runs a pass every kCheckInterval, until the process exits.
///
/// @return Never returns.
void* monitor(void* /*argument*/) {
  const std::vector<rasp::plugins::Listed> listed = plugins::load_plugins();
  rasp::plugins::Host host(listed);
  while (true) {
    const std::vector<Observation> observations = host.run_pass(checks::jailbreak());
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

}  // namespace rasp::ios
