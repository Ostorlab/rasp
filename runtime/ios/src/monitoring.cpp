/// start_monitoring: the runtime's own thread on iOS, which runs the checks.

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
#include "checks/jailbreak.h"
#include "rasp/observation.h"
#include "rasp/util/logging.h"

namespace rasp::ios {

namespace {

/// The stack size of the thread, a whole number of pages.
constexpr std::size_t kThreadStackSize = std::size_t{256} * 1024;

/// How long the thread waits between two runs of the checks.
constexpr std::chrono::seconds kCheckInterval{60};

/// The thread: runs the jailbreak, debugger and hooking checks, then again every kCheckInterval, until the process
/// exits.
void* monitor(void* /*argument*/) {
  while (true) {
    std::vector<Observation> observations = checks::jailbreak();
    std::ranges::move(checks::debugger(), std::back_inserter(observations));
    std::ranges::move(checks::hooks(), std::back_inserter(observations));
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
