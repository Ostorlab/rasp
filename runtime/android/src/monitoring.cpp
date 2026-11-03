/// start_monitoring: the runtime's own thread on Android, which runs the checks and the plugins.

#include "monitoring.h"

#include <algorithm>
#include <chrono>
#include <iterator>
#include <pthread.h>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "checks/debugger.h"
#include "checks/emulator.h"
#include "checks/hooks.h"
#include "checks/identity.h"
#include "checks/integrity.h"
#include "checks/mitm.h"
#include "checks/root.h"
#include "panic/end_process.h"
#include "rasp/context.h"
#include "rasp/embedded_config.h"
#include "rasp/heartbeat.h"
#include "rasp/observation.h"
#include "rasp/panic.h"
#include "rasp/plugins/registry.h"
#include "rasp/schedule.h"
#include "rasp/util/logging.h"

namespace rasp::android {

namespace {

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

/// The thread: beats the monitoring heartbeat, initialises the plugins, then, until the process exits, observes and
/// beats the heartbeat, runs the built-in checks, arms a panic when they or the heartbeat detect something, runs the
/// plugins, beats again and waits a random check_interval. The context the plugins share is a local of this thread,
/// which never returns, so it lives as long as the process.
///
/// @return Never returns.
void* monitor(void* /*argument*/) {
  Heartbeat& heartbeat = monitor_heartbeat();
  heartbeat.beat(std::chrono::steady_clock::now());
  rasp::plugins::Context context;
  rasp::plugins::init_plugins(rasp::plugins::compiled_in(), read_embedded_config(), context);
  while (true) {
    Observation alive = heartbeat.observe(std::chrono::steady_clock::now());
    heartbeat.beat(std::chrono::steady_clock::now());
    std::vector<Observation> builtin = run_checks();
    builtin.push_back(std::move(alive));
    static_cast<void>(panic_on_detection(builtin, end_process));
    const std::vector<Observation> observations =
        rasp::plugins::run_plugins(rasp::plugins::compiled_in(), std::move(builtin), context);
    heartbeat.beat(std::chrono::steady_clock::now());
    const std::chrono::milliseconds interval = check_interval();
    if constexpr (kLoggingEnabled) {
      for (const Observation& observation : observations) {
        rasp::log(describe(observation));
      }
      rasp::log("next run in " + std::to_string(interval.count()) + " ms");
    }
    std::this_thread::sleep_for(interval);
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
