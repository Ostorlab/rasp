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
#include "rasp/heartbeat.h"
#include "rasp/observation.h"
#include "rasp/panic.h"
#include "rasp/plugins/registry.h"
#include "rasp/schedule.h"
#include "rasp/util/logging.h"

namespace rasp::ios {

namespace {

/// The thread: beats the monitoring heartbeat, initialises the plugins, then, until the process exits, observes and
/// beats the heartbeat, runs the jailbreak, debugger, hooking, app-identity, emulator, virtualizer and
/// network-interception checks, arms a panic when they or the heartbeat detect something, runs the plugins, beats
/// again and waits a random check_interval. The context the plugins share is a local of this thread, which never
/// returns, so it lives as long as the process.
///
/// @param argument The value of `DYLD_INSERT_LIBRARIES` when the runtime loaded, a `std::string` allocated with `new`
/// that the thread takes and keeps until the process exits.
/// @return Never returns.
void* monitor(void* argument) {
  const std::unique_ptr<const std::string> inserted_libraries(static_cast<std::string*>(argument));
  Heartbeat& heartbeat = monitor_heartbeat();
  heartbeat.beat(std::chrono::steady_clock::now());
  rasp::plugins::Context context;
  rasp::plugins::init_plugins(rasp::plugins::compiled_in(), read_embedded_config(), context);
  while (true) {
    Observation alive = heartbeat.observe(std::chrono::steady_clock::now());
    heartbeat.beat(std::chrono::steady_clock::now());
    std::vector<Observation> builtin = checks::jailbreak();
    std::ranges::move(checks::debugger(), std::back_inserter(builtin));
    std::ranges::move(checks::hooks(*inserted_libraries), std::back_inserter(builtin));
    std::ranges::move(checks::identity(), std::back_inserter(builtin));
    std::ranges::move(checks::emulator(), std::back_inserter(builtin));
    std::ranges::move(checks::virtualizer(), std::back_inserter(builtin));
    std::ranges::move(checks::mitm(), std::back_inserter(builtin));
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

void start_monitoring(std::string inserted_libraries) noexcept {
  auto handed = std::make_unique<std::string>(std::move(inserted_libraries));
  pthread_attr_t attributes{};
  if (pthread_attr_init(&attributes) != 0) {
    return;
  }
  if (pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED) == 0) {
    pthread_t thread{};
    if (pthread_create(&thread, &attributes, monitor, handed.get()) == 0) {
      static_cast<void>(handed.release());
    }
  }
  static_cast<void>(pthread_attr_destroy(&attributes));
}

}  // namespace rasp::ios
