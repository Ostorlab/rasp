/// start_monitoring: the runtime's own thread on Android, which runs the checks and the plugins.

#include "monitoring.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iterator>
#include <optional>
#include <pthread.h>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "apk/archive.h"
#include "apk/location.h"
#include "checks/debugger.h"
#include "checks/emulator.h"
#include "checks/hooks.h"
#include "checks/identity.h"
#include "checks/integrity.h"
#include "checks/mitm.h"
#include "checks/root.h"
#include "payload/assets.h"
#include "rasp/config.h"
#include "rasp/observation.h"
#include "rasp/parse_config.h"
#include "rasp/plugins/registry.h"
#include "rasp/util/logging.h"

namespace rasp::android {

namespace {

/// How long the thread waits between two runs of the checks.
constexpr std::chrono::seconds kCheckInterval{60};

/// Reads the runtime's config, the config entry of the APK the runtime runs from.
///
/// @return The config. Each field is empty when the APK has no config entry or the entry can't be read.
[[nodiscard]] Config read_config() {
  const std::optional<std::string> apk = apk::self_apk_path();
  if (!apk.has_value()) {
    return {};
  }
  const std::optional<std::vector<std::uint8_t>> entry = apk::read_stored_entry(*apk, payload::kConfigEntry);
  if (!entry.has_value()) {
    return {};
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): the entry's bytes are the JSON text.
  return parse_config(std::string_view(reinterpret_cast<const char*>(entry->data()), entry->size()));
}

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
  rasp::plugins::init_plugins(rasp::plugins::compiled_in(), read_config());
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
