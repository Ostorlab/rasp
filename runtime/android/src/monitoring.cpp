/// start_monitoring: the runtime's own thread on Android, which runs the checks and the plugins.

#include "monitoring.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
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
#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/embedded_config.h"
#include "rasp/install_id.h"
#include "rasp/observation.h"
#include "rasp/plugins/registry.h"
#include "rasp/util/logging.h"
#include "util/app_storage.h"

namespace rasp::android {

namespace {

/// How long the thread waits between two runs of the checks.
constexpr std::chrono::seconds kCheckInterval{60};

/// Runs the built-in check groups that the runtime's config enables.
///
/// @param config The runtime's config.
/// @return What they observed: the root, debugger, hooking, integrity, network-interception, app-identity and emulator
/// checks, in that order, each only when the config enables its group.
[[nodiscard]] std::vector<Observation> run_checks(const Config& config) {
  std::vector<Observation> observations;
  // The mask's bits are the groups' positions in the packer's CHECKS order, which this dispatch's order keeps in
  // step with: new groups append at both ends.
  const auto enabled = [&config](unsigned bit, std::string_view id) {
    if (config.checks_mask.has_value()) {
      return (config.checks_mask.value() & (std::uint64_t{1} << bit)) != 0;
    }
    return is_check_enabled(config, id);
  };
  if (enabled(0, "root")) {
    std::ranges::move(checks::root(), std::back_inserter(observations));
  }
  if (enabled(1, "debugger")) {
    std::ranges::move(checks::debugger(), std::back_inserter(observations));
  }
  if (enabled(2, "hooks")) {
    std::ranges::move(checks::hooks(), std::back_inserter(observations));
  }
  if (enabled(3, "integrity")) {
    std::ranges::move(checks::integrity(), std::back_inserter(observations));
  }
  if (enabled(4, "mitm")) {
    std::ranges::move(checks::mitm(), std::back_inserter(observations));
  }
  if (enabled(5, "identity")) {
    std::ranges::move(checks::identity(), std::back_inserter(observations));
  }
  if (enabled(6, "emulator")) {
    std::ranges::move(checks::emulator(), std::back_inserter(observations));
  }
  return observations;
}

/// The runtime's config, with the install id kept in the app's `no_backup` folder.
///
/// @return The config the packer wrote, with its install id, which stays `std::nullopt` when it can't be read or kept.
[[nodiscard]] Config read_config() {
  Config config = read_embedded_config();
  const std::optional<std::string> directory = util::make_no_backup_directory();
  if (directory) {
    config.install_id = load_or_create_install_id(*directory);
  }
  return config;
}

/// The thread: reads the runtime's config and initialises the plugins with it, then runs the built-in checks the config
/// enables and the plugins, then again every kCheckInterval, until the process exits. The config and the context the
/// plugins share are locals of this thread, which never returns, so they live as long as the process.
///
/// @return Never returns.
void* monitor(void* /*argument*/) {
  const Config config = read_config();
  rasp::plugins::Context context;
  rasp::plugins::init_plugins(rasp::plugins::compiled_in(), config, context);
  while (true) {
    const std::vector<Observation> observations =
        rasp::plugins::run_plugins(rasp::plugins::compiled_in(), run_checks(config), context);
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
