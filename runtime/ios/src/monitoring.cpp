/// start_monitoring: the runtime's own thread on iOS, which runs the checks and the plugins.

#include "monitoring.h"

#include <CoreFoundation/CFBase.h>
#include <CoreFoundation/CFNumber.h>
#include <CoreFoundation/CFString.h>
#include <CoreFoundation/CFURL.h>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <memory>
#include <pthread.h>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <thread>
#include <utility>
#include <vector>

#include "builtin.h"
#include "checks/hooks.h"
#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/embedded_config.h"
#include "rasp/install_id.h"
#include "rasp/observation.h"
#include "rasp/plugins/registry.h"
#include "rasp/util/logging.h"

namespace rasp::ios {

namespace {

/// How long the thread waits between two runs of the checks.
constexpr std::chrono::seconds kCheckInterval{60};

/// The folder of the app's sandbox that keeps the install id, under its home folder: Library/Application Support,
/// which iOS never deletes to free space, unlike Library/Caches. The id's file is excluded from backups, so an id
/// restored from a backup is never shared by two devices.
constexpr std::string_view kInstallIdDirectory = "/Library/Application Support";

/// The permissions of the folder that keeps the install id, when the runtime creates it: only the app can read, write
/// and enter it.
constexpr mode_t kPrivateDirectoryMode = 0700;

/// What the thread reads from the app's environment, once, while the runtime loads.
struct Environment {
  /// The value of `DYLD_INSERT_LIBRARIES`.
  std::string inserted_libraries;
  /// The folder that keeps the install id, or empty when the app has no `HOME`.
  std::string install_id_directory;
};

/// Reads the folder that keeps the install id from `HOME`, the app's sandbox. Like read_inserted_libraries, it must
/// only be called while the runtime loads, on the app's main thread.
///
/// @return The folder, or an empty string when `HOME` is unset.
[[nodiscard]] std::string read_install_id_directory() {
  // NOLINTNEXTLINE(concurrency-mt-unsafe)
  const char* const home = std::getenv("HOME");
  return home == nullptr ? std::string() : std::string(home).append(kInstallIdDirectory);
}

/// Marks the file at `path` as excluded from the device's backups, so a backup restored on another device doesn't
/// carry it.
///
/// @param path The file.
/// @return `true` when the file is marked.
[[nodiscard]] bool exclude_from_backup(const std::string& path) {
  const CFStringRef text = CFStringCreateWithCString(kCFAllocatorDefault, path.c_str(), kCFStringEncodingUTF8);
  if (text == nullptr) {
    return false;
  }
  const CFURLRef url = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, text, kCFURLPOSIXPathStyle, 0);
  CFRelease(text);
  if (url == nullptr) {
    return false;
  }
  const bool excluded =
      CFURLSetResourcePropertyForKey(url, kCFURLIsExcludedFromBackupKey, kCFBooleanTrue, nullptr) != 0;
  CFRelease(url);
  return excluded;
}

/// The runtime's config, with the install id kept in `directory`, which is created when it doesn't exist yet. The id's
/// file is marked as excluded from backups on every launch.
///
/// @param directory The folder that keeps the install id, or empty when there is none.
/// @return The config the packer wrote, with its install id, which stays `std::nullopt` when it can't be read or kept.
[[nodiscard]] Config read_config(const std::string& directory) {
  Config config = read_embedded_config();
  if (directory.empty() || (mkdir(directory.c_str(), kPrivateDirectoryMode) != 0 && errno != EEXIST)) {
    return config;
  }
  config.install_id = load_or_create_install_id(directory);
  if (config.install_id.has_value() && !exclude_from_backup(directory + "/" + std::string(kInstallIdFileName))) {
    if constexpr (kLoggingEnabled) {
      rasp::log("install id: its file could not be excluded from backups");
    }
  }
  return config;
}

/// The thread: reads the runtime's config and initialises the plugins with it, then runs the jailbreak, debugger,
/// hooking, app-identity, emulator, virtualizer and network-interception checks, each only when the config enables its
/// group, and the plugins, then again every kCheckInterval, until the process exits. The config and the context the
/// plugins share are locals of this thread, which never returns, so they live as long as the process.
///
/// @param argument What the runtime read from the app's environment when it loaded, an Environment allocated with
/// `new` that the thread takes and keeps until the process exits.
/// @return Never returns.
void* monitor(void* argument) {
  const std::unique_ptr<const Environment> environment(static_cast<Environment*>(argument));
  const Config config = read_config(environment->install_id_directory);
  rasp::plugins::Context context;
  rasp::plugins::init_plugins(rasp::plugins::compiled_in(), config, context);
  while (true) {
    const std::vector<Observation> observations = rasp::plugins::run_plugins(
        rasp::plugins::compiled_in(), run_checks(config, environment->inserted_libraries), context);
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
  auto environment = std::make_unique<Environment>(Environment{
      .inserted_libraries = checks::read_inserted_libraries(),
      .install_id_directory = read_install_id_directory(),
  });
  pthread_attr_t attributes{};
  if (pthread_attr_init(&attributes) != 0) {
    return;
  }
  if (pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED) == 0) {
    pthread_t thread{};
    if (pthread_create(&thread, &attributes, monitor, environment.get()) == 0) {
      static_cast<void>(environment.release());
    }
  }
  static_cast<void>(pthread_attr_destroy(&attributes));
}

}  // namespace rasp::ios
