/// start_monitoring: the runtime's own thread on iOS, which runs the checks and reports what changed.

#include "monitoring.h"

#include <CoreFoundation/CoreFoundation.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <pthread.h>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "checks/jailbreak.h"
#include "rasp/observation.h"
#include "rasp/reporting/reporter.h"
#include "rasp/reporting/server.h"
#include "rasp/util/logging.h"
#include "rasp/util/uuid.h"
#include "reporting/install_id.h"
#include "reporting/network_transport.h"

namespace rasp::ios {

namespace {

/// The stack size of the thread, a whole number of pages.
constexpr std::size_t kThreadStackSize = std::size_t{256} * 1024;

/// How long the thread waits between two runs of the checks.
constexpr std::chrono::seconds kCheckInterval{60};

/// The longest one post to the server may take.
constexpr std::chrono::milliseconds kPostTimeout{10'000};

/// The most bytes the build id may take as UTF-8, with its final NUL.
constexpr std::size_t kMaxBuildIdBytes = 256;

/// The most bytes the path of the app's home directory may take, with its final NUL: PATH_MAX on iOS.
constexpr std::size_t kMaxPathBytes = 1024;

/// Reads the build id the packer wrote into the framework's Info.plist, or nothing when there's none.
[[nodiscard]] std::optional<std::string> read_build_id() {
  CFBundleRef bundle = CFBundleGetBundleWithIdentifier(CFSTR(RASP_FRAMEWORK_IDENTIFIER));
  if (bundle == nullptr) {
    return std::nullopt;
  }
  CFTypeRef value = CFBundleGetValueForInfoDictionaryKey(bundle, CFSTR("RaspBuildId"));
  if (value == nullptr || CFGetTypeID(value) != CFStringGetTypeID()) {
    return std::nullopt;
  }
  std::array<char, kMaxBuildIdBytes> buffer{};
  if (CFStringGetCString(static_cast<CFStringRef>(value), buffer.data(), static_cast<CFIndex>(buffer.size()),
                         kCFStringEncodingUTF8) == 0) {
    return std::nullopt;
  }
  std::string build_id(buffer.data());
  if (build_id.empty()) {
    return std::nullopt;
  }
  return build_id;
}

/// Gives the path of the app's home directory, or nothing when the system can't give it.
[[nodiscard]] std::optional<std::string> home_directory() {
  CFURLRef url = CFCopyHomeDirectoryURL();
  if (url == nullptr) {
    return std::nullopt;
  }
  std::array<std::uint8_t, kMaxPathBytes> buffer{};
  const bool converted = CFURLGetFileSystemRepresentation(url, static_cast<Boolean>(true), buffer.data(),
                                                          static_cast<CFIndex>(buffer.size())) != 0;
  CFRelease(url);
  if (!converted) {
    return std::nullopt;
  }
  return std::string(buffer.begin(), std::ranges::find(buffer, std::uint8_t{0}));
}

/// Gives the install id, kept in the app's Library/Application Support, or a temporary one without a home directory.
[[nodiscard]] Uuid install_id() {
  const std::optional<std::string> home = home_directory();
  if (!home.has_value()) {
    return random_uuid();
  }
  return load_install_id(*home + "/Library/Application Support");
}

/// The thread: runs the checks and reports what changed, then again every kCheckInterval, until the process exits.
void* monitor(void* /*argument*/) {
  const std::optional<std::string> build_id = read_build_id();
  if (!build_id.has_value()) {
    if constexpr (kLoggingEnabled) {
      rasp::log("monitoring: the framework has no build id");
    }
    return nullptr;
  }
  NetworkTransport transport{std::string(kServerHost), std::string(kServerPath), kPostTimeout};
  Reporter reporter{*build_id, SessionIds{.install_id = install_id(), .session_id = random_uuid()}, transport};
  while (true) {
    std::vector<Observation> observations = checks::jailbreak();
    if constexpr (kLoggingEnabled) {
      for (const Observation& observation : observations) {
        rasp::log(describe(observation));
      }
    }
    reporter.report(std::move(observations));
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
