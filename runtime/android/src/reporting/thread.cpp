/// start_reporting: the runtime's reporting thread on Android.

#include "reporting/thread.h"

#include <chrono>
#include <cstddef>
#include <memory>
#include <pthread.h>
#include <string>
#include <utility>
#include <vector>

#include "rasp/observation.h"
#include "rasp/reporting/install_id.h"
#include "rasp/reporting/reporter.h"
#include "rasp/reporting/server.h"
#include "rasp/util/logging.h"
#include "rasp/util/uuid.h"
#include "reporting/tls_transport.h"

namespace rasp::android {

namespace {

/// The stack size of the reporting thread, a whole number of pages.
constexpr std::size_t kThreadStackSize = std::size_t{256} * 1024;

/// The longest one post to the server may take.
constexpr std::chrono::milliseconds kPostTimeout{10'000};

/// What the reporting thread needs, handed over to it by start_reporting.
struct Work {
  /// The id the packer gave the protected build.
  std::string build_id;
  /// The directory that keeps the install id, empty for an install id of this launch only.
  std::string directory;
  /// What the checks observed at launch.
  std::vector<Observation> observations;
};

/// Gives the install id kept in `directory`, or a new random one for this launch only when `directory` is empty.
[[nodiscard]] Uuid install_id(const std::string& directory) {
  if (directory.empty()) {
    return random_uuid();
  }
  return load_install_id(directory);
}

/// Sends the observations of `work` as the session's first batch.
void send_observations(Work& work) {
  TlsTransport transport{std::string(kServerHost), std::string(kServerPath), kPostTimeout};
  Reporter reporter{std::move(work.build_id),
                    SessionIds{.install_id = install_id(work.directory), .session_id = random_uuid()}, transport};
  reporter.add(std::move(work.observations));
  reporter.send();
}

/// The reporting thread: sends the observations of the Work it owns, and ends.
void* report(void* argument) {
  const std::unique_ptr<Work> work{static_cast<Work*>(argument)};
  send_observations(*work);
  return nullptr;
}

}  // namespace

void start_reporting(std::string build_id, std::string directory, std::vector<Observation> observations) noexcept {
  if (build_id.empty()) {
    if constexpr (kLoggingEnabled) {
      rasp::log("reporting: the app has no build id");
    }
    return;
  }
  auto owned = std::make_unique<Work>(Work{
      .build_id = std::move(build_id),
      .directory = std::move(directory),
      .observations = std::move(observations),
  });
  pthread_attr_t attributes{};
  if (pthread_attr_init(&attributes) != 0) {
    return;
  }
  pthread_t thread{};
  const bool started = pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED) == 0 &&
                       pthread_attr_setstacksize(&attributes, kThreadStackSize) == 0 &&
                       pthread_create(&thread, &attributes, report, owned.get()) == 0;
  static_cast<void>(pthread_attr_destroy(&attributes));
  if (started) {
    static_cast<void>(owned.release());
  }
}

}  // namespace rasp::android
