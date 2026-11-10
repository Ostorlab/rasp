/// deliver and start_sender: the reporting plugin's sender thread.

#include "sender.h"

#include <cstddef>
#include <optional>
#include <pthread.h>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "config.h"
#include "json.h"
#include "rasp/observation.h"
#include "rasp/util/logging.h"
#include "reporting/undelivered_run.h"

namespace rasp::plugins::reporting {

namespace {

/// The largest list of observations a request may hold: the largest request, less the room of its other fields.
constexpr std::size_t kMaxObservationsSize = kMaxRequestSize - kOtherFieldsRoom;

/// Writes the request that posts a run.
///
/// @param config The plugin's config.
/// @param run All the observations of the run.
/// @return The request. Nothing when it would be larger than kMaxRequestSize.
[[nodiscard]] std::optional<std::string> serialise_run(const Config& config, std::span<const Observation> run) {
  const std::optional<std::string> observations = serialise_observations(run, kMaxObservationsSize);
  if (!observations.has_value()) {
    return std::nullopt;
  }
  return serialise_request(config, *observations, kMaxRequestSize);
}

/// The thread: takes each run from the mailbox and delivers it, until the process exits.
///
/// @param argument The Sender.
/// @return Never returns.
void* send_runs(void* argument) {
  auto* const sender = static_cast<Sender*>(argument);
  while (true) {
    deliver(*sender, sender->mailbox.take());
  }
}

}  // namespace

void deliver(const Sender& sender, std::vector<Observation> run) {
  const std::optional<std::string> request = serialise_run(sender.config, run);
  if (request.has_value() && sender.post(sender.config, *request)) {
    if constexpr (kLoggingEnabled) {
      rasp::log("reporting: posted a request of " + std::to_string(request->size()) + " bytes to " +
                sender.config.endpoint);
    }
    return;
  }
  if constexpr (kLoggingEnabled) {
    if (!request.has_value()) {
      rasp::log("reporting: the request would be larger than the limit");
    }
    rasp::log("reporting: the run's " + std::to_string(run.size()) + " observations are left in the context");
  }
  sender.context->put(kUndeliveredRun, std::move(run));
}

bool start_sender(Sender& sender) {
  pthread_attr_t attributes{};
  if (pthread_attr_init(&attributes) != 0) {
    return false;
  }
  bool started = false;
  if (pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED) == 0) {
    pthread_t thread{};
    started = pthread_create(&thread, &attributes, send_runs, &sender) == 0;
  }
  static_cast<void>(pthread_attr_destroy(&attributes));
  return started;
}

}  // namespace rasp::plugins::reporting
