/// kPlugin, the reporting plugin: it has no checks. Its init starts the plugin's sender, with the build id and install
/// id the runtime gives it, and its on_observations hands all the observations of each run to the sender, which posts
/// them from its own thread. Each run it does not deliver is left in the context the plugins share, under
/// kUndeliveredRun.
///
/// It supports Android and iOS. The build of the runtime compiles in the endpoint, with
/// `-DRASP_REPORTING_ENDPOINT=https://reports.example.com/rasp`. The posts carry no authorization.

#include <new>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/observation.h"
#include "rasp/plugin.h"
#include "rasp/util/logging.h"
#include "reporting/undelivered_run.h"
#include "sender.h"
#include "transport.h"

namespace rasp::plugins::reporting {

namespace {

/// The sender, which the plugin's init starts.
///
/// @return The sender, which lives as long as the process once it has started. Null before init, or when init could not
/// start it.
[[nodiscard]] Sender*& started_sender() {
  static Sender* value = nullptr;
  return value;
}

/// The plugin's init: builds the sender, with the endpoint the build compiled in, the build id and install id the
/// runtime gives and the context the plugins share, and starts its thread. When the sender can't be allocated or its
/// thread doesn't start, the plugin has no sender.
///
/// @param runtime_config The runtime's config.
/// @param context The context the plugins share, where the sender leaves each run it does not deliver.
void start(const rasp::Config& runtime_config, Context& context) {
  // NOLINTNEXTLINE(cppcoreguidelines-owning-memory): the sender's thread uses it until the process exits.
  auto* const started = new (std::nothrow) Sender{
      .config =
          {
              .endpoint = RASP_REPORTING_ENDPOINT,
              .build_id = runtime_config.build_id,
              .install_id = runtime_config.install_id,
          },
      .post = post,
      .context = &context,
      .mailbox = {},
  };
  if (started == nullptr) {
    return;
  }
  if (!start_sender(*started)) {
    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory): the thread did not start, so nothing else uses the sender.
    delete started;
    return;
  }
  started_sender() = started;
}

/// The plugin's on_observations: copies all the observations of the run into the sender's mailbox, replacing the run
/// the sender hasn't taken yet. It never waits for the network. When init could not start the sender, it leaves the run
/// in the context under kUndeliveredRun instead.
///
/// @param observations All the observations of the run.
/// @param context The context the plugins share.
void report(std::span<const Observation> observations, Context& context) {
  std::vector<Observation> run(observations.begin(), observations.end());
  Sender* const sender = started_sender();
  if (sender == nullptr) {
    if constexpr (kLoggingEnabled) {
      rasp::log("reporting: the sender did not start, the run's " + std::to_string(run.size()) +
                " observations are left in the context");
    }
    context.put(kUndeliveredRun, std::move(run));
    return;
  }
  sender->mailbox.put(std::move(run));
}

}  // namespace

/// The reporting plugin.
extern constexpr Plugin kPlugin{.init = start, .checks = {}, .on_observations = report};

}  // namespace rasp::plugins::reporting
