/// The reporting plugin's sender: its own thread, which posts the newest run's request, so the runtime's thread never
/// waits for the network, and leaves each run it does not deliver in the context the plugins share.

#pragma once

#include <string_view>
#include <vector>

#include "config.h"
#include "mailbox.h"
#include "rasp/context.h"
#include "rasp/observation.h"

namespace rasp::plugins::reporting {

/// A function that posts one request, with the shape of the platform's `post`.
///
/// @param config The plugin's config. Only its endpoint is read.
/// @param body The request.
/// @return `true` when the endpoint accepted it.
using PostFunction = bool (*)(const Config& config, std::string_view body) noexcept;

/// Everything the sender's thread needs. It lives as long as the process once the thread has started.
struct Sender {
  /// Where the requests are posted, and the fields every request holds.
  Config config;
  /// The function that posts a request: the platform's `post`.
  PostFunction post = nullptr;
  /// The context the plugins share, where each run that is not delivered is left under kUndeliveredRun. It must be set
  /// before the sender delivers a run.
  Context* context = nullptr;
  /// The run waiting to be posted.
  Mailbox mailbox;
};

/// Delivers one run: serialises its observations into a request, and posts the request once.
///
/// It blocks until the post ends. When the request would be larger than kMaxRequestSize, nothing is posted. When
/// nothing is posted or the post fails, the run is left in the sender's context under kUndeliveredRun, in place of the
/// run left there before. A run is never posted again. In a development build it logs the outcome.
///
/// @param sender The sender.
/// @param run All the observations of the run.
void deliver(const Sender& sender, std::vector<Observation> run);

/// Starts the sender's thread: a detached thread that takes each run from the mailbox and delivers it, until the
/// process exits.
///
/// @param sender The sender. It must live as long as the process, and is used by the thread from now on.
/// @return Whether the thread started.
[[nodiscard]] bool start_sender(Sender& sender);

}  // namespace rasp::plugins::reporting
