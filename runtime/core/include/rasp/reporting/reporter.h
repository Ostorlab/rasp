/// Reporter, which sends the batches of one session to the ADR server, each one at most once, in order, and SessionIds,
/// the ids every batch of the session carries.

#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "rasp/observation.h"
#include "rasp/reporting/submit_observations.h"
#include "rasp/reporting/transport.h"
#include "rasp/util/uuid.h"

namespace rasp {

/// The ids every batch of a session carries. Grouped so that a caller names each one, and can't swap them by mistake.
struct SessionIds {
  /// The id of this installation of the app on the device, a random version 4 UUID.
  Uuid install_id;
  /// The id of this run of the app, a new random version 4 UUID made with random_uuid each time the runtime starts.
  Uuid session_id;
};

/// Sends the batches of one session to the ADR server, in order.
///
/// report sends, at once, only the observations that changed since the last ones reported, as the next batch of the
/// session. Each batch gets the next `seq` of the session and is sent once: whatever happens to its request, it is
/// never sent again, so a batch that doesn't reach the server is lost. Not thread-safe: one thread reports.
class Reporter {
 public:
  /// Gives the current time. Tests replace it with a fixed time.
  using Clock = std::function<std::chrono::system_clock::time_point()>;

  /// Starts a session. Every batch of the session carries the same build id, install id and session id.
  ///
  /// @param build_id The id the packer gave the protected build that produces the batches.
  /// @param ids The install id and session id of the session.
  /// @param transport Sends the requests to the ADR server. The reporter keeps a reference to it, so it must live
  /// longer than the reporter.
  /// @param clock Gives the time stamped on each batch when it is made. By default, the system clock.
  Reporter(std::string build_id, SessionIds ids, Transport& transport, Clock clock = std::chrono::system_clock::now);

  /// Sends the observations that changed since the last ones reported, at once, as the next batch of the session.
  ///
  /// An observation is identified by its signal and its source. It has changed when no observation with the same
  /// signal and source was reported before, or when the last one reported has a different status or value. An
  /// observation that a later run no longer reports is not a change: nothing is sent for it. Within one call, an
  /// observation is also compared with the earlier ones of the same call, so a repeated observation is sent only once.
  ///
  /// The changed observations are sent as one batch with Transport::post, on the calling thread, before this returns.
  /// The batch gets the next `seq` of the session and the current time from the clock. When nothing changed, nothing
  /// is sent and no `seq` is used. The changed observations count as reported even when their batch doesn't reach the
  /// server, so the server doesn't learn of those changes until the observations change again.
  ///
  /// `seq` is a 32-bit number, as in the contract, so a session has at most `std::numeric_limits<std::int32_t>::max()`
  /// batches. Once that many have been sent, every later batch is dropped instead: it is never sent.
  ///
  /// @param observations What the checks observed in one run.
  void report(std::vector<Observation> observations);

  /// Gives the id of the session this reporter sends.
  ///
  /// @return The session id given to the constructor. The reference is valid as long as the reporter lives.
  [[nodiscard]] const Uuid& session_id() const { return ids_.session_id; }

 private:
  /// The build id every batch carries.
  std::string build_id_;
  /// The install id and session id every batch carries.
  SessionIds ids_;
  /// Sends the requests to the ADR server.
  std::reference_wrapper<Transport> transport_;
  /// Gives the time stamped on each batch.
  Clock clock_;
  /// The seq the next batch gets. It is 64 bits wide so that it can go one past the largest 32-bit seq without
  /// overflowing, which marks the session as having used every seq.
  std::int64_t next_seq_ = 1;
  /// The last observation reported for each signal and source.
  std::vector<Observation> reported_;
};

}  // namespace rasp
