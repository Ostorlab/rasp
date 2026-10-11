/// Reporter, which sends the batches of one session to the ADR server, each one at most once, in order, and SessionIds,
/// the ids every batch of the session carries.

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <string>
#include <vector>

#include "rasp/observation.h"
#include "rasp/reporting/event.h"
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
/// Each batch gets the next `seq` of the session when it is added, and is sent at most once. A batch dropped from a
/// full queue is never sent. Whatever happens to the request of a batch that is sent, the batch is never sent again,
/// so a batch that doesn't reach the server is lost. Not thread-safe: one thread adds and sends.
class Reporter {
 public:
  /// Gives the current time. Tests replace it with a fixed time.
  using Clock = std::function<std::chrono::system_clock::time_point()>;

  /// The most batches that can wait to be sent. Past that, the oldest one is dropped.
  static constexpr std::size_t kMaxPendingBatches = 64;

  /// Starts a session. Every batch of the session carries the same build id, install id and session id.
  ///
  /// @param build_id The id the packer gave the protected build that produces the batches.
  /// @param ids The install id and session id of the session.
  /// @param transport Sends the requests to the ADR server. The reporter keeps a reference to it, so it must live
  /// longer than the reporter.
  /// @param clock Gives the time stamped on each batch when it is added. By default, the system clock.
  Reporter(std::string build_id, SessionIds ids, Transport& transport, Clock clock = std::chrono::system_clock::now);

  /// Queues observations as the next batch of the session. Nothing is sent until send is called.
  ///
  /// The batch gets the next `seq` of the session, and the current time from the clock. When kMaxPendingBatches
  /// batches are already waiting, the oldest one is dropped first, without being sent.
  ///
  /// `seq` is a 32-bit number, as in the contract, so a session has at most `std::numeric_limits<std::int32_t>::max()`
  /// batches. Once that many have been added, every later batch is dropped instead of being queued: it is never sent,
  /// and the queue is left as it is.
  ///
  /// @param observations What the checks observed. It may be empty.
  void add(std::vector<Observation> observations);

  /// Sends every queued batch to the ADR server, oldest first, one request per batch, and empties the queue.
  ///
  /// It calls Transport::post on the calling thread, once for each batch. Each batch is sent only this once: whether
  /// the request reaches the server or not, the batch is removed from the queue and never sent again.
  void send();

  /// Counts the batches waiting to be sent.
  ///
  /// @return The number of queued batches, at most kMaxPendingBatches.
  [[nodiscard]] std::size_t pending() const { return queue_.size(); }

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
  /// The seq the next added batch gets. It is 64 bits wide so that it can go one past the largest 32-bit seq without
  /// overflowing, which marks the session as having used every seq.
  std::int64_t next_seq_ = 1;
  /// The batches waiting to be sent, oldest first.
  std::deque<Event> queue_;
};

}  // namespace rasp
