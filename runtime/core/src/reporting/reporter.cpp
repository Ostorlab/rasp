/// Reporter: queues the batches of a session and sends each one at most once, in order.

#include "rasp/reporting/reporter.h"

#include <cstdint>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include "rasp/observation.h"
#include "rasp/reporting/event.h"
#include "rasp/reporting/submit_event.h"
#include "rasp/reporting/transport.h"

namespace rasp {

Reporter::Reporter(std::string build_id, SessionIds ids, Transport& transport, Clock clock)
    : build_id_(std::move(build_id)), ids_(ids), transport_(transport), clock_(std::move(clock)) {}

void Reporter::add(std::vector<Observation> observations) {
  if (next_seq_ > std::numeric_limits<std::int32_t>::max()) {
    return;
  }
  if (queue_.size() >= kMaxPendingBatches) {
    queue_.pop_front();
  }
  queue_.push_back(Event{
      .install_id = ids_.install_id,
      .session_id = ids_.session_id,
      .seq = static_cast<std::int32_t>(next_seq_),
      .observed_at = clock_(),
      .build_id = build_id_,
      .observations = std::move(observations),
  });
  ++next_seq_;
}

void Reporter::send() {
  while (!queue_.empty()) {
    transport_.get().post(submit_event_request(queue_.front()));
    queue_.pop_front();
  }
}

}  // namespace rasp
