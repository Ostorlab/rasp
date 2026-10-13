/// Reporter: sends the observations of a session that changed, each batch once, in order.

#include "rasp/reporting/reporter.h"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include "rasp/observation.h"
#include "rasp/reporting/submit_observations.h"
#include "rasp/reporting/transport.h"

namespace rasp {

Reporter::Reporter(std::string build_id, SessionIds ids, Transport& transport, Clock clock)
    : build_id_(std::move(build_id)), ids_(ids), transport_(transport), clock_(std::move(clock)) {}

void Reporter::report(std::vector<Observation> observations) {
  std::vector<Observation> changed;
  for (Observation& observation : observations) {
    const auto last = std::ranges::find_if(reported_, [&observation](const Observation& reported) {
      return reported.signal == observation.signal && reported.source == observation.source;
    });
    if (last == reported_.end()) {
      reported_.push_back(observation);
    } else if (*last != observation) {
      *last = observation;
    } else {
      continue;
    }
    changed.push_back(std::move(observation));
  }
  if (changed.empty() || next_seq_ > std::numeric_limits<std::int32_t>::max()) {
    return;
  }
  const ObservationBatch batch{
      .install_id = ids_.install_id,
      .session_id = ids_.session_id,
      .seq = static_cast<std::int32_t>(next_seq_),
      .observed_at = clock_(),
      .build_id = build_id_,
      .observations = std::move(changed),
  };
  ++next_seq_;
  transport_.get().post(submit_observations_request(batch));
}

}  // namespace rasp
