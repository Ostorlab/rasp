/// Event, the batch of observations the runtime sends to the ADR server.

#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include "rasp/observation.h"
#include "rasp/util/uuid.h"

namespace rasp {

/// One batch of observations, as the ADR server receives it.
struct Event {
  /// The id of this installation of the app on the device, a random version 4 UUID made on the device.
  Uuid install_id;
  /// The id of this run of the app, a random version 4 UUID. The runtime makes a new one each time it starts.
  Uuid session_id;
  /// The number of this batch in its session: 1 for the first batch, then 2, 3 and so on.
  std::int32_t seq = 0;
  /// When the batch was made.
  std::chrono::system_clock::time_point observed_at;
  /// The id the packer gave the protected build that produced the batch. The ADR server finds the app from it.
  std::string build_id;
  /// What the checks observed.
  std::vector<Observation> observations;

  /// Compares two batches field by field.
  ///
  /// @param left The first batch.
  /// @param right The second batch.
  /// @return `true` when every field of both is equal, including every observation, in the same order.
  [[nodiscard]] friend bool operator==(const Event& left, const Event& right) = default;
};

}  // namespace rasp
