/// ObservationBatch, a batch of observations the runtime sends to the ADR server, and the GraphQL submitObservations
/// request that sends it.

#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include "rasp/observation.h"
#include "rasp/util/uuid.h"

namespace rasp {

/// One batch of observations, as the ADR server receives it.
struct ObservationBatch {
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
  [[nodiscard]] friend bool operator==(const ObservationBatch& left, const ObservationBatch& right) = default;
};

/// Writes the JSON body of the GraphQL `submitObservations` request for one batch.
///
/// The body holds the mutation in `query` and the batch in `variables.batch`, with the field names of the contract's
/// `ObservationBatchInput`. `observedAtMs` is the batch's time in milliseconds since the Unix epoch, written as a
/// decimal string like the `long` values. The time is rounded down to the millisecond, toward the past: for a time
/// before 1970, 1.5 milliseconds before the epoch is sent as `-2`, not `-1`. Each status is written as `OK`,
/// `UNSUPPORTED`, `ERROR` or `TIMEOUT`. Each value is written in the contract's form: `{"bool": true}`, `{"long": "5"}`
/// (the number as a string), `{"string": "text"}`, `{"strings": ["a", "b"]}`, or `null` when there is no value. Every
/// string is written with json::append_string, so invalid UTF-8 is replaced and the body is always valid JSON.
///
/// @param batch The batch to send.
/// @return The request body, ready to pass to Transport::post.
[[nodiscard]] std::string submit_observations_request(const ObservationBatch& batch);

}  // namespace rasp
