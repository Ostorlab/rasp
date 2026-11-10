/// The JSON the reporting plugin posts: one GraphQL request per run of the checks, which runs the `submitObservations`
/// mutation with all the observations of the run.
///
/// A request is `{"query": kMutation, "variables": {"batch": <batch>}}`. The batch, an `ObservationBatchInput`, is an
/// object with `installId`, `sessionId`, `buildId` and `observations`. `installId` is the config's install id, or
/// kZeroUuid when it has none, and `sessionId` is kZeroUuid.
/// `observations` is a list of `ObservationInput` objects, with `signal`, `source`, `status` and `value`.
/// `status` is `OK`, `UNSUPPORTED`, `ERROR` or `TIMEOUT`. `value` is null, or an `ObservationValueInput`: an object
/// with one field, which names the value's type: `bool`, `long` (a 64-bit integer, written as a decimal string),
/// `string` or `strings`. The request is valid UTF-8: each byte of a string that doesn't start a valid UTF-8 sequence
/// is written as U+FFFD.

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "config.h"
#include "rasp/observation.h"

namespace rasp::plugins::reporting {

/// The GraphQL mutation every request runs, with the batch as its `$batch` variable.
inline constexpr std::string_view kMutation =
    "mutation SubmitObservations($batch: ObservationBatchInput!) { submitObservations(batch: $batch) }";

/// The nil UUID, all zeros, which every request sends as its session id, and as its install id when it has none.
inline constexpr std::string_view kZeroUuid = "00000000-0000-0000-0000-000000000000";

/// The largest request the plugin posts, in bytes.
inline constexpr std::size_t kMaxRequestSize = std::size_t{1024} * 1024;

/// The room a request keeps for everything other than the batch's `observations`, in bytes. The mutation, the two ids
/// and a build id fit in it many times over.
inline constexpr std::size_t kOtherFieldsRoom = 4096;

/// Writes the observations of a run as a JSON list, the `observations` of a request's batch.
///
/// An observation whose status is unknown is left out. The list is written to a new string and checked against
/// `limit` after every string it adds, so the string never grows much beyond the limit.
///
/// @param observations The observations of the run. They are only read during the call.
/// @param limit The largest list accepted, in bytes.
/// @return The list. Nothing when it would be larger than `limit`.
[[nodiscard]] std::optional<std::string> serialise_observations(std::span<const Observation> observations,
                                                                std::size_t limit);

/// Writes a GraphQL request around a list of observations.
///
/// @param config The plugin's config. Its build id and install id are written into the batch.
/// @param observations The list that serialise_observations wrote.
/// @param limit The largest request accepted, in bytes.
/// @return The request. Nothing when it would be larger than `limit`.
[[nodiscard]] std::optional<std::string> serialise_request(const Config& config, std::string_view observations,
                                                           std::size_t limit);

}  // namespace rasp::plugins::reporting
