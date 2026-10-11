/// The GraphQL submitEvent request that sends a batch to the ADR server.

#pragma once

#include <string>

#include "rasp/reporting/event.h"

namespace rasp {

/// Writes the JSON body of the GraphQL `submitEvent` request for one batch.
///
/// The body holds the mutation in `query` and the batch in `variables.event`, with the field names of the contract's
/// `EventInput`. `observedAtMs` is the batch's time in milliseconds since the Unix epoch, written as a decimal string
/// like the `long` values. The time is rounded down to the millisecond, toward the past: for a time before 1970, 1.5
/// milliseconds before the epoch is sent as `-2`, not `-1`. Each status is written as `OK`, `UNSUPPORTED`, `ERROR` or
/// `TIMEOUT`. Each value is written in the contract's form: `{"bool": true}`, `{"long": "5"}` (the number as a
/// string), `{"string": "text"}`, `{"strings": ["a", "b"]}`, or `null` when there is no value. Every string is written
/// with json::append_string, so invalid UTF-8 is replaced and the body is always valid JSON.
///
/// @param event The batch to send.
/// @return The request body, ready to pass to Transport::post.
[[nodiscard]] std::string submit_event_request(const Event& event);

}  // namespace rasp
