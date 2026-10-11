/// submit_event_request: writes a batch as the GraphQL submitEvent request, in the form the ADR server's contract
/// defines.

#include "rasp/reporting/submit_event.h"

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "rasp/observation.h"
#include "rasp/reporting/event.h"
#include "rasp/util/json.h"
#include "rasp/util/uuid.h"

namespace rasp {

namespace {

/// The GraphQL mutation sent with every batch; it asks only for the type name, because nothing reads the answer.
constexpr std::string_view kQuery =
    "mutation SubmitEvent($event: EventInput!) { submitEvent(event: $event) { __typename } }";

/// The contract's name for `status`.
[[nodiscard]] constexpr std::string_view status_name(Status status) {
  switch (status) {
    case Status::kOk:
      return "OK";
    case Status::kUnsupported:
      return "UNSUPPORTED";
    case Status::kError:
      return "ERROR";
    case Status::kTimeout:
      return "TIMEOUT";
  }
  return "ERROR";
}

/// Appends a member name and the colon after it to `out`.
void append_member(std::string& out, std::string_view key) {
  json::append_string(out, key);
  out.push_back(':');
}

/// Appends an empty value as null.
void append_value(std::string& out, [[maybe_unused]] std::monostate empty) { out += "null"; }

/// Appends a boolean in the contract's form, `{"bool": true}`.
void append_value(std::string& out, bool value) { out += value ? R"({"bool":true})" : R"({"bool":false})"; }

/// Appends a 64-bit integer in the contract's form, `{"long": "5"}`, with the number written as a string.
void append_value(std::string& out, std::int64_t value) { out += R"({"long":")" + std::to_string(value) + R"("})"; }

/// Appends a string in the contract's form, `{"string": "text"}`.
void append_value(std::string& out, const std::string& value) {
  out += R"({"string":)";
  json::append_string(out, value);
  out.push_back('}');
}

/// Appends a list of strings in the contract's form, `{"strings": ["a", "b"]}`.
void append_value(std::string& out, const std::vector<std::string>& values) {
  out += R"({"strings":[)";
  std::string_view separator;
  for (const std::string& value : values) {
    out += separator;
    json::append_string(out, value);
    separator = ",";
  }
  out += "]}";
}

/// Appends one observation as the contract's ObservationInput.
void append_observation(std::string& out, const Observation& observation) {
  out.push_back('{');
  append_member(out, "signal");
  json::append_string(out, observation.signal);
  out.push_back(',');
  append_member(out, "source");
  json::append_string(out, observation.source);
  out.push_back(',');
  append_member(out, "status");
  json::append_string(out, status_name(observation.status));
  out.push_back(',');
  append_member(out, "value");
  std::visit([&out](const auto& value) { append_value(out, value); }, observation.value);
  out.push_back('}');
}

}  // namespace

std::string submit_event_request(const Event& event) {
  std::string out = "{";
  append_member(out, "query");
  json::append_string(out, kQuery);
  out += R"(,"variables":{"event":{)";
  append_member(out, "installId");
  json::append_string(out, to_string(event.install_id));
  out.push_back(',');
  append_member(out, "sessionId");
  json::append_string(out, to_string(event.session_id));
  out.push_back(',');
  append_member(out, "seq");
  out += std::to_string(event.seq);
  out.push_back(',');
  append_member(out, "observedAtMs");
  json::append_string(
      out, std::to_string(std::chrono::floor<std::chrono::milliseconds>(event.observed_at.time_since_epoch()).count()));
  out.push_back(',');
  append_member(out, "buildId");
  json::append_string(out, event.build_id);
  out.push_back(',');
  append_member(out, "observations");
  out.push_back('[');
  std::string_view separator;
  for (const Observation& observation : event.observations) {
    out += separator;
    append_observation(out, observation);
    separator = ",";
  }
  out += "]}}}";
  return out;
}

}  // namespace rasp
