/// Tests for the submitEvent request writer.

#include "rasp/reporting/submit_event.h"

#include <chrono>
#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "rasp/observation.h"
#include "rasp/reporting/event.h"
#include "rasp/util/uuid.h"

namespace rasp {
namespace {

/// The install id of the sample event, 0f8c2e1a-7b3d-4c5e-9a1b-2c3d4e5f6a7b.
constexpr Uuid kInstallId{
    .bytes = {0x0f, 0x8c, 0x2e, 0x1a, 0x7b, 0x3d, 0x4c, 0x5e, 0x9a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x6a, 0x7b},
};

/// The session id of the sample event, 3d6a9b7e-2c41-4f08-8e5d-1b7c9a2f4e63.
constexpr Uuid kSessionId{
    .bytes = {0x3d, 0x6a, 0x9b, 0x7e, 0x2c, 0x41, 0x4f, 0x08, 0x8e, 0x5d, 0x1b, 0x7c, 0x9a, 0x2f, 0x4e, 0x63},
};

/// An event with one observation of each value type.
[[nodiscard]] Event sample_event() {
  return Event{
      .install_id = kInstallId,
      .session_id = kSessionId,
      .seq = 3,
      .observed_at = std::chrono::system_clock::time_point{std::chrono::milliseconds{1791381801512}},
      .build_id = "build-1",
      .observations =
          {
              {.signal = "jb.fork_ok", .source = "fork", .status = Status::kOk, .value = true},
              {.signal = "dbg.tracer_pid", .source = "sysctl", .status = Status::kOk, .value = std::int64_t{0}},
              {
                  .signal = "integ.size",
                  .source = "stat",
                  .status = Status::kOk,
                  .value = std::int64_t{1'099'511'627'776},
              },
              {
                  .signal = "id.bundle_id",
                  .source = "plist",
                  .status = Status::kOk,
                  .value = std::string("co.ostorlab.demo"),
              },
              {
                  .signal = "jb.fs_paths",
                  .source = "stat",
                  .status = Status::kOk,
                  .value = std::vector<std::string>{"/var/jb"},
              },
              {.signal = "jb.sandbox_escape", .source = "open", .status = Status::kUnsupported, .value = {}},
          },
  };
}

/// An event like the sample one, with only `observations`.
[[nodiscard]] Event event_with(std::vector<Observation> observations) {
  Event event = sample_event();
  event.observations = std::move(observations);
  return event;
}

/// The exact request body for an event with the sample ids and seq, around the JSON text of its other fields.
[[nodiscard]] std::string body(std::string_view observed_at_ms, std::string_view build_id,
                               std::string_view observations) {
  std::string out =
      R"({"query":"mutation SubmitEvent($event: EventInput!) { submitEvent(event: $event) { __typename } }",)"
      R"("variables":{"event":{"installId":"0f8c2e1a-7b3d-4c5e-9a1b-2c3d4e5f6a7b",)"
      R"("sessionId":"3d6a9b7e-2c41-4f08-8e5d-1b7c9a2f4e63","seq":3,"observedAtMs":")";
  out += observed_at_ms;
  out += R"(","buildId":")";
  out += build_id;
  out += R"(","observations":[)";
  out += observations;
  out += "]}}}";
  return out;
}

/// The exact request body for event_with, with the sample time and build id.
[[nodiscard]] std::string body_with(std::string_view observations) {
  return body("1791381801512", "build-1", observations);
}

TEST(SubmitEvent, submitEventRequest_whenGivenAnEvent_encodesItAsTheContractDefinesIt) {
  const std::string expected =
      R"({"query":"mutation SubmitEvent($event: EventInput!) { submitEvent(event: $event) { __typename } }",)"
      R"("variables":{"event":{"installId":"0f8c2e1a-7b3d-4c5e-9a1b-2c3d4e5f6a7b",)"
      R"("sessionId":"3d6a9b7e-2c41-4f08-8e5d-1b7c9a2f4e63","seq":3,)"
      R"("observedAtMs":"1791381801512","buildId":"build-1",)"
      R"("observations":[)"
      R"({"signal":"jb.fork_ok","source":"fork","status":"OK","value":{"bool":true}},)"
      R"({"signal":"dbg.tracer_pid","source":"sysctl","status":"OK","value":{"long":"0"}},)"
      R"({"signal":"integ.size","source":"stat","status":"OK","value":{"long":"1099511627776"}},)"
      R"({"signal":"id.bundle_id","source":"plist","status":"OK","value":{"string":"co.ostorlab.demo"}},)"
      R"({"signal":"jb.fs_paths","source":"stat","status":"OK","value":{"strings":["/var/jb"]}},)"
      R"({"signal":"jb.sandbox_escape","source":"open","status":"UNSUPPORTED","value":null}]}}})";

  EXPECT_EQ(submit_event_request(sample_event()), expected);
}

TEST(SubmitEvent, submitEventRequest_whenTheTimeHasFinerDigits_sendsWholeMilliseconds) {
  Event event = sample_event();
  event.observed_at += std::chrono::microseconds{999};

  EXPECT_NE(submit_event_request(event).find(R"("observedAtMs":"1791381801512")"), std::string::npos);
}

TEST(SubmitEvent, submitEventRequest_whenTheStatusIsErrorOrTimeout_writesTheContractNames) {
  const Event event = event_with({
      {.signal = "jb.fork_ok", .source = "fork", .status = Status::kError, .value = {}},
      {.signal = "jb.fs_paths", .source = "stat", .status = Status::kTimeout, .value = {}},
  });

  EXPECT_EQ(submit_event_request(event),
            body_with(R"({"signal":"jb.fork_ok","source":"fork","status":"ERROR","value":null},)"
                      R"({"signal":"jb.fs_paths","source":"stat","status":"TIMEOUT","value":null})"));
}

TEST(SubmitEvent, submitEventRequest_whenTheValueIsFalse_writesFalse) {
  const Event event = event_with({{.signal = "jb.fork_ok", .source = "fork", .status = Status::kOk, .value = false}});

  EXPECT_EQ(submit_event_request(event),
            body_with(R"({"signal":"jb.fork_ok","source":"fork","status":"OK","value":{"bool":false}})"));
}

TEST(SubmitEvent, submitEventRequest_whenTheValueIsAListOfSeveralStrings_separatesThemWithCommas) {
  const Event event = event_with({
      {
          .signal = "jb.fs_paths",
          .source = "stat",
          .status = Status::kOk,
          .value = std::vector<std::string>{"/bin/sh", "/var/jb", "/Applications/Cydia.app"},
      },
  });

  EXPECT_EQ(submit_event_request(event),
            body_with(R"({"signal":"jb.fs_paths","source":"stat","status":"OK",)"
                      R"("value":{"strings":["/bin/sh","/var/jb","/Applications/Cydia.app"]}})"));
}

TEST(SubmitEvent, submitEventRequest_whenTheLongIsNegative_writesItWithAMinusSign) {
  const Event event = event_with({
      {.signal = "dbg.tracer_pid", .source = "sysctl", .status = Status::kOk, .value = std::int64_t{-1}},
  });

  EXPECT_EQ(submit_event_request(event),
            body_with(R"({"signal":"dbg.tracer_pid","source":"sysctl","status":"OK","value":{"long":"-1"}})"));
}

TEST(SubmitEvent, submitEventRequest_whenTextsNeedEscaping_escapesThem) {
  Event event = event_with({
      {
          .signal = "jb.\"x\" \\ \x02",
          .source = "stat",
          .status = Status::kOk,
          .value = std::string("C:\\tmp \"a\" \x01"),
      },
  });
  event.build_id = "build \"1\" \\ \x1f";

  EXPECT_EQ(submit_event_request(event), body("1791381801512", R"(build \"1\" \\ \u001f)",
                                              R"({"signal":"jb.\"x\" \\ \u0002","source":"stat","status":"OK",)"
                                              R"("value":{"string":"C:\\tmp \"a\" \u0001"}})"));
}

TEST(SubmitEvent, submitEventRequest_whenTheTimeIsBefore1970_roundsDownToTheMillisecond) {
  Event event = event_with({});
  event.observed_at = std::chrono::system_clock::time_point{} - std::chrono::microseconds{1500};

  EXPECT_EQ(submit_event_request(event), body("-2", "build-1", ""));
}

}  // namespace
}  // namespace rasp
