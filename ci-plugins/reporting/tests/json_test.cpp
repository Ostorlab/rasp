/// Tests for the reporting plugin's JSON: every value kind and status, string escaping and UTF-8 repair, observations
/// left out, and the size limits.

#include "json.h"

#include <array>
#include <bit>
#include <cstdint>
#include <gtest/gtest.h>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "config.h"
#include "rasp/observation.h"

namespace rasp::plugins::reporting {
namespace {

/// The JSON list of one observation whose value is the string `value`, under the request's limit.
///
/// @param value The string's bytes.
/// @return The list, or `refused` when it was refused.
[[nodiscard]] std::string serialise_string(std::string_view value) {
  const std::array<Observation, 1> run{observed("s.v", "test", std::string(value))};
  return serialise_observations(run, kMaxRequestSize).value_or("refused");
}

/// The JSON list that holds one observation of the signal `s.v`, the source `test`, the status OK and the given string
/// value.
///
/// @param value The string's JSON, with its quotes.
/// @return The list.
[[nodiscard]] std::string expected_list(std::string_view value) {
  return R"([{"signal":"s.v","source":"test","status":"OK","value":{"string":)" + std::string(value) + "}}]";
}

TEST(Json, serialiseObservations_whenNone_writesAnEmptyList) {
  EXPECT_EQ(serialise_observations({}, kMaxRequestSize), "[]");
}

TEST(Json, serialiseObservations_whenEachValueKind_writesItsJson) {
  const std::array<Observation, 9> run{
      observed("v.none", "test", {}),
      observed("v.true", "test", true),
      observed("v.false", "test", false),
      observed("v.max", "test", std::numeric_limits<std::int64_t>::max()),
      observed("v.min", "test", std::numeric_limits<std::int64_t>::min()),
      observed("v.string", "test", std::string("abc")),
      observed("v.empty", "test", std::string()),
      observed("v.list", "test", std::vector<std::string>{"a", "bc"}),
      observed("v.nothing", "test", std::vector<std::string>{}),
  };

  EXPECT_EQ(serialise_observations(run, kMaxRequestSize),
            R"([{"signal":"v.none","source":"test","status":"OK","value":null},)"
            R"({"signal":"v.true","source":"test","status":"OK","value":{"bool":true}},)"
            R"({"signal":"v.false","source":"test","status":"OK","value":{"bool":false}},)"
            R"({"signal":"v.max","source":"test","status":"OK","value":{"long":"9223372036854775807"}},)"
            R"({"signal":"v.min","source":"test","status":"OK","value":{"long":"-9223372036854775808"}},)"
            R"({"signal":"v.string","source":"test","status":"OK","value":{"string":"abc"}},)"
            R"({"signal":"v.empty","source":"test","status":"OK","value":{"string":""}},)"
            R"({"signal":"v.list","source":"test","status":"OK","value":{"strings":["a","bc"]}},)"
            R"({"signal":"v.nothing","source":"test","status":"OK","value":{"strings":[]}}])");
}

TEST(Json, serialiseObservations_whenEachStatus_writesItsName) {
  const std::array<Observation, 4> run{
      observed("s.a", "test", {}),
      unsupported("s.b", "test"),
      failed("s.c", "test"),
      Observation{.signal = "s.d", .source = "test", .status = Status::kTimeout, .value = {}},
  };

  EXPECT_EQ(serialise_observations(run, kMaxRequestSize),
            R"([{"signal":"s.a","source":"test","status":"OK","value":null},)"
            R"({"signal":"s.b","source":"test","status":"UNSUPPORTED","value":null},)"
            R"({"signal":"s.c","source":"test","status":"ERROR","value":null},)"
            R"({"signal":"s.d","source":"test","status":"TIMEOUT","value":null}])");
}

TEST(Json, serialiseObservations_whenStringHasQuotesBackslashesAndControls_escapesThem) {
  const std::string raw = std::string("q\"b\\s/ \b\f\n\r\t") + '\0' + "\x01\x1f\x7f";

  EXPECT_EQ(serialise_string(raw), expected_list(R"("q\"b\\s/ \b\f\n\r\t\u0000\u0001\u001f\u007f")"));
}

TEST(Json, serialiseObservations_whenSignalAndSourceNeedEscaping_escapesThem) {
  const std::array<Observation, 1> run{observed("a\"b", "c\nd", {})};

  EXPECT_EQ(serialise_observations(run, kMaxRequestSize),
            R"([{"signal":"a\"b","source":"c\nd","status":"OK","value":null}])");
}

TEST(Json, serialiseObservations_whenStringIsValidUtf8_copiesIt) {
  const std::string_view raw = "\xc3\xa9 \xe4\xb8\xad \xf0\x9f\x98\x80 \xef\xbf\xbf \xf4\x8f\xbf\xbf";

  EXPECT_EQ(serialise_string(raw), expected_list("\"" + std::string(raw) + "\""));
}

TEST(Json, serialiseObservations_whenStringIsInvalidUtf8_replacesEachBadByte) {
  EXPECT_EQ(serialise_string("a\xff"
                             "b"),
            expected_list(R"("a\ufffdb")"));
  EXPECT_EQ(serialise_string("\xc0\x80"), expected_list(R"("\ufffd\ufffd")"));
  EXPECT_EQ(serialise_string("\xed\xa0\x80"), expected_list(R"("\ufffd\ufffd\ufffd")"));
  EXPECT_EQ(serialise_string("\xe2\x82"), expected_list(R"("\ufffd\ufffd")"));
  EXPECT_EQ(serialise_string("\xe0\x9f\xbf"), expected_list(R"("\ufffd\ufffd\ufffd")"));
  EXPECT_EQ(serialise_string("\xf0\x8f\xbf\xbf"), expected_list(R"("\ufffd\ufffd\ufffd\ufffd")"));
  EXPECT_EQ(serialise_string("\xf4\x90\x80\x80"), expected_list(R"("\ufffd\ufffd\ufffd\ufffd")"));
  EXPECT_EQ(serialise_string("\xf5\x80"), expected_list(R"("\ufffd\ufffd")"));
  EXPECT_EQ(serialise_string("\x80\xe2\x82\xac"), expected_list("\"\\ufffd\xe2\x82\xac\""));
}

TEST(Json, serialiseObservations_whenStatusIsUnknown_leavesItOutAndKeepsTheOthers) {
  Observation unknown = observed("bad.status", "test", {});
  unknown.status = std::bit_cast<Status>(std::uint8_t{9});
  const std::array<Observation, 3> run{
      observed("ok.first", "test", {}),
      unknown,
      observed("ok.last", "test", std::vector<std::string>{}),
  };

  EXPECT_EQ(serialise_observations(run, kMaxRequestSize),
            R"([{"signal":"ok.first","source":"test","status":"OK","value":null},)"
            R"({"signal":"ok.last","source":"test","status":"OK","value":{"strings":[]}}])");
}

TEST(Json, serialiseObservations_whenAtTheLimit_acceptsItAndRefusesOneByteLess) {
  const std::array<Observation, 2> run{
      observed("s.a", "test", std::string("abc")),
      observed("s.b", "test", std::string("\"\n")),
  };
  const std::optional<std::string> list = serialise_observations(run, kMaxRequestSize);
  ASSERT_TRUE(list.has_value());

  EXPECT_EQ(serialise_observations(run, list->size()), list);
  EXPECT_EQ(serialise_observations(run, list->size() - 1), std::nullopt);
}

TEST(Json, serialiseObservations_whenAtTheLimitAndAnUnknownStatusFollows_keepsTheList) {
  Observation unknown = observed("bad.status", "test", {});
  unknown.status = std::bit_cast<Status>(std::uint8_t{9});
  const Observation known = observed("s.a", "test", std::string("abc"));
  const std::array<Observation, 1> alone{known};
  const std::optional<std::string> list = serialise_observations(alone, kMaxRequestSize);
  ASSERT_TRUE(list.has_value());
  const std::array<Observation, 2> run{known, unknown};

  EXPECT_EQ(serialise_observations(run, list->size()), list);
}

TEST(Json, serialiseObservations_whenEscapingMakesItTooLarge_refuses) {
  const std::array<Observation, 1> run{
      observed("big.list", "test", std::vector<std::string>(256, std::string(4096, '"'))),
  };

  EXPECT_EQ(serialise_observations(run, kMaxRequestSize), std::nullopt);
}

TEST(Json, serialiseRequest_whenGivenAList_wrapsItInTheMutationWithTheZeroIdsAndTheBuildId) {
  const Config config{.endpoint = "https://reports.example.com/rasp", .build_id = "build-7"};

  EXPECT_EQ(serialise_request(config, "[]", kMaxRequestSize),
            R"({"query":")" + std::string(kMutation) +
                R"(","variables":{"batch":{"installId":"00000000-0000-0000-0000-000000000000",)"
                R"("sessionId":"00000000-0000-0000-0000-000000000000","buildId":"build-7","observations":[]}}})");
}

TEST(Json, serialiseRequest_whenGivenAnInstallId_sendsItAsTheInstallId) {
  const Config config{
      .endpoint = "https://reports.example.com/rasp",
      .build_id = "build-7",
      .install_id = "0f8e5b8e-6c1a-4b7e-9d3a-2a4c5e6f7a8b",
  };

  const std::optional<std::string> request = serialise_request(config, "[]", kMaxRequestSize);

  EXPECT_EQ(request,
            R"({"query":")" + std::string(kMutation) +
                R"(","variables":{"batch":{"installId":"0f8e5b8e-6c1a-4b7e-9d3a-2a4c5e6f7a8b",)"
                R"("sessionId":"00000000-0000-0000-0000-000000000000","buildId":"build-7","observations":[]}}})");
}

TEST(Json, serialiseRequest_whenTheBuildIdNeedsEscaping_escapesIt) {
  const Config config{.endpoint = "https://reports.example.com/rasp", .build_id = "b\"\\7\xff"};

  EXPECT_EQ(serialise_request(config, "[]", kMaxRequestSize),
            R"({"query":")" + std::string(kMutation) +
                R"(","variables":{"batch":{"installId":"00000000-0000-0000-0000-000000000000",)"
                R"("sessionId":"00000000-0000-0000-0000-000000000000","buildId":"b\"\\7\ufffd","observations":[]}}})");
}

TEST(Json, serialiseRequest_whenAtTheLimit_acceptsItAndRefusesOneByteLess) {
  const Config config{.endpoint = "https://reports.example.com/rasp", .build_id = "build-7"};
  const std::optional<std::string> request = serialise_request(config, "[]", kMaxRequestSize);
  ASSERT_TRUE(request.has_value());

  EXPECT_EQ(serialise_request(config, "[]", request->size()), request);
  EXPECT_EQ(serialise_request(config, "[]", request->size() - 1), std::nullopt);
}

}  // namespace
}  // namespace rasp::plugins::reporting
