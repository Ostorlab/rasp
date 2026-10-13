/// Tests for Reporter, which sends through a fake transport that records each request.

#include "rasp/reporting/reporter.h"

#include <chrono>
#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "rasp/observation.h"
#include "rasp/reporting/submit_observations.h"
#include "rasp/reporting/transport.h"
#include "rasp/util/uuid.h"

namespace {

/// A transport that records each request body it is asked to send.
class FakeTransport : public rasp::Transport {
 public:
  /// Records `body`.
  void post(std::string_view body) noexcept override { bodies_.emplace_back(body); }

  /// Every request body sent so far, in order.
  [[nodiscard]] const std::vector<std::string>& bodies() const { return bodies_; }

 private:
  /// The request bodies received so far.
  std::vector<std::string> bodies_;
};

/// The install id of the session, 0f8c2e1a-7b3d-4c5e-9a1b-2c3d4e5f6a7b.
constexpr rasp::Uuid kInstallId{
    .bytes = {0x0f, 0x8c, 0x2e, 0x1a, 0x7b, 0x3d, 0x4c, 0x5e, 0x9a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x6a, 0x7b},
};

/// The session id of the session, 3d6a9b7e-2c41-4f08-8e5d-1b7c9a2f4e63.
constexpr rasp::Uuid kSessionId{
    .bytes = {0x3d, 0x6a, 0x9b, 0x7e, 0x2c, 0x41, 0x4f, 0x08, 0x8e, 0x5d, 0x1b, 0x7c, 0x9a, 0x2f, 0x4e, 0x63},
};

/// The build id of the session.
constexpr std::string_view kBuildId = "build-7";

/// The time the fixture's clock always gives, 1791381801512 milliseconds after the Unix epoch.
constexpr std::chrono::system_clock::time_point kNow{std::chrono::milliseconds{1791381801512}};

/// Gives each test a reporter for one session that sends through a fake transport, with a fixed clock.
class Reporter : public testing::Test {
 protected:
  /// The fake transport the reporter sends through.
  FakeTransport transport_;
  /// The reporter under test.
  rasp::Reporter reporter_{
      std::string(kBuildId),
      rasp::SessionIds{.install_id = kInstallId, .session_id = kSessionId},
      transport_,
      [] { return kNow; },
  };
};

/// The request body of the session's batch `seq`, holding `observations`.
[[nodiscard]] std::string body_of(std::int32_t seq, std::vector<rasp::Observation> observations) {
  return rasp::submit_observations_request(rasp::ObservationBatch{
      .install_id = kInstallId,
      .session_id = kSessionId,
      .seq = seq,
      .observed_at = kNow,
      .build_id = std::string(kBuildId),
      .observations = std::move(observations),
  });
}

/// What a first run of the checks observes.
[[nodiscard]] std::vector<rasp::Observation> first_run() {
  return {
      {.signal = "jb.fs_paths", .source = "stat", .status = rasp::Status::kOk, .value = std::vector<std::string>{}},
      {.signal = "jb.fork_ok", .source = "fork", .status = rasp::Status::kOk, .value = false},
  };
}

TEST_F(Reporter, report_whenNothingWasReported_sendsEveryObservation) {
  reporter_.report(first_run());

  ASSERT_EQ(transport_.bodies().size(), 1U);
  EXPECT_EQ(transport_.bodies().at(0), body_of(1, first_run()));
}

TEST_F(Reporter, report_whenNothingChanged_sendsNothingAndUsesNoSeq) {
  const rasp::Observation changed{.signal = "jb.fork_ok", .source = "fork", .status = rasp::Status::kOk, .value = true};
  reporter_.report(first_run());

  reporter_.report(first_run());
  reporter_.report({changed});

  ASSERT_EQ(transport_.bodies().size(), 2U);
  EXPECT_EQ(transport_.bodies().at(1), body_of(2, {changed}));
}

TEST_F(Reporter, report_whenAValueChanged_sendsOnlyThatObservation) {
  const rasp::Observation changed{
      .signal = "jb.fs_paths",
      .source = "stat",
      .status = rasp::Status::kOk,
      .value = std::vector<std::string>{"/var/jb"},
  };
  reporter_.report(first_run());

  reporter_.report({changed, first_run().back()});

  ASSERT_EQ(transport_.bodies().size(), 2U);
  EXPECT_EQ(transport_.bodies().at(1), body_of(2, {changed}));
}

TEST_F(Reporter, report_whenAStatusChanged_sendsOnlyThatObservation) {
  const rasp::Observation changed{
      .signal = "jb.fork_ok",
      .source = "fork",
      .status = rasp::Status::kError,
      .value = {},
  };
  reporter_.report(first_run());

  reporter_.report({first_run().front(), changed});

  ASSERT_EQ(transport_.bodies().size(), 2U);
  EXPECT_EQ(transport_.bodies().at(1), body_of(2, {changed}));
}

TEST_F(Reporter, report_whenASignalAndSourceAreNew_sendsOnlyThatObservation) {
  const rasp::Observation added{
      .signal = "jb.fs_paths",
      .source = "access",
      .status = rasp::Status::kOk,
      .value = std::vector<std::string>{},
  };
  std::vector<rasp::Observation> observations = first_run();
  observations.push_back(added);
  reporter_.report(first_run());

  reporter_.report(observations);

  ASSERT_EQ(transport_.bodies().size(), 2U);
  EXPECT_EQ(transport_.bodies().at(1), body_of(2, {added}));
}

TEST_F(Reporter, report_whenAnObservationChangesBack_sendsItAgain) {
  reporter_.report(first_run());
  reporter_.report({{.signal = "jb.fork_ok", .source = "fork", .status = rasp::Status::kOk, .value = true}});

  reporter_.report(first_run());

  ASSERT_EQ(transport_.bodies().size(), 3U);
  EXPECT_EQ(transport_.bodies().at(2), body_of(3, {first_run().back()}));
}

TEST_F(Reporter, report_whenAnObservationIsMissing_sendsNothingForIt) {
  reporter_.report(first_run());
  reporter_.report({first_run().front()});

  reporter_.report(first_run());

  EXPECT_EQ(transport_.bodies().size(), 1U);
}

TEST_F(Reporter, report_whenAnObservationRepeatsInOneRun_sendsItOnce) {
  const rasp::Observation observation = first_run().front();

  reporter_.report({observation, observation});

  ASSERT_EQ(transport_.bodies().size(), 1U);
  EXPECT_EQ(transport_.bodies().at(0), body_of(1, {observation}));
}

}  // namespace
