/// Tests for Reporter, which sends through a fake transport that records each request.

#include "rasp/reporting/reporter.h"

#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "rasp/observation.h"
#include "rasp/reporting/event.h"
#include "rasp/reporting/submit_event.h"
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

/// The seq in a request body, or -1 when the body has none.
[[nodiscard]] std::int64_t seq_of(std::string_view body) {
  constexpr std::string_view kKey = R"("seq":)";
  const std::size_t start = body.find(kKey);
  if (start == std::string_view::npos) {
    return -1;
  }
  const std::string_view rest = body.substr(start + kKey.size());
  std::int64_t seq = 0;
  const auto [stop, error] = std::from_chars(std::to_address(rest.begin()), std::to_address(rest.end()), seq);
  return error == std::errc() ? seq : -1;
}

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

TEST_F(Reporter, send_whenBatchesAreQueued_sendsEachOnceInOrderWithIncreasingSeq) {
  reporter_.add({});
  reporter_.add({});

  reporter_.send();

  ASSERT_EQ(transport_.bodies().size(), 2U);
  EXPECT_EQ(seq_of(transport_.bodies().at(0)), 1);
  EXPECT_EQ(seq_of(transport_.bodies().at(1)), 2);
  EXPECT_EQ(reporter_.pending(), 0U);
}

TEST_F(Reporter, send_whenObservationsAreQueued_sendsThemWithTheSessionIdsTheClockTimeAndTheBuildId) {
  const std::vector<rasp::Observation> observations{
      {.signal = "jb.fork_ok", .source = "fork", .status = rasp::Status::kOk, .value = true},
      {
          .signal = "jb.fs_paths",
          .source = "stat",
          .status = rasp::Status::kOk,
          .value = std::vector<std::string>{"/var/jb"},
      },
  };
  reporter_.add({});
  reporter_.add(observations);

  reporter_.send();

  ASSERT_EQ(transport_.bodies().size(), 2U);
  EXPECT_EQ(transport_.bodies().at(1), rasp::submit_event_request(rasp::Event{
                                           .install_id = kInstallId,
                                           .session_id = kSessionId,
                                           .seq = 2,
                                           .observed_at = kNow,
                                           .build_id = std::string(kBuildId),
                                           .observations = observations,
                                       }));
}

TEST_F(Reporter, send_whenCalledAgain_neverSendsABatchTwice) {
  reporter_.add({{.signal = "example.loaded", .source = "runtime", .status = rasp::Status::kOk, .value = true}});

  reporter_.send();
  reporter_.send();

  EXPECT_EQ(transport_.bodies().size(), 1U);
}

TEST_F(Reporter, add_whenEarlierBatchesWereSent_continuesTheSeqOfTheSession) {
  reporter_.add({});
  reporter_.send();
  reporter_.add({});
  reporter_.send();

  ASSERT_EQ(transport_.bodies().size(), 2U);
  EXPECT_EQ(seq_of(transport_.bodies().at(1)), 2);
}

TEST_F(Reporter, add_whenTheQueueIsFull_dropsTheOldestBatch) {
  for (std::size_t i = 0; i <= rasp::Reporter::kMaxPendingBatches; ++i) {
    reporter_.add({});
  }

  EXPECT_EQ(reporter_.pending(), rasp::Reporter::kMaxPendingBatches);
  reporter_.send();
  ASSERT_EQ(transport_.bodies().size(), rasp::Reporter::kMaxPendingBatches);
  EXPECT_EQ(seq_of(transport_.bodies().at(0)), 2);
}

}  // namespace
