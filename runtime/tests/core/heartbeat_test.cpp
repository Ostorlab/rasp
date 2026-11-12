/// Tests for Heartbeat: when its integ.monitor_alive observation reports the beating thread as stopped, and that a
/// stopped heartbeat panics.

#include "rasp/heartbeat.h"

#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <thread>
#include <vector>

#include "rasp/observation.h"
#include "rasp/panic.h"

namespace rasp {
namespace {

using std::chrono::milliseconds;
using std::chrono::seconds;
using std::chrono::steady_clock;

/// A time of the steady clock, `offset` after an arbitrary start.
///
/// @param offset How long after the start.
/// @return The time.
[[nodiscard]] steady_clock::time_point at(milliseconds offset) {
  return steady_clock::time_point{seconds{1000}} + offset;
}

/// The integ.monitor_alive observation with the value `alive`.
///
/// @param alive Whether the thread is reported as running.
/// @return The observation.
[[nodiscard]] Observation monitor_alive(bool alive) { return observed("integ.monitor_alive", "heartbeat", alive); }

/// Just over the bound after the start.
constexpr milliseconds kStale = kHeartbeatBound + milliseconds{1};

/// How many times the stand-in ended the process.
///
/// @return The counter, which lives as long as the test process.
[[nodiscard]] std::atomic<int>& end_calls() {
  static std::atomic<int> calls{0};
  return calls;
}

/// The stand-in for the end of the process: counts the call and returns.
void record_end() noexcept { end_calls().fetch_add(1); }

TEST(Heartbeat, observe_whenItNeverBeat_reportsAlive) {
  Heartbeat heartbeat;
  EXPECT_EQ(heartbeat.observe(at(milliseconds{0})), monitor_alive(true));
  EXPECT_EQ(heartbeat.observe(at(kStale + kStaleConfirmation)), monitor_alive(true));
}

TEST(Heartbeat, observe_whenTheLastBeatIsWithinTheBound_reportsAlive) {
  Heartbeat heartbeat;
  heartbeat.beat(at(milliseconds{0}));
  EXPECT_EQ(heartbeat.observe(at(kHeartbeatBound)), monitor_alive(true));
  EXPECT_EQ(heartbeat.observe(at(kHeartbeatBound + kStaleConfirmation)), monitor_alive(true));
}

TEST(Heartbeat, observe_whenFirstSeenStale_reportsAlive) {
  Heartbeat heartbeat;
  heartbeat.beat(at(milliseconds{0}));
  EXPECT_EQ(heartbeat.observe(at(kStale)), monitor_alive(true));
}

TEST(Heartbeat, observe_whenSeenStaleAgainWithinTheConfirmation_reportsAlive) {
  Heartbeat heartbeat;
  heartbeat.beat(at(milliseconds{0}));
  ASSERT_EQ(heartbeat.observe(at(kStale)), monitor_alive(true));
  EXPECT_EQ(heartbeat.observe(at(kStale + kStaleConfirmation - milliseconds{1})), monitor_alive(true));
}

TEST(Heartbeat, observe_whenSeenStaleAgainAfterTheConfirmation_reportsStopped) {
  Heartbeat heartbeat;
  heartbeat.beat(at(milliseconds{0}));
  ASSERT_EQ(heartbeat.observe(at(kStale)), monitor_alive(true));
  EXPECT_EQ(heartbeat.observe(at(kStale + kStaleConfirmation)), monitor_alive(false));
  EXPECT_EQ(heartbeat.observe(at(kStale + seconds{3600})), monitor_alive(false));
}

TEST(Heartbeat, observe_whenTheThreadBeatsAgain_reportsAlive) {
  Heartbeat heartbeat;
  heartbeat.beat(at(milliseconds{0}));
  ASSERT_EQ(heartbeat.observe(at(kStale)), monitor_alive(true));
  ASSERT_EQ(heartbeat.observe(at(kStale + kStaleConfirmation)), monitor_alive(false));
  heartbeat.beat(at(kStale + kStaleConfirmation + milliseconds{1}));
  EXPECT_EQ(heartbeat.observe(at(kStale + kStaleConfirmation + milliseconds{2})), monitor_alive(true));
}

TEST(Heartbeat, observe_whenTheThreadBeatsRightAfterTheProcessResumes_neverReportsStopped) {
  Heartbeat heartbeat;
  heartbeat.beat(at(milliseconds{0}));
  const milliseconds resumed = seconds{3600};
  ASSERT_EQ(heartbeat.observe(at(resumed)), monitor_alive(true));
  heartbeat.beat(at(resumed + milliseconds{1}));
  EXPECT_EQ(heartbeat.observe(at(resumed + kStaleConfirmation)), monitor_alive(true));
  EXPECT_EQ(heartbeat.observe(at(resumed + seconds{60})), monitor_alive(true));
}

TEST(Heartbeat, observe_whenTheStaleSightingPrecedesTheLastBeat_recordsANewOne) {
  Heartbeat heartbeat;
  heartbeat.beat(at(milliseconds{0}));
  ASSERT_EQ(heartbeat.observe(at(kStale)), monitor_alive(true));
  const milliseconds beat = kStale + milliseconds{1};
  heartbeat.beat(at(beat));
  EXPECT_EQ(heartbeat.observe(at(beat + kStale)), monitor_alive(true));
  EXPECT_EQ(heartbeat.observe(at(beat + kStale + kStaleConfirmation - milliseconds{1})), monitor_alive(true));
  EXPECT_EQ(heartbeat.observe(at(beat + kStale + kStaleConfirmation)), monitor_alive(false));
}

TEST(Heartbeat, observe_whenThreadsBeatAndObserveAtOnce_isSafe) {
  Heartbeat heartbeat;
  std::atomic<bool> stop{false};
  const std::jthread beater([&heartbeat, &stop] {
    while (!stop.load()) {
      heartbeat.beat(steady_clock::now());
    }
  });
  {
    std::vector<std::jthread> observers;
    observers.reserve(4);
    for (int thread = 0; thread < 4; ++thread) {
      observers.emplace_back([&heartbeat] {
        for (int call = 0; call < 10000; ++call) {
          EXPECT_EQ(heartbeat.observe(steady_clock::now()), monitor_alive(true));
        }
      });
    }
  }
  stop.store(true);
}

TEST(Heartbeat, monitorHeartbeat_whenCalledTwice_returnsTheSameHeartbeat) {
  EXPECT_EQ(&monitor_heartbeat(), &monitor_heartbeat());
}

TEST(Heartbeat, panicOnDetection_whenTheHeartbeatIsReportedStopped_armsAPanic) {
  Heartbeat heartbeat;
  heartbeat.beat(at(milliseconds{0}));
  ASSERT_EQ(heartbeat.observe(at(kStale)), monitor_alive(true));
  const std::vector<Observation> observations = {heartbeat.observe(at(kStale + kStaleConfirmation))};
  EXPECT_TRUE(panic_on_detection(observations, record_end));
  const steady_clock::time_point deadline = steady_clock::now() + kMaxPanicDelay + seconds{2};
  while (end_calls().load() == 0 && steady_clock::now() < deadline) {
    std::this_thread::sleep_for(milliseconds{10});
  }
  EXPECT_EQ(end_calls().load(), 1);
}

TEST(Heartbeat, panicOnDetection_whenTheHeartbeatIsReportedAlive_armsNothing) {
  const std::vector<Observation> observations = {monitor_alive(true)};
  EXPECT_FALSE(panic_on_detection(observations, record_end));
}

}  // namespace
}  // namespace rasp
