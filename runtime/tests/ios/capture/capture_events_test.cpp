/// Production primitive reducer tests; these do not simulate or validate UIKit.
#include "capture/capture_events.h"

#include <atomic>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <thread>

#include "rasp/cycle.h"

namespace rasp::ios::capture {
namespace {
std::int64_t& clock_tick() {
  static std::int64_t tick = 0;
  return tick;
}
CycleClockReading clock_reading() {
  return {.monotonic_ns = clock_tick() < 0 ? std::nullopt : std::optional(clock_tick())};
}
void publish(CaptureEvents& events, std::int64_t session, std::int64_t generation, int value,
             SampleKind kind = SampleKind::kInitial) {
  events.sample(session, generation, events.ticket(session, generation), kind, value);
}
TEST(IOSCaptureEvents, drain_whenNoHost_doesNotInventNegative) {
  CaptureEvents events(clock_reading);
  const auto cut = events.drain(true, true);
  EXPECT_EQ(cut.sources[0].availability, Availability::kNeverStarted);
  EXPECT_EQ(cut.sources[1].state, -1);
}
TEST(IOSCaptureEvents, open_whenMonitorInterleaves_requiresRegistrationAndSample) {
  clock_tick() = 0;
  CaptureEvents events(clock_reading);
  const auto session = events.start(true, true);
  EXPECT_NE(events.drain(true, true).sources[0].availability, Availability::kActive);
  const auto generation = events.open(session, Scope::kScene);
  EXPECT_NE(events.drain(true, true).sources[1].availability, Availability::kActive);
  publish(events, session, generation, 0);
  EXPECT_NE(events.drain(true, true).sources[1].availability, Availability::kActive);
  events.registered(session, generation);
  const auto cut = events.drain(true, true);
  EXPECT_EQ(cut.sources[1].availability, Availability::kActive);
  EXPECT_EQ(cut.sources[1].state, 0);
}
TEST(IOSCaptureEvents, sample_whenInitialReadReenters_doesNotOverwriteNewerCallback) {
  clock_tick() = 0;
  CaptureEvents events(clock_reading);
  const auto session = events.start(false, true);
  const auto generation = events.open(session, Scope::kScene);
  const auto older = events.ticket(session, generation);
  publish(events, session, generation, 1, SampleKind::kCallback);
  events.registered(session, generation);
  events.sample(session, generation, older, SampleKind::kInitial, 0);
  const auto cut = events.drain(false, true).sources[1];
  EXPECT_EQ(cut.state, 1);
  EXPECT_EQ(cut.callbacks, 1);
  EXPECT_EQ(cut.ignored, 1);
}
TEST(IOSCaptureEvents, invalidate_whenTeardownInterleaves_closesBeforeCleanupOrReselection) {
  clock_tick() = 0;
  CaptureEvents events(clock_reading);
  const auto session = events.start(false, true);
  const auto old = events.open(session, Scope::kScene);
  events.registered(session, old);
  publish(events, session, old, 1);
  events.invalidate(session, Availability::kInactive);
  EXPECT_EQ(events.drain(false, true).sources[1].state, -1);
  publish(events, session, old, 0, SampleKind::kCallback);
  EXPECT_EQ(events.drain(false, true).sources[1].availability, Availability::kInactive);
  const auto replacement = events.open(session, Scope::kScene);
  events.registered(session, replacement);
  EXPECT_NE(events.drain(false, true).sources[1].availability, Availability::kActive);
  publish(events, session, old, 0, SampleKind::kCallback);
  publish(events, session, replacement, 1);
  events.failure(session, 1, Availability::kTeardownError);
  EXPECT_EQ(events.drain(false, true).sources[1].availability, Availability::kTeardownError);
}
TEST(IOSCaptureEvents, drain_whenStaleOrClockFails_requiresFreshMainSampleToRecover) {
  clock_tick() = 0;
  CaptureEvents events(clock_reading);
  const auto session = events.start(true, true);
  events.screenshot_ready(session, true);
  const auto generation = events.open(session, Scope::kScreen);
  events.registered(session, generation);
  publish(events, session, generation, 0);
  clock_tick() = 15000000000;
  EXPECT_EQ(events.drain(true, true).sources[1].availability, Availability::kActive);
  clock_tick() = 15001000000;
  EXPECT_EQ(events.drain(true, true).sources[1].availability, Availability::kStale);
  clock_tick() = -1;
  EXPECT_EQ(events.drain(true, true).sources[1].availability, Availability::kClockUnavailable);
  clock_tick() = 1;
  EXPECT_EQ(events.drain(true, true).sources[1].availability, Availability::kClockUnavailable);
  publish(events, session, generation, 0, SampleKind::kResample);
  events.screenshot_ready(session, true);
  EXPECT_EQ(events.drain(true, true).sources[1].availability, Availability::kActive);
}
TEST(IOSCaptureEvents, drain_whenOneGroupDisabled_preservesOtherDeltasAcrossStopStart) {
  clock_tick() = 0;
  CaptureEvents events(clock_reading);
  const auto session = events.start(true, true);
  events.screenshot_ready(session, true);
  events.screenshot(session);
  const auto generation = events.open(session, Scope::kScene);
  events.registered(session, generation);
  publish(events, session, generation, 1);
  publish(events, session, generation, 1, SampleKind::kCallback);
  EXPECT_EQ(events.drain(false, true).sources[1].callbacks, 1);
  events.stop(session);
  const auto next = events.start(true, false);
  events.screenshot_ready(next, true);
  const auto retained = events.drain(true, false);
  EXPECT_EQ(retained.sources[0].callbacks, 1);
  EXPECT_EQ(events.drain(true, false).sources[0].callbacks, 0);
  EXPECT_EQ(retained.sources[0].callbacks, 1);
}
TEST(IOSCaptureEvents, sample_whenUnspecifiedInvalidDuplicateAndResampled_distinguishesEvidence) {
  clock_tick() = 0;
  CaptureEvents events(clock_reading);
  const auto session = events.start(false, true);
  const auto generation = events.open(session, Scope::kScene);
  events.registered(session, generation);
  publish(events, session, generation, 2);
  EXPECT_EQ(events.drain(false, true).sources[1].availability, Availability::kUnavailableState);
  publish(events, session, generation, 0, SampleKind::kCallback);
  publish(events, session, generation, 0, SampleKind::kCallback);
  publish(events, session, generation, 1, SampleKind::kResample);
  const auto cut = events.drain(false, true).sources[1];
  EXPECT_EQ(cut.callbacks, 2);
  EXPECT_EQ(cut.changes, 1);
  EXPECT_EQ(cut.resamples, 1);
  EXPECT_EQ(cut.lost, 1);
  publish(events, session, generation, 88, SampleKind::kCallback);
  EXPECT_EQ(events.drain(false, true).sources[1].availability, Availability::kUnavailableState);
}
TEST(IOSCaptureEvents, screenshot_whenCounterOrEpochExhausts_neverWraps) {
  clock_tick() = 0;
  CaptureEvents events(clock_reading, 2);
  const auto session = events.start(true, false);
  events.screenshot_ready(session, true);
  for (int index = 0; index < 4; ++index) {
    events.screenshot(session);
  }
  const auto cut = events.drain(true, false).sources[0];
  EXPECT_EQ(cut.callbacks, 2);
  EXPECT_TRUE(cut.overflow);
  events.stop(session);
  const auto next = events.start(true, false);
  events.stop(next);
  EXPECT_EQ(events.start(true, false), 0);
  EXPECT_EQ(events.drain(true, false).sources[0].availability, Availability::kExhausted);
}
TEST(IOSCaptureEvents, reject_whenWrongThreadAndOldGeneration_doesNotRestoreHealth) {
  clock_tick() = 0;
  CaptureEvents events(clock_reading);
  const auto session = events.start(true, true);
  events.screenshot_ready(session, true);
  const auto generation = events.open(session, Scope::kScene);
  events.registered(session, generation);
  publish(events, session, generation, 0);
  events.reject(session, 1, generation, true);
  EXPECT_EQ(events.drain(false, true).sources[1].availability, Availability::kError);
  events.screenshot(session);
  EXPECT_EQ(events.drain(true, false).sources[0].callbacks, 1);
}
TEST(IOSCaptureEvents, screenshot_whenProducerAndConsumerRace_retainsEveryAcceptedNotification) {
  CaptureEvents events;
  const auto session = events.start(true, false);
  events.screenshot_ready(session, true);
  std::atomic<bool> finished = false;
  std::thread producer([&] {
    for (int index = 0; index < 2000; ++index) {
      events.screenshot(session);
    }
    finished = true;
  });
  std::int64_t count = 0;
  while (!finished.load()) {
    count += events.drain(true, false).sources[0].callbacks;
  }
  producer.join();
  count += events.drain(true, false).sources[0].callbacks;
  EXPECT_EQ(count, 2000);
}

TEST(IOSCaptureEvents, cleanup_whenFailedStopIsRetried_doesNotLeaveObsoleteTeardownErrorAfterSuccess) {
  clock_tick() = 0;
  CaptureEvents events(clock_reading);
  const auto session = events.start(true, true);
  events.stop(session);
  events.failure(session, 1, Availability::kTeardownError);
  EXPECT_EQ(events.drain(false, true).sources[1].availability, Availability::kTeardownError);
  events.cleanup_complete(session);
  EXPECT_EQ(events.drain(false, true).sources[1].availability, Availability::kDeactivated);
}
TEST(IOSCaptureEvents, sample_whenClockOrStaleGapEnds_startsNewBaselineWithoutInventedTransition) {
  for (const int gap : {0, 1, 2, 3}) {
    SCOPED_TRACE(gap);
    clock_tick() = gap == 2 ? 1000000000 : 0;
    CaptureEvents events(clock_reading);
    const auto session = events.start(false, true);
    const auto generation = events.open(session, Scope::kScene);
    events.registered(session, generation);
    publish(events, session, generation, 0);
    static_cast<void>(events.drain(false, true));
    if (gap == 0) {
      clock_tick() = -1;
    } else if (gap == 2) {
      clock_tick() = 0;
    } else {
      clock_tick() = 16000000000;
    }
    if (gap != 3) {
      static_cast<void>(events.drain(false, true));
    }
    clock_tick() = gap == 0 || gap == 2 ? 1000000000 : 16000000001;
    publish(events, session, generation, 1, SampleKind::kCallback);
    const auto cut = events.drain(false, true).sources[1];
    EXPECT_EQ(cut.availability, Availability::kActive);
    EXPECT_EQ(cut.callbacks, 1);
    EXPECT_EQ(cut.initial, 1);
    EXPECT_EQ(cut.changes, 0);
    EXPECT_GT(cut.lost, 0);
  }
}
TEST(IOSCaptureEvents, failure_whenOnlyRecordingFails_preservesScreenshotOwnershipAndCounts) {
  clock_tick() = 0;
  CaptureEvents events(clock_reading);
  const auto session = events.start(true, true);
  events.screenshot_ready(session, true);
  const auto generation = events.open(session, Scope::kScene);
  events.failure(session, 1, Availability::kRegistrationError);
  publish(events, session, generation, 0, SampleKind::kCallback);
  events.registered(session, generation);
  events.screenshot(session);
  const auto cut = events.drain(true, true);
  EXPECT_EQ(cut.sources[0].callbacks, 1);
  EXPECT_EQ(cut.sources[0].availability, Availability::kActive);
  EXPECT_EQ(cut.sources[1].availability, Availability::kRegistrationError);
  EXPECT_EQ(cut.sources[1].state, -1);
}
TEST(IOSCaptureEvents, drain_whenClockMovesBackwardsOrIsEqual_requiresTwoFreshIntervalSamples) {
  clock_tick() = 1000000;
  CaptureEvents events(clock_reading);
  const auto session = events.start(true, false);
  events.screenshot_ready(session, true);
  EXPECT_EQ(events.drain(true, false).sources[0].interval_ms, -1);
  EXPECT_EQ(events.drain(true, false).sources[0].interval_ms, 0);
  clock_tick() = 0;
  EXPECT_EQ(events.drain(true, false).sources[0].interval_ms, -1);
  clock_tick() = 1000000;
  EXPECT_EQ(events.drain(true, false).sources[0].interval_ms, -1);
  events.screenshot_ready(session, true);
  clock_tick() = 2000000;
  const auto cut = events.drain(true, false);
  EXPECT_EQ(cut.sources[0].interval_ms, 1);
  EXPECT_EQ(cut.sources[0].availability, Availability::kActive);
}
TEST(IOSCaptureEvents, screenshot_whenInactiveOrOldSession_isIgnoredAndDoesNotReopen) {
  clock_tick() = 0;
  CaptureEvents events(clock_reading);
  const auto session = events.start(true, false);
  events.screenshot_ready(session, false);
  events.screenshot(session);
  auto cut = events.drain(true, false).sources[0];
  EXPECT_EQ(cut.callbacks, 0);
  EXPECT_EQ(cut.ignored, 1);
  EXPECT_EQ(cut.availability, Availability::kInactive);
  events.stop(session);
  const auto next = events.start(true, false);
  events.screenshot_ready(next, true);
  events.screenshot(session);
  cut = events.drain(true, false).sources[0];
  EXPECT_EQ(cut.callbacks, 0);
  EXPECT_EQ(cut.ignored, 1);
  EXPECT_EQ(cut.availability, Availability::kActive);
}
TEST(IOSCaptureEvents, open_whenGenerationSpaceExhausted_hasNoWrappedHealthySelection) {
  clock_tick() = 0;
  CaptureEvents events(clock_reading, 2);
  const auto session = events.start(false, true);
  EXPECT_GT(events.open(session, Scope::kScene), 0);
  EXPECT_GT(events.open(session, Scope::kScene), 0);
  EXPECT_EQ(events.open(session, Scope::kScene), 0);
  const auto cut = events.drain(false, true).sources[1];
  EXPECT_EQ(cut.availability, Availability::kExhausted);
  EXPECT_FALSE(cut.registered);
  EXPECT_EQ(cut.state, -1);
}
}  // namespace
}  // namespace rasp::ios::capture
