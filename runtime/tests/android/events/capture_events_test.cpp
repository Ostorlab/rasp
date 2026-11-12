/// Bounded capture state, interval ownership and source independence.
#include "events/capture_events.h"

#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <thread>

#include "rasp/cycle.h"

namespace {
using rasp::android::events::CaptureEvents;
using rasp::android::events::CaptureKind;
using rasp::android::events::CaptureState;

/// Gives the reducer the successful effective permission checks performed by the Java adapter.
void grant(CaptureEvents& events, std::int64_t epoch) {
  ASSERT_TRUE(events.push(epoch, 0, 0, CaptureKind::kPermission, 4));
  ASSERT_TRUE(events.push(epoch, 1, 0, CaptureKind::kPermission, 4));
}

TEST(CaptureEvents, drain_whenSourcesSelectedIndependently_preservesOtherDeltas) {
  CaptureEvents events;
  events.platform(35);
  const auto epoch = events.start(true, true);
  ASSERT_GT(epoch, 0);
  grant(events, epoch);
  ASSERT_TRUE(events.push(epoch, 0, 1, CaptureKind::kOpen, 0));
  ASSERT_TRUE(events.push(epoch, 0, 1, CaptureKind::kCallback, 0));
  ASSERT_TRUE(events.push(epoch, 1, 1, CaptureKind::kOpen, 0));
  ASSERT_TRUE(events.push(epoch, 1, 1, CaptureKind::kInitial, 1));
  ASSERT_TRUE(events.push(epoch, 1, 1, CaptureKind::kCallback, 1));
  ASSERT_TRUE(events.push(epoch, 1, 1, CaptureKind::kCallback, 0));
  const auto screenshot = events.drain(true, false);
  EXPECT_EQ(screenshot[0].callbacks, 1);
  const auto recording = events.drain(false, true);
  EXPECT_EQ(recording[1].initial_samples, 1);
  EXPECT_EQ(recording[1].callbacks, 2);
  EXPECT_EQ(recording[1].changes, 1);
  EXPECT_EQ(recording[1].visibility, 0);
  EXPECT_EQ(events.drain(true, true)[0].callbacks, 0);
}

TEST(CaptureEvents, stop_whenEvidencePending_invalidatesCurrentStateAndRetainsDeltas) {
  CaptureEvents events;
  events.platform(35);
  const auto epoch = events.start(true, true);
  grant(events, epoch);
  ASSERT_TRUE(events.push(epoch, 1, 2, CaptureKind::kOpen, 0));
  ASSERT_TRUE(events.push(epoch, 1, 2, CaptureKind::kInitial, 1));
  events.stop(epoch);
  EXPECT_FALSE(events.push(epoch, 1, 2, CaptureKind::kCallback, 0));
  const auto result = events.drain(false, true)[1];
  EXPECT_EQ(result.visibility, -1);
  EXPECT_EQ(result.active_activities, 0);
  EXPECT_EQ(result.initial_samples, 1);
  EXPECT_EQ(result.invalid, 1);
  EXPECT_EQ(result.state, CaptureState::kDeactivated);
}

TEST(CaptureEvents, start_whenOldPlatform_reportsUnsupportedWithoutOptIn) {
  CaptureEvents events;
  events.platform(33);
  EXPECT_EQ(events.drain(true, true)[0].state, CaptureState::kUnsupported);
  EXPECT_EQ(events.drain(true, true)[1].state, CaptureState::kUnsupported);
  events.platform(34);
  const auto epoch = events.start(true, true);
  EXPECT_GT(epoch, 0);
  EXPECT_EQ(events.drain(true, true)[1].state, CaptureState::kUnsupported);
}

/// Opens a bounded set of screenshot memberships for slot/exhaustion tests.
void open_screenshots(std::int64_t epoch, CaptureEvents& events, int count) {
  for (int token = 1; token <= count; ++token) {
    EXPECT_TRUE(events.push(epoch, 0, token, CaptureKind::kOpen, 0));
  }
}
/// Delivers repeated callbacks without creating an event queue in the fixture.
void repeated_callbacks(std::int64_t epoch, CaptureEvents& events, int count) {
  for (int index = 0; index < count; ++index) {
    EXPECT_TRUE(events.push(epoch, 0, 1, CaptureKind::kCallback, 0));
  }
}

TEST(CaptureEvents, push_whenBoundsOrStateInvalid_rejectsAndPreservesHealthySource) {
  CaptureEvents events;
  events.platform(35);
  const auto epoch = events.start(true, true);
  grant(events, epoch);
  open_screenshots(epoch, events, 32);
  EXPECT_FALSE(events.push(epoch, 0, 33, CaptureKind::kOpen, 0));
  EXPECT_FALSE(events.push(epoch - 1, 0, 1, CaptureKind::kCallback, 0));
  EXPECT_FALSE(events.push(epoch, 1, 1, CaptureKind::kCallback, 7));
  const auto result = events.drain(true, true);
  EXPECT_EQ(result[0].active_activities, 32);
  EXPECT_GT(result[0].lost, 0);
  EXPECT_GT(result[0].invalid, 0);
}

TEST(CaptureEvents, push_whenOneScreenshotRegistrationFails_preservesOtherActivityAndGlobalFaults) {
  CaptureEvents events;
  events.platform(35);
  const auto epoch = events.start(true, true);
  grant(events, epoch);
  ASSERT_TRUE(events.push(epoch, 0, 1, CaptureKind::kOpen, 0));
  ASSERT_TRUE(events.push(epoch, 0, 2, CaptureKind::kOpen, 0));
  ASSERT_TRUE(events.push(epoch, 0, 1, CaptureKind::kClose, 0));
  ASSERT_TRUE(events.push(epoch, 0, 0, CaptureKind::kState, 10));
  auto const partial = events.drain(true, false)[0];
  EXPECT_EQ(partial.state, CaptureState::kPartial);
  EXPECT_EQ(partial.active_activities, 1);
  ASSERT_TRUE(events.push(epoch, 0, 2, CaptureKind::kCallback, 0));
  ASSERT_TRUE(events.push(epoch, 0, 0, CaptureKind::kState, 9));
  EXPECT_EQ(events.drain(true, false)[0].callbacks, 1);
  ASSERT_TRUE(events.push(epoch, 0, 0, CaptureKind::kState, 11));
  EXPECT_FALSE(events.push(epoch, 0, 2, CaptureKind::kCallback, 0));
  ASSERT_TRUE(events.push(epoch, 1, 2, CaptureKind::kOpen, 0));
  ASSERT_TRUE(events.push(epoch, 1, 2, CaptureKind::kInitial, 1));
  ASSERT_TRUE(events.push(epoch, 1, 0, CaptureKind::kState, 10));
  const auto failed_recording = events.drain(false, true)[1];
  EXPECT_EQ(failed_recording.active_activities, 0);
  EXPECT_EQ(failed_recording.visibility, -1);
}

TEST(CaptureEvents, push_whenActiveMetadataHasNoRegistration_rejectsInconsistentState) {
  CaptureEvents events;
  events.platform(35);
  const auto epoch = events.start(true, true);
  grant(events, epoch);
  EXPECT_FALSE(events.push(epoch, 0, 0, CaptureKind::kState, 7));
  EXPECT_FALSE(events.push(epoch, 1, 0, CaptureKind::kState, 8));
  EXPECT_EQ(events.drain(true, true)[0].state, CaptureState::kNoActiveActivity);
}

TEST(CaptureEvents, push_whenPermissionBecomesUnknown_invalidatesOnlyThatSource) {
  CaptureEvents events;
  events.platform(35);
  const auto epoch = events.start(true, true);
  grant(events, epoch);
  ASSERT_TRUE(events.push(epoch, 0, 1, CaptureKind::kOpen, 0));
  ASSERT_TRUE(events.push(epoch, 1, 1, CaptureKind::kOpen, 0));
  ASSERT_TRUE(events.push(epoch, 1, 1, CaptureKind::kInitial, 1));
  ASSERT_TRUE(events.push(epoch, 0, 0, CaptureKind::kPermission, 0));
  EXPECT_FALSE(events.push(epoch, 1, 0, CaptureKind::kPermission, 1));
  const auto result = events.drain(true, true);
  EXPECT_EQ(result[0].state, CaptureState::kError);
  EXPECT_EQ(result[0].active_activities, 0);
  EXPECT_EQ(result[1].visibility, 1);
}

TEST(CaptureEvents, push_whenConcurrentWithDrain_countsEachAcceptedCallbackOnce) {
  CaptureEvents events;
  events.platform(35);
  const auto epoch = events.start(true, false);
  ASSERT_TRUE(events.push(epoch, 0, 0, CaptureKind::kPermission, 4));
  ASSERT_TRUE(events.push(epoch, 0, 1, CaptureKind::kOpen, 0));
  std::thread writer([&] {
    for (int index = 0; index < 10000; ++index) {
      EXPECT_TRUE(events.push(epoch, 0, 1, CaptureKind::kCallback, 0));
    }
  });
  std::int64_t count = 0;
  for (int index = 0; index < 100; ++index) {
    count += events.drain(true, false)[0].callbacks;
  }
  writer.join();
  count += events.drain(true, false)[0].callbacks;
  EXPECT_EQ(count, 10000);
}

TEST(CaptureEvents, push_whenCountersAndEpochExhaust_preservesLowerBoundAndNeverWraps) {
  CaptureEvents events(rasp::read_cycle_clock, 2);
  events.platform(35);
  const auto epoch = events.start(true, true);
  grant(events, epoch);
  ASSERT_TRUE(events.push(epoch, 0, 1, CaptureKind::kOpen, 0));
  repeated_callbacks(epoch, events, 3);
  const auto snapshot = events.drain(true, false)[0];
  EXPECT_EQ(snapshot.callbacks, 2);
  EXPECT_TRUE(snapshot.overflow);
  EXPECT_FALSE(events.drain(true, false)[0].overflow);
  EXPECT_EQ(events.start(true, true), 2);
  EXPECT_EQ(events.start(true, true), 0);
  EXPECT_EQ(events.drain(true, true)[0].state, CaptureState::kError);
}

/// Returns the finite fixture clock storage.
std::int64_t& capture_tick() {
  static std::int64_t value = 0;
  return value;
}
/// Supplies finite checked clock failures without changing the production sampler.
rasp::CycleClockReading capture_clock() {
  return {.monotonic_ns = capture_tick() < 0 ? std::nullopt : std::optional(capture_tick()), .unix_ms = std::nullopt};
}
TEST(CaptureEvents, drain_whenClockFailsOrMovesBackwards_requiresTwoFreshSamples) {
  CaptureEvents events(capture_clock);
  capture_tick() = 10000000;
  EXPECT_EQ(events.drain(true, false)[0].interval_ms, -1);
  EXPECT_EQ(events.drain(true, false)[0].interval_ms, 0);
  capture_tick() = -1;
  EXPECT_EQ(events.drain(true, false)[0].interval_ms, -1);
  capture_tick() = 20000000;
  EXPECT_EQ(events.drain(true, false)[0].interval_ms, -1);
  capture_tick() = 10000000;
  EXPECT_EQ(events.drain(true, false)[0].interval_ms, -1);
  capture_tick() = 30000000;
  EXPECT_EQ(events.drain(true, false)[0].interval_ms, -1);
  capture_tick() = 40000000;
  EXPECT_EQ(events.drain(true, false)[0].interval_ms, 10);
}
}  // namespace
