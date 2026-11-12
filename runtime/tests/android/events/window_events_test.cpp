#include "events/window_events.h"

#include <atomic>
#include <cstdint>
#include <gtest/gtest.h>
#include <thread>

namespace {

struct TouchBatch {
  int count;
  int flags;
};

void expect_touches(rasp::android::events::WindowEvents& events, std::int64_t session, TouchBatch batch) {
  bool accepted = true;
  for (int index = 0; index < batch.count; ++index) {
    accepted = events.push(session, 1, 3, batch.flags) && accepted;
  }
  EXPECT_TRUE(accepted);
}

void expect_counts(const rasp::android::events::WindowSnapshot& snapshot, std::int64_t touches, std::int64_t obscured,
                   std::int64_t partial, std::int64_t dropped) {
  EXPECT_EQ(snapshot.touch_events, touches);
  EXPECT_EQ(snapshot.obscured_touch_events, obscured);
  EXPECT_EQ(snapshot.partially_obscured_touch_events, partial);
  EXPECT_EQ(snapshot.dropped_events, dropped);
}

}  // namespace

TEST(WindowEvents, drain_whenOverflow_keepsBoundsAndReportsLoss) {
  rasp::android::events::WindowEvents events;
  const auto session = events.start();
  ASSERT_TRUE(events.push(session, 1, 1, 0));
  expect_touches(events, session, {.count = 200, .flags = 3});
  const auto snapshot = events.drain();
  EXPECT_EQ(snapshot.active_windows, 1);
  expect_counts(snapshot, 127, 127, 127, 73);
  EXPECT_EQ(events.drain().touch_events, 0);
}

TEST(WindowEvents, push_whenMalformedOrStale_countsUnknownWithoutPublishingTouch) {
  rasp::android::events::WindowEvents events;
  const auto session = events.start();
  ASSERT_TRUE(events.push(session, 4, 1, 0));
  EXPECT_FALSE(events.push(0, 4, 3, 0));
  EXPECT_FALSE(events.push(session, -4, 3, 0));
  EXPECT_FALSE(events.push(session, 4, 3, -1));
  EXPECT_FALSE(events.push(session, 4, 3, 4));
  EXPECT_FALSE(events.push(session, 4, 1, 0));
  EXPECT_FALSE(events.push(session, 9, 3, 0));
  EXPECT_FALSE(events.push(session, 4, 6, 0));
  EXPECT_FALSE(events.push(session, 4, 2, 1));
  EXPECT_FALSE(events.push(session, 4, 5, 0));
  const auto snapshot = events.drain();
  EXPECT_EQ(snapshot.invalid_events, 9);
  EXPECT_EQ(snapshot.active_windows, 1);
  EXPECT_EQ(snapshot.touch_events, 0);
  EXPECT_EQ(snapshot.interval_ms, -1);
  events.stop(session, rasp::android::events::ObserverState::kDeactivated);
  EXPECT_FALSE(events.push(session, 4, 3, 1));
  const auto next = events.start();
  EXPECT_NE(session, next);
  events.stop(session, rasp::android::events::ObserverState::kDeactivated);
  EXPECT_TRUE(events.push(next, 4, 1, 0));
  EXPECT_EQ(events.drain().state, rasp::android::events::ObserverState::kActive);
}

TEST(WindowEvents, push_whenWindowTableFull_reportsLossWithoutInventingWindow) {
  rasp::android::events::WindowEvents events;
  const auto session = events.start();
  bool opened = true;
  for (int token = 1; token <= 32; ++token) {
    opened = events.push(session, token, 1, 0) && opened;
  }
  EXPECT_TRUE(opened);
  EXPECT_FALSE(events.push(session, 33, 1, 0));
  const auto snapshot = events.drain();
  EXPECT_EQ(snapshot.active_windows, 32);
  EXPECT_EQ(snapshot.lost_windows, 1);
  EXPECT_EQ(events.drain().lost_windows, 0);
}

TEST(WindowEvents, push_whenQueueFull_keepsCurrentStateAndLossMetadata) {
  rasp::android::events::WindowEvents events;
  const auto session = events.start();
  ASSERT_TRUE(events.push(session, 1, 1, 0));
  ASSERT_TRUE(events.push(session, 2, 1, 0));
  expect_touches(events, session, {.count = 128, .flags = 0});
  EXPECT_TRUE(events.push(session, 1, 4, 0));
  EXPECT_TRUE(events.push(session, 2, 2, 0));
  const auto snapshot = events.drain();
  EXPECT_EQ(snapshot.active_windows, 0);
  EXPECT_EQ(snapshot.lost_windows, 1);
  expect_counts(snapshot, 126, 0, 0, 4);
  EXPECT_GE(events.drain().interval_ms, 0);
}

TEST(WindowEvents, drain_whenConcurrent_preservesAllAcceptedOrDroppedEvents) {
  rasp::android::events::WindowEvents events;
  const auto session = events.start();
  ASSERT_TRUE(events.push(session, 1, 1, 0));
  static_cast<void>(events.drain());
  std::atomic<bool> finished{false};
  std::int64_t total = 0;
  std::thread reader([&] {
    while (!finished.load()) {
      const auto snapshot = events.drain();
      total += snapshot.touch_events + snapshot.dropped_events;
    }
  });
  bool accepted = true;
  for (int index = 0; index < 10000; ++index) {
    accepted = events.push(session, 1, 3, 3) && accepted;
  }
  finished.store(true);
  reader.join();
  EXPECT_TRUE(accepted);
  const auto last = events.drain();
  EXPECT_EQ(total + last.touch_events + last.dropped_events, 10000);
  events.stop(session, rasp::android::events::ObserverState::kError);
  EXPECT_EQ(events.drain().active_windows, 0);
  EXPECT_EQ(events.drain().state, rasp::android::events::ObserverState::kError);
}
