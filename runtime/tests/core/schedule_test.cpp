/// Tests for check_interval, the monitoring thread's random wait, and RateLimit.

#include "rasp/schedule.h"

#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <set>
#include <thread>
#include <vector>

namespace rasp {
namespace {

using std::chrono::milliseconds;
using std::chrono::seconds;
using std::chrono::steady_clock;

/// The interval of the rate limits under test.
constexpr seconds kInterval{1};

/// A time of the steady clock, `offset` after an arbitrary start.
///
/// @param offset How long after the start.
/// @return The time.
[[nodiscard]] steady_clock::time_point at(milliseconds offset) {
  return steady_clock::time_point{seconds{1000}} + offset;
}

TEST(Schedule, checkInterval_whenCalled_isWithinTheBounds) {
  for (int draw = 0; draw < 1000; ++draw) {
    const milliseconds interval = check_interval();
    EXPECT_GE(interval, kMinCheckInterval);
    EXPECT_LE(interval, kMaxCheckInterval);
  }
}

TEST(Schedule, checkInterval_whenCalledManyTimes_spreadsOverTheRange) {
  std::set<milliseconds> intervals;
  for (int draw = 0; draw < 1000; ++draw) {
    intervals.insert(check_interval());
  }
  EXPECT_GT(intervals.size(), 900U);
  EXPECT_LT(*intervals.begin(), kMinCheckInterval + seconds{10});
  EXPECT_GT(*intervals.rbegin(), kMaxCheckInterval - seconds{10});
}

TEST(RateLimit, tryAcquire_whenFirstCalled_letsThrough) {
  RateLimit limit{kInterval};
  EXPECT_TRUE(limit.try_acquire(at(milliseconds{0})));
}

TEST(RateLimit, tryAcquire_whenCalledWithinTheInterval_refuses) {
  RateLimit limit{kInterval};
  ASSERT_TRUE(limit.try_acquire(at(milliseconds{0})));
  EXPECT_FALSE(limit.try_acquire(at(milliseconds{0})));
  EXPECT_FALSE(limit.try_acquire(at(milliseconds{999})));
}

TEST(RateLimit, tryAcquire_whenTheIntervalHasPassed_letsThroughOnce) {
  RateLimit limit{kInterval};
  ASSERT_TRUE(limit.try_acquire(at(milliseconds{0})));
  EXPECT_TRUE(limit.try_acquire(at(milliseconds{1000})));
  EXPECT_FALSE(limit.try_acquire(at(milliseconds{1500})));
  EXPECT_TRUE(limit.try_acquire(at(milliseconds{5000})));
}

TEST(RateLimit, tryAcquire_whenARefusedCallCame_countsFromTheLastCallLetThrough) {
  RateLimit limit{kInterval};
  ASSERT_TRUE(limit.try_acquire(at(milliseconds{0})));
  ASSERT_FALSE(limit.try_acquire(at(milliseconds{900})));
  EXPECT_TRUE(limit.try_acquire(at(milliseconds{1000})));
}

TEST(RateLimit, tryAcquire_whenManyThreadsAskAtOnce_letsExactlyOneThrough) {
  RateLimit limit{kInterval};
  std::atomic<int> let_through{0};
  {
    std::vector<std::jthread> threads;
    threads.reserve(16);
    for (int thread = 0; thread < 16; ++thread) {
      threads.emplace_back([&limit, &let_through] {
        for (int call = 0; call < 1000; ++call) {
          if (limit.try_acquire(at(milliseconds{call % 500}))) {
            let_through.fetch_add(1);
          }
        }
      });
    }
  }
  EXPECT_EQ(let_through.load(), 1);
}

}  // namespace
}  // namespace rasp
