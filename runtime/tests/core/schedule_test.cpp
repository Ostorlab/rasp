/// Tests for check_interval, the monitoring thread's random wait.

#include "rasp/schedule.h"

#include <chrono>
#include <gtest/gtest.h>
#include <set>

namespace rasp {
namespace {

using std::chrono::milliseconds;
using std::chrono::seconds;

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

}  // namespace
}  // namespace rasp
