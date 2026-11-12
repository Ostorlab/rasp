/// Tests the actual shared POSIX sampling path, including system-call failures.
#include "rasp/posix/cycle_clock.h"

#include <cstdint>
#include <gtest/gtest.h>
#include <limits>

namespace {
TEST(CycleClock, sample_whenSystemCallsFail_keepsBothClocksUnavailable) {
  const auto reading = rasp::posix::read_cycle_clock([](auto, auto*) { return -1; });
  EXPECT_FALSE(reading.monotonic_ns.has_value());
  EXPECT_FALSE(reading.unix_ms.has_value());
}

TEST(CycleClock, sample_whenSystemReturnsInvalidFields_doesNotInventTimes) {
  const auto reading = rasp::posix::read_cycle_clock([](auto, auto* sample) {
    sample->tv_sec = -1;
    sample->tv_nsec = 1000000000;
    return 0;
  });
  EXPECT_FALSE(reading.monotonic_ns.has_value());
  EXPECT_FALSE(reading.unix_ms.has_value());
}

TEST(CycleClock, ticks_whenZeroOrMaximumValid_preservesMeasuredBoundaries) {
  EXPECT_EQ(rasp::posix::monotonic_ticks({.tv_sec = 0, .tv_nsec = 0}), 0);
  EXPECT_EQ(rasp::posix::monotonic_ticks({.tv_sec = 9223372036, .tv_nsec = 854775807}),
            std::numeric_limits<std::int64_t>::max());
  EXPECT_FALSE(rasp::posix::monotonic_ticks({.tv_sec = 9223372036, .tv_nsec = 854775808}).has_value());
}

TEST(CycleClock, ticks_whenMalformedOrOverflowing_reportsUnavailable) {
  EXPECT_FALSE(rasp::posix::monotonic_ticks({.tv_sec = -1, .tv_nsec = 0}).has_value());
  EXPECT_FALSE(rasp::posix::monotonic_ticks({.tv_sec = 0, .tv_nsec = -1}).has_value());
  EXPECT_FALSE(rasp::posix::monotonic_ticks({.tv_sec = 0, .tv_nsec = 1000000000}).has_value());
  EXPECT_FALSE(rasp::posix::monotonic_ticks({.tv_sec = 9223372037, .tv_nsec = 0}).has_value());
}

TEST(CycleClock, sample_whenWallUpperBoundaryReached_omitsWallWhileKeepingMonotonic) {
  const auto reading = rasp::posix::read_cycle_clock([](auto, auto* sample) {
    sample->tv_sec = 4102444800;
    sample->tv_nsec = 0;
    return 0;
  });
  EXPECT_TRUE(reading.monotonic_ns.has_value());
  EXPECT_FALSE(reading.unix_ms.has_value());
}
}  // namespace
