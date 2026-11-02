/// Tests for Context, the values the plugins share, and Key, the name and the type of one of them.

#include "rasp/context.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace rasp::plugins {
namespace {

/// The key of a text.
constexpr Key<std::string> kText{.name = "test.text"};
/// A key with the name of kText and another type.
constexpr Key<std::int64_t> kTextAsNumber{.name = "test.text"};
/// The key of a number.
constexpr Key<std::int64_t> kNumber{.name = "test.number"};
/// The key of the lists of numbers the concurrent test shares between its threads.
constexpr Key<std::vector<std::int64_t>> kNumbers{.name = "test.numbers"};

/// How many lists each thread of the concurrent test puts, gets or takes.
constexpr int kCallsPerThread = 2000;
/// How many threads of the concurrent test put lists. One more gets them, and one more takes them.
constexpr std::size_t kWriters = 4;
/// How many numbers each list of the concurrent test holds.
constexpr std::size_t kListSize = 64;

/// Whether a list is one of those the concurrent test puts.
///
/// @param numbers The list.
/// @return `true` when it holds kListSize numbers, all equal.
[[nodiscard]] bool whole(const std::vector<std::int64_t>& numbers) {
  return numbers.size() == kListSize &&
         std::ranges::adjacent_find(numbers, std::ranges::not_equal_to{}) == numbers.end();
}

TEST(Context, get_whenAValueWasPut_returnsACopyAndKeepsTheValue) {
  Context context;
  context.put(kText, "hello");

  const std::optional<std::string> first = context.get(kText);
  const std::optional<std::string> second = context.get(kText);

  EXPECT_EQ(first, "hello");
  EXPECT_EQ(second, "hello");
}

TEST(Context, get_whenNoValueHasTheName_returnsNothing) {
  Context context;
  context.put(kNumber, 7);

  EXPECT_EQ(context.get(kText), std::nullopt);
}

TEST(Context, get_whenTheValueHasAnotherType_returnsNothing) {
  Context context;
  context.put(kText, "hello");

  EXPECT_EQ(context.get(kTextAsNumber), std::nullopt);
}

TEST(Context, take_whenAValueWasPut_returnsItAndRemovesIt) {
  Context context;
  context.put(kText, "hello");

  const std::optional<std::string> taken = context.take(kText);

  EXPECT_EQ(taken, "hello");
  EXPECT_EQ(context.get(kText), std::nullopt);
}

TEST(Context, take_whenTheValueHasAnotherType_returnsNothingAndKeepsTheValue) {
  Context context;
  context.put(kText, "hello");

  const std::optional<std::int64_t> taken = context.take(kTextAsNumber);

  EXPECT_EQ(taken, std::nullopt);
  EXPECT_EQ(context.get(kText), "hello");
}

TEST(Context, put_whenAValueHasTheSameName_replacesIt) {
  Context context;
  context.put(kText, "first");

  context.put(kText, "second");

  EXPECT_EQ(context.get(kText), "second");
}

TEST(Context, get_whenAnotherThreadPutTheValue_returnsIt) {
  Context context;

  std::thread writer([&context] { context.put(kText, "put by another thread"); });
  writer.join();

  EXPECT_EQ(context.get(kText), "put by another thread");
}

TEST(Context, putGetAndTake_whenCalledFromManyThreadsAtOnce_returnOnlyWholeValues) {
  Context context;
  int broken_gets = 0;
  int broken_takes = 0;
  std::vector<std::thread> threads;
  threads.reserve(kWriters + 2);

  for (std::size_t writer = 0; writer < kWriters; ++writer) {
    threads.emplace_back([&context, writer] {
      for (int call = 0; call < kCallsPerThread; ++call) {
        context.put(kNumbers, std::vector<std::int64_t>(kListSize, static_cast<std::int64_t>(writer)));
      }
    });
  }
  threads.emplace_back([&context, &broken_gets] {
    for (int call = 0; call < kCallsPerThread; ++call) {
      const std::optional<std::vector<std::int64_t>> numbers = context.get(kNumbers);
      if (numbers.has_value() && !whole(*numbers)) {
        ++broken_gets;
      }
    }
  });
  threads.emplace_back([&context, &broken_takes] {
    for (int call = 0; call < kCallsPerThread; ++call) {
      const std::optional<std::vector<std::int64_t>> numbers = context.take(kNumbers);
      if (numbers.has_value() && !whole(*numbers)) {
        ++broken_takes;
      }
    }
  });
  for (std::thread& thread : threads) {
    thread.join();
  }

  EXPECT_EQ(broken_gets, 0);
  EXPECT_EQ(broken_takes, 0);
}

}  // namespace
}  // namespace rasp::plugins
