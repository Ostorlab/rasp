/// Controlled native-boundary tests for the iOS direct process-entry query.
#include "util/process_query.h"

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <span>

namespace rasp::ios::util {
namespace {

/// Exercises the production native-query transport with only the system-call instruction replaced.
struct QueryState {
  std::array<std::byte, 16> entry{};
  std::optional<std::uint64_t> pid = 1234;
  std::optional<std::uint64_t> result = 0;
  std::size_t returned_size = 16;
  int pid_calls = 0;
  int query_calls = 0;
};

class ProcessQuery : public ::testing::Test {
 protected:
  void SetUp() override { active = this; }
  void TearDown() override { active = nullptr; }

  /// Supplies native register results and a controlled returned byte count.
  static std::optional<std::uint64_t> invoke(std::uint64_t number, const std::array<std::uint64_t, 6>& arguments) {
    if (number == 20) {
      ++active->state_.pid_calls;
      return active->state_.pid;
    }
    EXPECT_EQ(number, 202U);
    EXPECT_EQ(arguments[1], 4U);
    EXPECT_EQ(arguments[4], 0U);
    EXPECT_EQ(arguments[5], 0U);
    ++active->state_.query_calls;
    const auto* const name = std::bit_cast<const std::array<int, 4>*>(arguments[0]);
    EXPECT_EQ(*name, (std::array<int, 4>{1, 14, 1, 1234}));
    auto* const size = std::bit_cast<std::size_t*>(arguments[3]);
    EXPECT_EQ(*size, active->state_.entry.size());
    *size = active->state_.returned_size;
    auto* const output = std::bit_cast<std::array<std::byte, 16>*>(arguments[2]);
    output->fill(std::byte{0x42});
    return active->state_.result;
  }

  /// Runs the same transport used by own_process_direct, with a small opaque native entry fixture.
  bool query() { return query_process({1, 14, 1, 0}, state_.entry, {.getpid = 20, .sysctl = 202}, invoke); }

  QueryState& state() { return state_; }

 private:
  QueryState state_;
  static thread_local ProcessQuery* active;
};
thread_local ProcessQuery* ProcessQuery::active = nullptr;

TEST_F(ProcessQuery, query_whenWholeEntryIsReturned_acceptsCompleteBytes) {
  EXPECT_TRUE(query());
  EXPECT_EQ(state().pid_calls, 1);
  EXPECT_EQ(state().query_calls, 1);
  EXPECT_EQ(state().entry[0], std::byte{0x42});
}

TEST_F(ProcessQuery, query_whenPidCallFails_doesNotQueryGuessedPid) {
  state().pid = std::nullopt;
  EXPECT_FALSE(query());
  EXPECT_EQ(state().query_calls, 0);
}

TEST_F(ProcessQuery, query_whenPidIsInvalid_rejectsBeforeNarrowing) {
  for (const std::uint64_t pid : {std::uint64_t{0}, std::uint64_t{2147483648}, UINT64_MAX}) {
    state().pid = pid;
    EXPECT_FALSE(query());
  }
  EXPECT_EQ(state().query_calls, 0);
}

TEST_F(ProcessQuery, query_whenKernelSetsCarry_reportsFailure) {
  state().result = std::nullopt;
  EXPECT_FALSE(query());
}

TEST_F(ProcessQuery, query_whenReturnValueIsNotZero_rejectsEntry) {
  state().result = 1;
  EXPECT_FALSE(query());
}

TEST_F(ProcessQuery, query_whenReturnedSizeIsShortOrOversized_rejectsPartialEntry) {
  for (const std::size_t size : {std::size_t{0}, std::size_t{15}, std::size_t{17}}) {
    state().returned_size = size;
    EXPECT_FALSE(query());
  }
}

TEST(ProcessQueryArchitecture, directSyscall_whenNotAppleArm64_reportsUnavailable) {
#if !defined(__APPLE__) || !defined(__aarch64__)
  EXPECT_EQ(direct_syscall(20, {}), std::nullopt);
#endif
}

}  // namespace
}  // namespace rasp::ios::util
