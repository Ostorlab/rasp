/// Tests for bounded file reads through the libc syscall entry.

#include "util/direct_syscall.h"

#include <array>
#include <bit>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <sys/syscall.h>
#include <utility>
#include <vector>

#include "support/files.h"

namespace rasp::android::util {
namespace {

/// One controlled result at the native boundary.
struct ReadStep {
  long count;
  int error = 0;
};

/// A controlled native boundary; the parser and resource ownership stay in production code.
struct BoundaryState {
  SyscallResult opened{.value = 42, .error = 0};
  SyscallResult closed{.value = 0, .error = 0};
  SyscallResult access{.value = 0, .error = 0};
  std::vector<ReadStep> steps;
  std::size_t position = 0;
  int opens = 0;
  int closes = 0;
  int reads = 0;
  std::uintptr_t open_flags = 0;
};

class DirectSyscallBoundary : public ::testing::Test {
 protected:
  void SetUp() override { active = this; }
  void TearDown() override { active = nullptr; }

  /// Simulates only openat/read/close/faccessat, recording resource ownership and request bounds.
  static SyscallResult invoke(long number, const std::array<std::uintptr_t, 4>& arguments) {
    if (number == SYS_openat) {
      ++active->state_.opens;
      active->state_.open_flags = arguments[2];
      return active->state_.opened;
    }
    if (number == SYS_close) {
      ++active->state_.closes;
      EXPECT_EQ(arguments[0], 42U);
      return active->state_.closed;
    }
    if (number == SYS_faccessat) {
      return active->state_.access;
    }
    EXPECT_EQ(number, SYS_read);
    ++active->state_.reads;
    EXPECT_EQ(arguments[0], 42U);
    EXPECT_LE(arguments[2], 1024U);
    if (active->state_.position >= active->state_.steps.size()) {
      return {.value = 0, .error = 0};
    }
    const ReadStep step = active->state_.steps[active->state_.position++];
    if (step.count > 0 && std::cmp_less_equal(step.count, arguments[2])) {
      std::memset(std::bit_cast<void*>(arguments[1]), 'x', static_cast<std::size_t>(step.count));
    }
    return {.value = step.count, .error = step.error};
  }

  BoundaryState& state() { return state_; }

 private:
  BoundaryState state_;
  static thread_local DirectSyscallBoundary* active;
};

thread_local DirectSyscallBoundary* DirectSyscallBoundary::active = nullptr;

TEST_F(DirectSyscallBoundary, readFile_whenReadIsShort_continuesUntilEofAndClosesOnce) {
  state().steps = {{.count = 1}, {.count = -1, .error = EINTR}, {.count = 2}, {.count = 1}};
  EXPECT_EQ(read_file_direct("fixture", 4, invoke), "xxxx");
  EXPECT_EQ(state().closes, 1);
  EXPECT_NE(state().open_flags & O_CLOEXEC, 0U);
  EXPECT_NE(state().open_flags & O_NONBLOCK, 0U);
}

TEST_F(DirectSyscallBoundary, readFile_whenCountExceedsBuffer_rejectsAndClosesOnce) {
  state().steps = {{.count = 1025}};
  EXPECT_EQ(read_file_direct("fixture", 4096, invoke), std::nullopt);
  EXPECT_EQ(state().closes, 1);
}

TEST_F(DirectSyscallBoundary, readFile_whenReadFailsAfterPartialData_rejectsWholeContent) {
  state().steps = {{.count = 1}, {.count = -1, .error = EIO}};
  EXPECT_EQ(read_file_direct("fixture", 4, invoke), std::nullopt);
  EXPECT_EQ(state().closes, 1);
}

TEST_F(DirectSyscallBoundary, readFile_whenReadIsRepeatedlyInterrupted_stopsWithError) {
  state().steps.assign(20, {.count = -1, .error = EINTR});
  EXPECT_EQ(read_file_direct("fixture", 4, invoke), std::nullopt);
  EXPECT_EQ(state().reads, 9);
  EXPECT_EQ(state().closes, 1);
}

TEST_F(DirectSyscallBoundary, readFile_whenCloseIsInterrupted_doesNotRetryDescriptor) {
  state().steps = {{.count = 1}};
  state().closed = {.value = -1, .error = EINTR};
  EXPECT_EQ(read_file_direct("fixture", 4, invoke), std::nullopt);
  EXPECT_EQ(state().closes, 1);
}

TEST_F(DirectSyscallBoundary, readFile_whenOpenIsDenied_doesNotReadOrClose) {
  state().opened = {.value = -1, .error = EACCES};
  EXPECT_EQ(read_file_direct("fixture", 4, invoke), std::nullopt);
  EXPECT_EQ(state().reads, 0);
  EXPECT_EQ(state().closes, 0);
}

TEST_F(DirectSyscallBoundary, readFile_whenLimitIsExceeded_rejectsAndClosesOnce) {
  state().steps = {{.count = 5}};
  EXPECT_EQ(read_file_direct("fixture", 4, invoke), std::nullopt);
  EXPECT_EQ(state().closes, 1);
}

TEST_F(DirectSyscallBoundary, readFile_whenLimitIsTooLarge_doesNotOpen) {
  EXPECT_EQ(read_file_direct("fixture", (std::size_t{4} << 20U) + 1, invoke), std::nullopt);
  EXPECT_EQ(state().opens, 0);
}

TEST_F(DirectSyscallBoundary, exists_whenDeniedOrUnexpectedError_reportsUnavailable) {
  for (const int error : {EACCES, EPERM, EIO, EINTR, ENOSYS}) {
    state().access = {.value = -1, .error = error};
    EXPECT_EQ(exists_direct("fixture", invoke), std::nullopt);
  }
  state().access = {.value = 1, .error = 0};
  EXPECT_EQ(exists_direct("fixture", invoke), std::nullopt);
}

TEST_F(DirectSyscallBoundary, exists_whenMissingOrPresent_preservesRawValue) {
  EXPECT_EQ(exists_direct("fixture", invoke), true);
  for (const int error : {ENOENT, ENOTDIR}) {
    state().access = {.value = -1, .error = error};
    EXPECT_EQ(exists_direct("fixture", invoke), false);
  }
}

TEST_F(DirectSyscallBoundary, exists_whenPathHasNull_doesNotAliasPrefix) {
  EXPECT_EQ(exists_direct(std::string("fixture\0tail", 12), invoke), std::nullopt);
}

#ifdef __linux__
TEST(DirectSyscall, readFile_whenExactLimit_readsWholeFile) {
  const test_support::TemporaryDirectory directory;
  const std::string path = directory.path() + "/data";
  ASSERT_TRUE(test_support::write_file(path, "hello"));
  EXPECT_EQ(read_file_direct(path, 5), "hello");
  EXPECT_EQ(read_file_direct(path, 4), std::nullopt);
}
#else
TEST(DirectSyscall, nativeBoundary_whenHostIsNotLinux_reportsUnavailable) {
  const auto result = libc_syscall(0, {});
  EXPECT_EQ(result.value, -1);
  EXPECT_EQ(result.error, ENOSYS);
  EXPECT_EQ(read_file_direct("/", 5), std::nullopt);
  EXPECT_EQ(exists_direct("/"), std::nullopt);
}
#endif

TEST(DirectSyscall, readFile_whenPathContainsNull_rejectsPrefixAlias) {
  const test_support::TemporaryDirectory directory;
  const std::string path = directory.path() + "/data";
  ASSERT_TRUE(test_support::write_file(path, "hello"));
  EXPECT_EQ(read_file_direct(path + std::string("\0suffix", 7), 20), std::nullopt);
}

}  // namespace
}  // namespace rasp::android::util
