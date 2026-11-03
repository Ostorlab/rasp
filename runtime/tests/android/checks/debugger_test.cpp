/// Tests for the Android debugger checks.

#include "checks/debugger.h"

#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "rasp/observation.h"
#include "support/files.h"

namespace rasp::android::checks {
namespace {

using test_support::TemporaryDirectory;
using test_support::write_file;

/// The size limit of the status file, 64 KiB.
constexpr std::size_t kStatusLimit = std::size_t{64} << 10U;

/// The lines of an app's status file before its TracerPid line.
constexpr std::string_view kStatusHead =
    "Name:\tco.ostorlab.app\n"
    "Umask:\t0077\n"
    "State:\tS (sleeping)\n"
    "Tgid:\t4321\n"
    "Ngid:\t0\n"
    "Pid:\t4321\n"
    "PPid:\t612\n";

/// The lines of an app's status file after its TracerPid line.
constexpr std::string_view kStatusTail =
    "Uid:\t10187\t10187\t10187\t10187\n"
    "Gid:\t10187\t10187\t10187\t10187\n"
    "FDSize:\t256\n"
    "VmRSS:\t  152412 kB\n"
    "Threads:\t31\n";

/// A status file whose TracerPid line is `line`.
[[nodiscard]] std::string status_with(std::string_view line) {
  return std::string(kStatusHead) + std::string(line) + "\n" + std::string(kStatusTail);
}

/// The dbg.tracer_pid observations, through proc_status and through proc_status_syscall, that both report `pid`.
[[nodiscard]] std::vector<Observation> tracer_pid(std::int64_t pid) {
  return {
      {.signal = "dbg.tracer_pid", .source = "proc_status", .status = Status::kOk, .value = pid},
      {.signal = "dbg.tracer_pid", .source = "proc_status_syscall", .status = Status::kOk, .value = pid},
  };
}

/// The dbg.tracer_pid observations, through both sources, of a status file that couldn't be read or understood.
[[nodiscard]] std::vector<Observation> unreadable_tracer_pid() {
  return {
      {.signal = "dbg.tracer_pid", .source = "proc_status", .status = Status::kError, .value = {}},
      {.signal = "dbg.tracer_pid", .source = "proc_status_syscall", .status = Status::kError, .value = {}},
  };
}

TEST(Debugger, observeTracerPid_whenNothingIsAttached_reportsZero) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string status = directory.path() + "/status";
  ASSERT_TRUE(write_file(status, status_with("TracerPid:\t0")));

  EXPECT_EQ(observe_tracer_pid(status), tracer_pid(0));
}

TEST(Debugger, observeTracerPid_whenADebuggerIsAttached_reportsItsProcessId) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string status = directory.path() + "/status";
  ASSERT_TRUE(write_file(status, status_with("TracerPid:\t8812")));

  EXPECT_EQ(observe_tracer_pid(status), tracer_pid(8812));
}

TEST(Debugger, observeTracerPid_whenTheValueIsAfterSpaces_reportsIt) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string status = directory.path() + "/status";
  ASSERT_TRUE(write_file(status, status_with("TracerPid: \t 8812")));

  EXPECT_EQ(observe_tracer_pid(status), tracer_pid(8812));
}

TEST(Debugger, observeTracerPid_whenTheLineIsLastWithoutALineBreak_reportsIt) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string status = directory.path() + "/status";
  ASSERT_TRUE(write_file(status, std::string(kStatusHead) + "TracerPid:\t8812"));

  EXPECT_EQ(observe_tracer_pid(status), tracer_pid(8812));
}

TEST(Debugger, observeTracerPid_whenTheFileHasTwoTracerPidLines_reportsTheFirst) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string status = directory.path() + "/status";
  ASSERT_TRUE(write_file(status, status_with("TracerPid:\t8812\nTracerPid:\t0")));

  EXPECT_EQ(observe_tracer_pid(status), tracer_pid(8812));
}

TEST(Debugger, observeTracerPid_whenTheProcessIdIsTheLargest32BitValue_reportsIt) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string status = directory.path() + "/status";
  ASSERT_TRUE(write_file(status, status_with("TracerPid:\t4294967295")));

  EXPECT_EQ(observe_tracer_pid(status), tracer_pid(4294967295));
}

/// A TracerPid line that doesn't hold a process id.
class DebuggerMalformedTracerPidLine : public ::testing::TestWithParam<std::string_view> {};

TEST_P(DebuggerMalformedTracerPidLine, observeTracerPid_whenTheLineHoldsNoProcessId_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string status = directory.path() + "/status";
  ASSERT_TRUE(write_file(status, status_with(GetParam())));

  EXPECT_EQ(observe_tracer_pid(status), unreadable_tracer_pid());
}

INSTANTIATE_TEST_SUITE_P(Debugger, DebuggerMalformedTracerPidLine,
                         ::testing::Values("TracerPid:", "TracerPid:\t", "TracerPid:\t-1", "TracerPid:\t+1",
                                           "TracerPid:\tabc", "TracerPid:\t12a", "TracerPid:\t12 ",
                                           "TracerPid:\t4294967296", "TracerPid:\t0x10"));

TEST(Debugger, observeTracerPid_whenTheFileHasNoTracerPidLine_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string status = directory.path() + "/status";
  ASSERT_TRUE(
      write_file(status, std::string(kStatusHead) + "tracerpid:\t0\n Tracerpid:\t0\n" + std::string(kStatusTail)));

  EXPECT_EQ(observe_tracer_pid(status), unreadable_tracer_pid());
}

TEST(Debugger, observeTracerPid_whenTheFileIsEmpty_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string status = directory.path() + "/status";
  ASSERT_TRUE(write_file(status, ""));

  EXPECT_EQ(observe_tracer_pid(status), unreadable_tracer_pid());
}

TEST(Debugger, observeTracerPid_whenTheFileIsExactly64KiB_readsItWhole) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string status = directory.path() + "/status";
  const std::string last = "TracerPid:\t8812";
  const std::string content = std::string(kStatusLimit - last.size() - 1, 'a') + "\n" + last;
  ASSERT_EQ(content.size(), kStatusLimit);
  ASSERT_TRUE(write_file(status, content));

  EXPECT_EQ(observe_tracer_pid(status), tracer_pid(8812));
}

TEST(Debugger, observeTracerPid_whenTheFileIsLargerThan64KiB_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string status = directory.path() + "/status";
  const std::string last = "TracerPid:\t8812";
  ASSERT_TRUE(write_file(status, std::string(kStatusLimit - last.size(), 'a') + "\n" + last));

  EXPECT_EQ(observe_tracer_pid(status), unreadable_tracer_pid());
}

TEST(Debugger, observeTracerPid_whenTheFileIsMissing_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());

  EXPECT_EQ(observe_tracer_pid(directory.path() + "/missing"), unreadable_tracer_pid());
}

TEST(Debugger, observeTracerPid_whenTheFileCantBeRead_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());

  EXPECT_EQ(observe_tracer_pid(directory.path()), unreadable_tracer_pid());
}

TEST(Debugger, observeJavaDebugger_whenADebuggerIsConnected_reportsTrue) {
  EXPECT_EQ(
      observe_java_debugger(true),
      (Observation{
          .signal = "dbg.java_debugger", .source = "is_debugger_connected", .status = Status::kOk, .value = true}));
}

TEST(Debugger, observeJavaDebugger_whenNoDebuggerIsConnected_reportsFalse) {
  EXPECT_EQ(
      observe_java_debugger(false),
      (Observation{
          .signal = "dbg.java_debugger", .source = "is_debugger_connected", .status = Status::kOk, .value = false}));
}

TEST(Debugger, observeJavaDebugger_whenTheVmCouldntBeAsked_reportsAnError) {
  EXPECT_EQ(
      observe_java_debugger(std::nullopt),
      (Observation{
          .signal = "dbg.java_debugger", .source = "is_debugger_connected", .status = Status::kError, .value = {}}));
}

TEST(Debugger, debugger_whenOffAndroid_reportsEveryCheckAsUnsupported) {
  EXPECT_EQ(
      debugger(),
      (std::vector<Observation>{
          {.signal = "dbg.tracer_pid", .source = "proc_status", .status = Status::kUnsupported, .value = {}},
          {.signal = "dbg.tracer_pid", .source = "proc_status_syscall", .status = Status::kUnsupported, .value = {}},
          {.signal = "dbg.java_debugger",
           .source = "is_debugger_connected",
           .status = Status::kUnsupported,
           .value = {}},
      }));
}

}  // namespace
}  // namespace rasp::android::checks
