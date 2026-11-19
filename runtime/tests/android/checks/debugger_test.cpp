/// Tests for the Android debugger checks.

#include "checks/debugger.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <gtest/gtest.h>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "rasp/observation.h"
#include "rasp/util/read_file.h"
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

/// The dbg.tracer_pid observation that reports `pid`.
[[nodiscard]] Observation tracer_pid(std::int64_t pid) {
  return {.signal = "dbg.tracer_pid", .source = "proc_status", .status = Status::kOk, .value = pid};
}

/// The dbg.tracer_pid observation that reports `pid`, read through libc.
[[nodiscard]] Observation tracer_pid_libc(std::int64_t pid) {
  return {.signal = "dbg.tracer_pid", .source = "proc_status_libc", .status = Status::kOk, .value = pid};
}

/// The dbg.tracer_pid observation of a status file that couldn't be read or understood.
[[nodiscard]] Observation unreadable_tracer_pid() {
  return {.signal = "dbg.tracer_pid", .source = "proc_status", .status = Status::kError, .value = {}};
}

TEST(Debugger, observeTracerPid_whenNothingIsAttached_reportsZero) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string status = directory.path() + "/status";
  ASSERT_TRUE(write_file(status, status_with("TracerPid:\t0")));

  EXPECT_EQ(observe_tracer_pid(status, rasp::util::read_file), tracer_pid(0));
}

TEST(Debugger, observeTracerPidLibc_whenNothingIsAttached_reportsZeroThroughADifferentSource) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string status = directory.path() + "/status";
  ASSERT_TRUE(write_file(status, status_with("TracerPid:\t0")));

  const Observation direct = observe_tracer_pid(status, rasp::util::read_file);
  const Observation libc = observe_tracer_pid_libc(status);

  EXPECT_EQ(direct, tracer_pid(0));
  EXPECT_EQ(libc, tracer_pid_libc(0));
}

#if defined(__linux__) && (defined(__x86_64__) || defined(__aarch64__))
TEST(Debugger, observeTracerPid_whenBothProductionReadersReadTheRealStatusFile_agreeOnTheTracer) {
  // Neither probe is given a reader: the direct-system-call probe and the libc probe each read the kernel's own status
  // file the way the shipped runtime does. Both must read it, and both must name the same tracer, or the disagreement
  // panic reports when something answers one of them has no clean baseline to stand on. The direct reader exists only
  // on Linux x86_64 and aarch64; anywhere else both probes would read through libc and compare nothing.
  const Observation direct = observe_tracer_pid("/proc/self/status");
  const Observation libc = observe_tracer_pid_libc("/proc/self/status");

  ASSERT_EQ(direct.status, Status::kOk);
  ASSERT_EQ(libc.status, Status::kOk);
  EXPECT_EQ(direct.value, libc.value);
}
#endif

TEST(Debugger, observeTracerPidLibc_whenADebuggerIsAttached_reportsItsProcessId) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string status = directory.path() + "/status";
  ASSERT_TRUE(write_file(status, status_with("TracerPid:\t5771")));

  EXPECT_EQ(observe_tracer_pid_libc(status), tracer_pid_libc(5771));
}

TEST(Debugger, observeTracerPid_whenADebuggerIsAttached_reportsItsProcessId) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string status = directory.path() + "/status";
  ASSERT_TRUE(write_file(status, status_with("TracerPid:\t8812")));

  EXPECT_EQ(observe_tracer_pid(status, rasp::util::read_file), tracer_pid(8812));
}

TEST(Debugger, observeTracerPid_whenTheValueIsAfterSpaces_reportsIt) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string status = directory.path() + "/status";
  ASSERT_TRUE(write_file(status, status_with("TracerPid: \t 8812")));

  EXPECT_EQ(observe_tracer_pid(status, rasp::util::read_file), tracer_pid(8812));
}

TEST(Debugger, observeTracerPid_whenTheLineIsLastWithoutALineBreak_reportsIt) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string status = directory.path() + "/status";
  ASSERT_TRUE(write_file(status, std::string(kStatusHead) + "TracerPid:\t8812"));

  EXPECT_EQ(observe_tracer_pid(status, rasp::util::read_file), tracer_pid(8812));
}

TEST(Debugger, observeTracerPid_whenTheFileHasTwoTracerPidLines_reportsTheFirst) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string status = directory.path() + "/status";
  ASSERT_TRUE(write_file(status, status_with("TracerPid:\t8812\nTracerPid:\t0")));

  EXPECT_EQ(observe_tracer_pid(status, rasp::util::read_file), tracer_pid(8812));
}

TEST(Debugger, observeTracerPid_whenTheProcessIdIsTheLargest32BitValue_reportsIt) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string status = directory.path() + "/status";
  ASSERT_TRUE(write_file(status, status_with("TracerPid:\t4294967295")));

  EXPECT_EQ(observe_tracer_pid(status, rasp::util::read_file), tracer_pid(4294967295));
}

/// A TracerPid line that doesn't hold a process id.
class DebuggerMalformedTracerPidLine : public ::testing::TestWithParam<std::string_view> {};

TEST_P(DebuggerMalformedTracerPidLine, observeTracerPid_whenTheLineHoldsNoProcessId_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string status = directory.path() + "/status";
  ASSERT_TRUE(write_file(status, status_with(GetParam())));

  EXPECT_EQ(observe_tracer_pid(status, rasp::util::read_file), unreadable_tracer_pid());
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

  EXPECT_EQ(observe_tracer_pid(status, rasp::util::read_file), unreadable_tracer_pid());
}

TEST(Debugger, observeTracerPid_whenTheFileIsEmpty_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string status = directory.path() + "/status";
  ASSERT_TRUE(write_file(status, ""));

  EXPECT_EQ(observe_tracer_pid(status, rasp::util::read_file), unreadable_tracer_pid());
}

TEST(Debugger, observeTracerPid_whenTheFileIsExactly64KiB_readsItWhole) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string status = directory.path() + "/status";
  const std::string last = "TracerPid:\t8812";
  const std::string content = std::string(kStatusLimit - last.size() - 1, 'a') + "\n" + last;
  ASSERT_EQ(content.size(), kStatusLimit);
  ASSERT_TRUE(write_file(status, content));

  EXPECT_EQ(observe_tracer_pid(status, rasp::util::read_file), tracer_pid(8812));
}

TEST(Debugger, observeTracerPid_whenTheFileIsLargerThan64KiB_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string status = directory.path() + "/status";
  const std::string last = "TracerPid:\t8812";
  ASSERT_TRUE(write_file(status, std::string(kStatusLimit - last.size(), 'a') + "\n" + last));

  EXPECT_EQ(observe_tracer_pid(status, rasp::util::read_file), unreadable_tracer_pid());
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

/// A thread of a test thread folder: its id and the content of its name file.
struct Thread {
  /// The thread's id, the name of its folder.
  std::string_view id;
  /// The content of the thread's name file.
  std::string_view comm;
};

/// Creates under `task_path` a folder for each thread of `threads`, holding its name file.
[[nodiscard]] bool write_threads(const std::string& task_path, std::initializer_list<Thread> threads) {
  for (const Thread& thread : threads) {
    const std::string folder = task_path + "/" + std::string(thread.id);
    std::error_code error;
    if (!std::filesystem::create_directories(folder, error) || !write_file(folder + "/comm", thread.comm)) {
      return false;
    }
  }
  return true;
}

/// The dbg.java_debugger observation that reports whether a JDWP thread was `found`.
[[nodiscard]] Observation jdwp_threads(bool found) {
  return {.signal = "dbg.java_debugger", .source = "jdwp_threads", .status = Status::kOk, .value = found};
}

/// The dbg.java_debugger observation of a thread folder that couldn't be read.
[[nodiscard]] Observation unreadable_jdwp_threads() {
  return {.signal = "dbg.java_debugger", .source = "jdwp_threads", .status = Status::kError, .value = {}};
}

TEST(Debugger, observeJdwpThreads_whenTheAppCantBeDebugged_reportsFalse) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  ASSERT_TRUE(write_threads(directory.path(), {{"4321", "co.ostorlab.app\n"}, {"4330", "RenderThread\n"}}));

  EXPECT_EQ(observe_jdwp_threads(directory.path(), rasp::util::read_file), jdwp_threads(false));
}

TEST(Debugger, observeJdwpThreads_whenTheAppCanBeDebugged_reportsTrue) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  ASSERT_TRUE(write_threads(directory.path(), {{"4321", "co.ostorlab.app\n"}, {"4334", "ADB-JDWP Connec\n"}}));

  EXPECT_EQ(observe_jdwp_threads(directory.path(), rasp::util::read_file), jdwp_threads(true));
}

TEST(Debugger, observeJdwpThreads_whenADebuggerIsAttached_reportsTrue) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  ASSERT_TRUE(write_threads(directory.path(), {{"4321", "co.ostorlab.app\n"},
                                               {"4401", "JDWP Transport \n"},
                                               {"4402", "JDWP Event Help\n"},
                                               {"4403", "JDWP Command Re\n"}}));

  EXPECT_EQ(observe_jdwp_threads(directory.path(), rasp::util::read_file), jdwp_threads(true));
}

TEST(Debugger, observeJdwpThreads_whenAnEntryIsNotAThreadId_ignoresIt) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  ASSERT_TRUE(write_threads(directory.path(), {{"self", "JDWP Transport \n"}, {"44a1", "JDWP Event Help\n"}}));

  EXPECT_EQ(observe_jdwp_threads(directory.path(), rasp::util::read_file), jdwp_threads(false));
}

TEST(Debugger, observeJdwpThreads_whenAThreadEndedBeforeItsNameIsRead_skipsIt) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  std::error_code error;
  ASSERT_TRUE(std::filesystem::create_directory(directory.path() + "/4402", error));

  EXPECT_EQ(observe_jdwp_threads(directory.path()), jdwp_threads(false));
}

TEST(Debugger, observeJdwpThreads_whenANameIsLongerThan64Bytes_skipsIt) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string long_name = "JDWP" + std::string(61, 'a');
  ASSERT_TRUE(write_threads(directory.path(), {{"4401", long_name}}));

  EXPECT_EQ(observe_jdwp_threads(directory.path(), rasp::util::read_file), jdwp_threads(false));
}

TEST(Debugger, observeJdwpThreads_whenThereAre4096Threads_readsThemAll) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  for (int index = 0; index < 4096; ++index) {
    ASSERT_TRUE(write_threads(directory.path(), {{std::to_string(10000 + index), "Thread\n"}}));
  }

  EXPECT_EQ(observe_jdwp_threads(directory.path(), rasp::util::read_file), jdwp_threads(false));
}

TEST(Debugger, observeJdwpThreads_whenThereAreMoreThan4096Threads_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  for (int index = 0; index < 4097; ++index) {
    ASSERT_TRUE(write_threads(directory.path(), {{std::to_string(10000 + index), "Thread\n"}}));
  }

  EXPECT_EQ(observe_jdwp_threads(directory.path(), rasp::util::read_file), unreadable_jdwp_threads());
}

TEST(Debugger, observeJdwpThreads_whenTheFolderIsMissing_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());

  EXPECT_EQ(observe_jdwp_threads(directory.path() + "/missing"), unreadable_jdwp_threads());
}

TEST(Debugger, observeDebugApi_whenADebuggerIsConnected_reportsTrue) {
  EXPECT_EQ(observe_debug_api(true),
            (Observation{.signal = "dbg.java_debugger", .source = "debug_api", .status = Status::kOk, .value = true}));
}

TEST(Debugger, observeDebugApi_whenNoDebuggerIsConnected_reportsFalse) {
  EXPECT_EQ(observe_debug_api(false),
            (Observation{.signal = "dbg.java_debugger", .source = "debug_api", .status = Status::kOk, .value = false}));
}

TEST(Debugger, observeDebugApi_whenTheCallFailed_reportsAnError) {
  EXPECT_EQ(observe_debug_api(std::nullopt),
            (Observation{.signal = "dbg.java_debugger", .source = "debug_api", .status = Status::kError, .value = {}}));
}

TEST(Debugger, debugger_whenOffAndroid_reportsEveryCheckAsUnsupported) {
  EXPECT_EQ(debugger(),
            (std::vector<Observation>{
                {.signal = "dbg.tracer_pid", .source = "proc_status", .status = Status::kUnsupported, .value = {}},
                {.signal = "dbg.tracer_pid", .source = "proc_status_libc", .status = Status::kUnsupported, .value = {}},
                {.signal = "dbg.java_debugger", .source = "jdwp_threads", .status = Status::kUnsupported, .value = {}},
                {.signal = "dbg.java_debugger", .source = "debug_api", .status = Status::kUnsupported, .value = {}},
            }));
}

}  // namespace
}  // namespace rasp::android::checks
