/// Tests for panic_on_detection as a development build compiles it: it logs what would end the process, and never ends
/// it.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "rasp/config.h"
#include "rasp/observation.h"
#include "rasp/panic.h"
#include "rasp/util/logging.h"

namespace rasp {

namespace {

/// The lines the development build logged.
///
/// @return The lines, which live as long as the test process.
[[nodiscard]] std::vector<std::string>& logged() {
  static std::vector<std::string> lines;
  return lines;
}

/// How many times the stand-in ended the process.
///
/// @return The counter, which lives as long as the test process.
[[nodiscard]] std::atomic<int>& end_calls() {
  static std::atomic<int> calls{0};
  return calls;
}

/// The stand-in for the end of the process: counts the call and returns.
void record_end() noexcept { end_calls().fetch_add(1); }

}  // namespace

void log(std::string_view message) noexcept { logged().emplace_back(message); }

namespace {

TEST(PanicDevelopment, panicOnDetection_whenSomethingIsDetected_logsEachDetectionAndNeverEndsTheProcess) {
  logged().clear();
  ASSERT_TRUE(kLoggingEnabled);
  const std::vector<Observation> observations = {
      observed("dbg.tracer_pid", "proc_status", std::int64_t{4242}),
      observed("emu.props", "system_property", std::vector<std::string>{"ro.hardware=ranchu"}),
      observed("integ.text_sha256", "file", std::string("aa")),
      observed("integ.text_sha256", "memory", std::string("bb")),
      observed("id.package", "proc_cmdline", std::string("com.example")),
  };
  const std::vector<std::string> expected = {
      "would panic: dbg.tracer_pid/proc_status",
      "would panic: emu.props/system_property",
      "would panic: integ.text_sha256/file!=memory",
  };

  EXPECT_FALSE(panic_on_detection(observations, record_end, {}, CheckPlatform::kAndroid));

  EXPECT_EQ(logged(), expected);
  std::this_thread::sleep_for(kMaxPanicDelay + std::chrono::milliseconds{500});
  EXPECT_EQ(end_calls().load(), 0);
}

TEST(PanicDevelopment, panicOnDetection_whenAGroupReports_logsItsActionAndKeepsBlockingLogsDistinct) {
  logged().clear();
  const std::vector<Observation> observations = {
      observed("mitm.tunnels", "getifaddrs", std::vector<std::string>{"tun0"}),
      observed("dbg.tracer_pid", "proc_status", std::int64_t{42}),
  };
  EXPECT_FALSE(panic_on_detection(observations, record_end,
                                  {.build_id = {}, .checks_mask = 0xFF, .report_only_mask = 1U << 4},
                                  CheckPlatform::kAndroid));
  const std::vector<std::string> expected = {"report only: mitm.tunnels/getifaddrs",
                                             "would panic: dbg.tracer_pid/proc_status"};
  EXPECT_EQ(logged(), expected);
  EXPECT_EQ(end_calls().load(), 0);
}

TEST(PanicDevelopment, panicOnDetection_whenAGroupIsOff_logsItDistinctlyFromReportAndBlock) {
  logged().clear();
  const std::vector<Observation> observations = {
      observed("root.fs_paths", "access", std::vector<std::string>{"su"}),
      observed("mitm.tunnels", "getifaddrs", std::vector<std::string>{"tun0"}),
      observed("dbg.tracer_pid", "proc_status", std::int64_t{42}),
  };
  const Config config{.build_id = {}, .checks_mask = (1U << 1) | (1U << 4), .report_only_mask = 1U << 4};
  EXPECT_FALSE(panic_on_detection(observations, record_end, config, CheckPlatform::kAndroid));
  const std::vector<std::string> expected = {
      "check off: root.fs_paths/access",
      "report only: mitm.tunnels/getifaddrs",
      "would panic: dbg.tracer_pid/proc_status",
  };
  EXPECT_EQ(logged(), expected);
  EXPECT_EQ(end_calls().load(), 0);
}

}  // namespace
}  // namespace rasp
