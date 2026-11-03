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

  EXPECT_FALSE(panic_on_detection(observations, record_end));

  EXPECT_EQ(logged(), expected);
  std::this_thread::sleep_for(kMaxPanicDelay + std::chrono::milliseconds{500});
  EXPECT_EQ(end_calls().load(), 0);
}

}  // namespace
}  // namespace rasp
