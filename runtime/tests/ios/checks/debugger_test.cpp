/// Tests for the iOS debugger checks.

#include "checks/debugger.h"

#include <cstdint>
#include <gtest/gtest.h>
#include <unistd.h>
#include <vector>

#include "rasp/observation.h"

namespace rasp::ios::checks {
namespace {

#ifdef __APPLE__
TEST(Debugger, observeTraced_whenNoDebuggerIsAttached_reportsFalse) {
  EXPECT_EQ(observe_traced(),
            (Observation{.signal = "dbg.traced", .source = "sysctl", .status = Status::kOk, .value = false}));
}
#else
TEST(Debugger, observeTraced_whenTheSystemHasNoProcessFlags_reportsUnsupported) {
  EXPECT_EQ(observe_traced(),
            (Observation{.signal = "dbg.traced", .source = "sysctl", .status = Status::kUnsupported, .value = {}}));
}
#endif

TEST(Debugger, observeParent_whenCalled_reportsTheParentProcessId) {
  EXPECT_EQ(observe_parent(), (Observation{.signal = "dbg.parent",
                                           .source = "getppid",
                                           .status = Status::kOk,
                                           .value = static_cast<std::int64_t>(getppid())}));
}

TEST(Debugger, debugger_whenOffAPhysicalDevice_reportsEveryCheckAsUnsupported) {
  EXPECT_EQ(debugger(), (std::vector<Observation>{
                            {.signal = "dbg.traced", .source = "sysctl", .status = Status::kUnsupported, .value = {}},
                            {.signal = "dbg.parent", .source = "getppid", .status = Status::kUnsupported, .value = {}},
                        }));
}

}  // namespace
}  // namespace rasp::ios::checks
