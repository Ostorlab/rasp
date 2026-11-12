/// Compiled tests of iOS check selection and dispatch, including the integrity group.

#include "builtin.h"

#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/cycle.h"
#include "rasp/decision.h"
#include "rasp/observation.h"

namespace rasp::ios {
namespace {
TEST(Builtin, runChecks_whenIntegritySelected_dispatchesTypedObservations) {
  Config config;
  config.checks = {"integrity"};
  EXPECT_EQ(run_checks(config, ""), (std::vector<Observation>{unsupported("integ.text_sha256", "file"),
                                                              unsupported("integ.text_sha256", "memory")}));
}
TEST(Builtin, runChecks_whenIntegrityNotSelected_doesNotDispatchIntegrity) {
  Config config;
  config.checks = {"debugger"};
  const auto observations = run_checks(config, "");
  ASSERT_FALSE(observations.empty());
  for (const auto& observation : observations) {
    EXPECT_NE(observation.signal, "integ.text_sha256");
  }
}
TEST(Builtin, runChecks_whenNoChecksSelected_returnsNoObservations) { EXPECT_TRUE(run_checks(Config{}, "").empty()); }
TEST(Builtin, runChecks_whenOwnedMonitorDispatchesRealIntegrity_preservesUnsupportedWithoutCleanVerdict) {
  CycleMonitor monitor;
  plugins::Context context;
  const Config config{.build_id = "test", .checks = std::vector<std::string>{"integrity"}};
  const auto snapshot = monitor.run(config, cycle_catalogue("ios"), {}, context,
                                    [](const Config& selection, const void*) { return run_checks(selection, ""); });
  EXPECT_EQ(snapshot->local_decisions.builtin_observations, 2U);
  EXPECT_EQ(snapshot->local_decisions.coverage, LocalCoverage::kComplete);
  EXPECT_EQ(snapshot->local_decisions.predicates_evaluated, 0U);
  for (const auto& decision : snapshot->local_decisions.rows) {
    EXPECT_EQ(decision.verdict, LocalVerdict::kUnknown);
  }
}
}  // namespace
}  // namespace rasp::ios
