/// The production monitor dispatcher preserves opt-in service outputs and existing empty-selection behavior.

#include "builtin.h"

#include <gtest/gtest.h>
#include <vector>

#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/cycle.h"
#include "rasp/decision.h"
#include "rasp/observation.h"

namespace rasp::android {
namespace {
TEST(Builtin, runChecks_whenServicesSelected_dispatchesEveryContractOnce) {
  Config config;
  config.checks = {"accessibility", "input_method", "notification_access", "accessibility"};
  EXPECT_EQ(run_checks(config),
            (std::vector<Observation>{unsupported("a11y.enabled_services", "accessibility_manager"),
                                      unsupported("ime.enabled_components", "input_method_manager"),
                                      unsupported("ime.current_component", "input_method_manager"),
                                      unsupported("notification.enabled_listeners", "settings_secure")}));
}
TEST(Builtin, runChecks_whenRootContextSelected_dispatchesSixFixedOptInOutputs) {
  Config config;
  config.checks = {"root_packages", "root_context", "proxy", "developer_settings", "root_packages"};
  EXPECT_EQ(run_checks(config),
            (std::vector<Observation>{unsupported("root.manager_packages_v1", "package_manager"),
                                      unsupported("root.mountinfo_context_v1", "proc_self_mountinfo"),
                                      unsupported("root.mount_namespace_v1", "proc_self_ns_mnt"),
                                      unsupported("net.default_proxy_v1", "connectivity_manager"),
                                      unsupported("debug.adb_enabled_v1", "settings_global"),
                                      unsupported("debug.developer_options_enabled_v1", "settings_global")}));
}
TEST(Builtin, runChecks_whenNoGroupsSelected_returnsNoObservations) {
  EXPECT_TRUE(run_checks(Config{}).empty());
  Config config;
  config.checks = {"unknown"};
  EXPECT_TRUE(run_checks(config).empty());
}
TEST(Builtin, runChecks_whenOwnedMonitorDispatchesRealServices_publishesUnavailableDecisionsWithCompleteRetention) {
  CycleMonitor monitor;
  plugins::Context context;
  const Config config{
      .build_id = "test",
      .checks = std::vector<std::string>{"root_packages", "root_context", "proxy", "developer_settings"},
  };
  const auto snapshot = monitor.run(config, cycle_catalogue("android"), {}, context,
                                    [](const Config& selection, const void*) { return run_checks(selection); });
  EXPECT_EQ(snapshot->observations.size(), 6U);
  EXPECT_EQ(snapshot->local_decisions.builtin_observations, 6U);
  EXPECT_EQ(snapshot->local_decisions.coverage, LocalCoverage::kComplete);
  EXPECT_EQ(snapshot->local_decisions.predicates_evaluated, 0U);
  for (const auto& decision : snapshot->local_decisions.rows) {
    EXPECT_EQ(decision.verdict, LocalVerdict::kUnknown);
  }
}
TEST(Builtin, runChecks_whenRealCaptureDispatchesThroughOwner_keepsAllTwentyOneUnavailableWithoutPredicates) {
  CycleMonitor monitor;
  plugins::Context context;
  const Config config{.build_id = "test", .checks = std::vector<std::string>{"screenshot", "screen_recording"}};
  const auto snapshot = monitor.run(config, cycle_catalogue("android"), {}, context,
                                    [](const Config& selection, const void*) { return run_checks(selection); });
  EXPECT_EQ(snapshot->observations.size(), 21U);
  EXPECT_EQ(snapshot->local_decisions.builtin_observations, 21U);
  EXPECT_EQ(snapshot->local_decisions.predicates_evaluated, 0U);
  EXPECT_EQ(snapshot->local_decisions.coverage, LocalCoverage::kComplete);
  for (const auto& decision : snapshot->local_decisions.rows) {
    EXPECT_EQ(decision.verdict, LocalVerdict::kUnknown);
  }
}
}  // namespace
}  // namespace rasp::android
