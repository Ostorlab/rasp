/// The production monitor dispatcher preserves opt-in service outputs and existing empty-selection behavior.

#include "builtin.h"

#include <gtest/gtest.h>
#include <vector>

#include "rasp/config.h"
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
TEST(Builtin, runChecks_whenNoGroupsSelected_returnsNoObservations) {
  EXPECT_TRUE(run_checks(Config{}).empty());
  Config config;
  config.checks = {"unknown"};
  EXPECT_TRUE(run_checks(config).empty());
}
}  // namespace
}  // namespace rasp::android
