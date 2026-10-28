/// Tests for init_plugins, against test plugins that record the config their init receives.

#include <array>
#include <gtest/gtest.h>
#include <string>
#include <utility>
#include <vector>

#include "rasp/config.h"
#include "rasp/plugin.h"
#include "rasp/plugins/registry.h"

namespace rasp::plugins {
namespace {

/// The build id every `init` received, with the plugin's name, in call order.
using Received = std::vector<std::pair<std::string, std::string>>;

/// What the test plugins received during the running test.
///
/// @return The record, which lives as long as the test process.
[[nodiscard]] Received& received() {
  static Received value;
  return value;
}

/// The `init` of the alpha plugin.
///
/// @param config The runtime's config. Only its build id is recorded.
void init_alpha(const Config& config) { received().emplace_back("alpha", config.build_id); }

/// The `init` of the beta plugin.
///
/// @param config The runtime's config. Only its build id is recorded.
void init_beta(const Config& config) { received().emplace_back("beta", config.build_id); }

/// A plugin that records its init.
constexpr Plugin kAlpha{.init = init_alpha, .checks = {}};
/// Another plugin that records its init.
constexpr Plugin kBeta{.init = init_beta, .checks = {}};

/// Clears the record before each test.
class InitPluginsTest : public testing::Test {
 protected:
  /// Clears the record.
  void SetUp() override { received().clear(); }
};

TEST_F(InitPluginsTest, initPlugins_whenThereIsNoPlugin_callsNothing) {
  init_plugins({}, {.build_id = "build-7"});

  EXPECT_TRUE(received().empty());
}

TEST_F(InitPluginsTest, initPlugins_whenThereArePlugins_givesEachInitTheConfigInOrder) {
  const std::array<const Plugin*, 2> plugins{&kBeta, &kAlpha};

  init_plugins(plugins, {.build_id = "build-7"});

  EXPECT_EQ(received(), (Received{{"beta", "build-7"}, {"alpha", "build-7"}}));
}

}  // namespace
}  // namespace rasp::plugins
