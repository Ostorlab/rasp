/// Tests for init_plugins, against test plugins that record the config and the context their init receives.

#include <array>
#include <gtest/gtest.h>
#include <string>
#include <tuple>
#include <vector>

#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/plugin.h"
#include "rasp/plugins/registry.h"

namespace rasp::plugins {
namespace {

/// The build id and the context every `init` received, with the plugin's name, in call order.
using Received = std::vector<std::tuple<std::string, std::string, Context*>>;

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
/// @param context The values the plugins share. Only its address is recorded.
void init_alpha(const Config& config, Context& context) { received().emplace_back("alpha", config.build_id, &context); }

/// The `init` of the beta plugin.
///
/// @param config The runtime's config. Only its build id is recorded.
/// @param context The values the plugins share. Only its address is recorded.
void init_beta(const Config& config, Context& context) { received().emplace_back("beta", config.build_id, &context); }

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
  Context context;

  init_plugins({}, {.build_id = "build-7", .checks = {}}, context);

  EXPECT_TRUE(received().empty());
}

TEST_F(InitPluginsTest, initPlugins_whenThereArePlugins_givesEachInitTheConfigAndTheContextInOrder) {
  const std::array<const Plugin*, 2> plugins{&kBeta, &kAlpha};
  Context context;

  init_plugins(plugins, {.build_id = "build-7", .checks = {}}, context);

  EXPECT_EQ(received(), (Received{{"beta", "build-7", &context}, {"alpha", "build-7", &context}}));
}

}  // namespace
}  // namespace rasp::plugins
