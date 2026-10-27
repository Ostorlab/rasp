/// Tests for Plugin, the type of a plugin compiled into the runtime.

#include "rasp/plugin.h"

#include <array>
#include <gtest/gtest.h>
#include <string_view>
#include <vector>

#include "rasp/observation.h"

namespace rasp::plugins {
namespace {

/// Accepts every config.
///
/// @param config The config, which is not read.
/// @return `true`.
[[nodiscard]] bool accept([[maybe_unused]] std::string_view config) { return true; }

/// A check that observes a constant.
///
/// @return One test.ping observation, true, read through constant.
[[nodiscard]] std::vector<Observation> ping() { return {observed("test.ping", "constant", true)}; }

/// The checks of the plugin that has checks.
constexpr std::array<Check, 1> kChecks{ping};

TEST(Plugin, construct_whenNoObserverIsGiven_hasNone) {
  constexpr Plugin kPlugin{.name = "test", .init = accept, .checks = {}};

  EXPECT_EQ(kPlugin.on_observations, nullptr);
}

TEST(Plugin, construct_whenChecksAreGiven_holdsThemInOrder) {
  constexpr Plugin kPlugin{.name = "test", .init = accept, .checks = kChecks};

  ASSERT_EQ(kPlugin.checks.size(), 1U);
  EXPECT_EQ(kPlugin.checks.front()(), std::vector<Observation>{observed("test.ping", "constant", true)});
  EXPECT_TRUE(kPlugin.init("any config"));
}

}  // namespace
}  // namespace rasp::plugins
