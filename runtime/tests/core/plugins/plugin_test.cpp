/// Tests for Plugin, the type of a plugin compiled into the runtime.

#include "rasp/plugin.h"

#include <array>
#include <gtest/gtest.h>
#include <vector>

#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/observation.h"

namespace rasp::plugins {
namespace {

/// An init that does nothing.
void ignore(const Config& /*config*/, Context& /*context*/) {}

/// A check that observes a constant.
///
/// @return One test.ping observation, true, read through constant.
[[nodiscard]] std::vector<Observation> ping(Context& /*context*/) { return {observed("test.ping", "constant", true)}; }

/// The checks of the plugin that has checks.
constexpr std::array<Check, 1> kChecks{ping};

TEST(Plugin, construct_whenInitIsGiven_holdsIt) {
  constexpr Plugin kPlugin{.init = ignore, .checks = {}};

  EXPECT_EQ(kPlugin.init, ignore);
}

TEST(Plugin, construct_whenNoObserverIsGiven_hasNone) {
  constexpr Plugin kPlugin{.init = ignore, .checks = {}};

  EXPECT_EQ(kPlugin.on_observations, nullptr);
}

TEST(Plugin, construct_whenChecksAreGiven_holdsThemInOrder) {
  constexpr Plugin kPlugin{.init = ignore, .checks = kChecks};

  ASSERT_EQ(kPlugin.checks.size(), 1U);
  EXPECT_EQ(kPlugin.checks.front(), ping);
}

}  // namespace
}  // namespace rasp::plugins
