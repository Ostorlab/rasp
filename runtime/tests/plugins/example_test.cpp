/// Tests for the example plugin, compiled into a registry of its own, the way the build compiles the plugins it is
/// given into the runtime.

#include <cstdint>
#include <gtest/gtest.h>
#include <vector>

#include "rasp/observation.h"
#include "rasp/plugin.h"
#include "rasp/plugins/registry.h"

namespace rasp::plugins {

namespace example {

/// The example plugin, which the example's sources define.
extern const Plugin kPlugin;

}  // namespace example

namespace {

TEST(ExamplePlugin, compiledIn_whenTheRegistryHoldsTheExample_returnsIt) {
  ASSERT_EQ(compiled_in().size(), 1U);
  EXPECT_EQ(compiled_in().front(), &example::kPlugin);
}

TEST(ExamplePlugin, runPlugins_whenRunTwice_reportsItsRunsThenWhatThePreviousRunHeld) {
  const Observation builtin = observed("jb.fork_ok", "fork", false);

  const std::vector<Observation> first = run_plugins(compiled_in(), {builtin});
  const std::vector<Observation> second = run_plugins(compiled_in(), {builtin});

  EXPECT_EQ(first, (std::vector<Observation>{builtin, observed("example.runs", "counter", std::int64_t{1})}));
  EXPECT_EQ(second, (std::vector<Observation>{
                        builtin,
                        observed("example.runs", "counter", std::int64_t{2}),
                        observed("example.seen", "on_observations", static_cast<std::int64_t>(first.size())),
                    }));
}

}  // namespace
}  // namespace rasp::plugins
