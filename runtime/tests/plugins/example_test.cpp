/// Tests for the example plugin, compiled into a registry of its own, the way the build compiles the plugins it is
/// given into the runtime.

#include <cstdint>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

#include "rasp/context.h"
#include "rasp/cycle.h"
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

TEST(ExamplePlugin, runPlugins_whenInitialisedThenRunTwice_reportsTheBuildIdItsRunsThenWhatThePreviousRunHeld) {
  const Observation builtin = observed("jb.fork_ok", "fork", false);
  const Observation build_id = observed("example.build_id", "init", std::string("build-7"));
  Context context;

  init_plugins(compiled_in(), {.build_id = "build-7", .checks = {}}, context);
  const std::vector<Observation> first = run_plugins(compiled_in(), {builtin}, context);
  const std::vector<Observation> second = run_plugins(compiled_in(), {builtin}, context);

  EXPECT_EQ(first, (std::vector<Observation>{builtin, build_id, observed("example.runs", "counter", std::int64_t{1})}));
  EXPECT_EQ(second, (std::vector<Observation>{
                        builtin,
                        build_id,
                        observed("example.runs", "counter", std::int64_t{2}),
                        observed("example.seen", "on_observations", static_cast<std::int64_t>(first.size())),
                    }));
}
TEST(ExamplePlugin, onCycle_whenRealMonitorPublishes_retainsSameImmutableOwningUnit) {
  CycleMonitor monitor;
  Context context;
  constexpr Key<std::shared_ptr<const CycleSnapshot>> kRetainedCycle{"example.owned_cycle.v1"};
  const auto snapshot =
      monitor.run({.build_id = "test", .checks = std::vector<std::string>{}}, cycle_catalogue("android"), compiled_in(),
                  context, [](const Config&, const void*) { return std::vector<Observation>{}; });
  const auto retained = context.get(kRetainedCycle);
  ASSERT_TRUE(retained.has_value());
  EXPECT_EQ(*retained, snapshot);
  EXPECT_EQ((*retained)->local_decisions.predicates_evaluated, 0U);
  EXPECT_FALSE(context.get(kCycleSnapshot).has_value());
}

}  // namespace
}  // namespace rasp::plugins
