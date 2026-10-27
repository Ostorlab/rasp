/// Tests for the example plugin, compiled into a registry of its own, the way the build compiles the plugins it is
/// given into the runtime.

#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <vector>

#include "rasp/observation.h"
#include "rasp/plugins/host.h"
#include "rasp/plugins/registry.h"

namespace rasp::plugins {
namespace {

/// A config reader that gives every plugin its own name as its config.
///
/// @param name The plugin's name.
/// @return The name.
[[nodiscard]] std::string name_as_config(std::string_view name) { return std::string(name); }

TEST(ExamplePlugin, compiledIn_whenTheRegistryHoldsTheExample_returnsIt) {
  ASSERT_EQ(compiled_in().size(), 1U);
  EXPECT_EQ(compiled_in().front()->name, "example");
}

TEST(ExamplePlugin, run_whenRunTwice_reportsItsConfigSizeThenWhatThePreviousRunHeld) {
  const Host host(compiled_in(), name_as_config);
  const Observation builtin = observed("jb.fork_ok", "fork", false);

  const std::vector<Observation> first = host.run({builtin});
  const std::vector<Observation> second = host.run({builtin});

  const Observation loaded = observed(kLoadSignal, "example", Value{});
  const Observation config_size = observed("example.config_size", "init", std::int64_t{7});
  EXPECT_EQ(first, (std::vector<Observation>{builtin, loaded, config_size}));
  EXPECT_EQ(second, (std::vector<Observation>{
                        builtin,
                        loaded,
                        config_size,
                        observed("example.seen", "on_observations", static_cast<std::int64_t>(first.size())),
                    }));
}

}  // namespace
}  // namespace rasp::plugins
