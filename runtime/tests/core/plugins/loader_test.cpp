/// Tests for load_plugin, against the example plugin built for this machine, and for the example plugin itself through
/// the host.

#include "rasp/plugins/loader.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <vector>

#include "rasp/observation.h"
#include "rasp/plugin.h"
#include "rasp/plugins/host.h"

namespace rasp::plugins {
namespace {

/// The example plugin's library, built by this project for this machine.
constexpr std::string_view kExamplePlugin = RASP_EXAMPLE_PLUGIN;
/// A shared library that exports no rasp_plugin_init.
constexpr std::string_view kNotAPlugin = RASP_NOT_A_PLUGIN;

/// What the tests tell the plugin when they initialise it.
///
/// @return A host description for a test platform, with no config and no Java VM.
[[nodiscard]] rasp_host test_host() { return host_info("test", "", nullptr); }

/// Whether `pass` holds `observation`.
///
/// @param pass The observations of a pass.
/// @param observation The observation to look for.
/// @return `true` when one of the pass's observations equals it.
[[nodiscard]] bool holds(const std::vector<Observation>& pass, const Observation& observation) {
  return std::ranges::find(pass, observation) != pass.end();
}

TEST(PluginLoader, loadPlugin_whenTheLibraryIsAPlugin_returnsTheTableItsInitReturned) {
  const rasp_plugin* const table = load_plugin(std::string(kExamplePlugin), test_host());

  ASSERT_NE(table, nullptr);
  EXPECT_EQ(std::string_view(table->name.data, table->name.size), "example");
  EXPECT_EQ(table->api_version, RASP_PLUGIN_API_VERSION);
}

TEST(PluginLoader, loadPlugin_whenTheLibraryDoesNotExist_returnsNull) {
  EXPECT_EQ(load_plugin(std::string(kExamplePlugin) + ".missing", test_host()), nullptr);
}

TEST(PluginLoader, loadPlugin_whenTheLibraryHasNoInit_returnsNull) {
  EXPECT_EQ(load_plugin(std::string(kNotAPlugin), test_host()), nullptr);
}

TEST(ExamplePlugin, runPass_whenTwoPassesRun_pingsAndReportsWhatThePreviousPassHeld) {
  const std::array<Listed, 1> listed{
      {{.name = "example", .table = load_plugin(std::string(kExamplePlugin), test_host())}},
  };
  Host host(listed);

  const std::vector<Observation> first = host.run_pass({observed("jb.fork_ok", "fork", false)});
  const std::vector<Observation> second = host.run_pass({observed("jb.fork_ok", "fork", false)});

  EXPECT_TRUE(holds(first, observed("plugin.load", "example", Value{})));
  EXPECT_TRUE(holds(first, observed("example.ping", "constant", true)));
  EXPECT_TRUE(holds(second, observed("example.ping", "constant", true)));
  EXPECT_TRUE(holds(second, observed("example.seen", "on_pass", static_cast<std::int64_t>(first.size()))));
  EXPECT_EQ(second.size(), first.size() + 1);
}

}  // namespace
}  // namespace rasp::plugins
