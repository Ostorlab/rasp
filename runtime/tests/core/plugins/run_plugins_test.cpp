/// Tests for run_plugins, against test plugins that record what they receive.

#include <array>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/observation.h"
#include "rasp/plugin.h"
#include "rasp/plugins/registry.h"

namespace rasp::plugins {
namespace {

/// The observations every `on_observations` received, with the plugin's name, in call order.
using Received = std::vector<std::pair<std::string, std::vector<Observation>>>;

/// The key of the value the writer plugin's check puts in the context.
constexpr Key<std::string> kWritten{.name = "test.written"};

/// What the test plugins received during the running test.
///
/// @return The record, which lives as long as the test process.
[[nodiscard]] Received& received() {
  static Received value;
  return value;
}

/// The value the reader plugin's `on_observations` took from the context during the running test.
///
/// @return The record, which lives as long as the test process. Nothing when the reader took nothing.
[[nodiscard]] std::optional<std::string>& value_taken() {
  static std::optional<std::string> value;
  return value;
}

/// Records the observations `plugin` received.
///
/// @param plugin The plugin's name.
/// @param observations The observations it received.
void observe(std::string_view plugin, std::span<const Observation> observations) {
  received().emplace_back(std::string(plugin), std::vector<Observation>(observations.begin(), observations.end()));
}

/// An init that does nothing.
void ignore(const Config& /*config*/, Context& /*context*/) {}

/// The first check of the alpha plugin.
///
/// @return One alpha.first observation, true, read through test.
[[nodiscard]] std::vector<Observation> alpha_first(Context& /*context*/) {
  return {observed("alpha.first", "test", true)};
}

/// The second check of the alpha plugin.
///
/// @return One alpha.second observation, 2, read through test.
[[nodiscard]] std::vector<Observation> alpha_second(Context& /*context*/) {
  return {observed("alpha.second", "test", std::int64_t{2})};
}

/// The `on_observations` of the alpha plugin.
///
/// @param observations The observations it received.
void observe_alpha(std::span<const Observation> observations, Context& /*context*/) { observe("alpha", observations); }

/// The check of the beta plugin.
///
/// @return One beta.only observation, false, read through test.
[[nodiscard]] std::vector<Observation> beta_only(Context& /*context*/) {
  return {observed("beta.only", "test", false)};
}

/// The `on_observations` of the beta plugin.
///
/// @param observations The observations it received.
void observe_beta(std::span<const Observation> observations, Context& /*context*/) { observe("beta", observations); }

/// The check of the writer plugin: puts a value in the context.
///
/// @param context The values the plugins share, where it puts the value under kWritten.
/// @return No observation.
[[nodiscard]] std::vector<Observation> put_value(Context& context) {
  context.put(kWritten, "written by the writer's check");
  return {};
}

/// The `on_observations` of the reader plugin: takes the value the context holds under kWritten, and records it.
///
/// @param context The values the plugins share.
void take_value(std::span<const Observation> /*observations*/, Context& context) {
  value_taken() = context.take(kWritten);
}

/// The checks of the alpha plugin.
constexpr std::array<Check, 2> kAlphaChecks{alpha_first, alpha_second};
/// The checks of the beta plugin.
constexpr std::array<Check, 1> kBetaChecks{beta_only};
/// The checks of the writer plugin.
constexpr std::array<Check, 1> kWriterChecks{put_value};

/// A plugin with two checks and an observer.
constexpr Plugin kAlpha{.init = ignore, .checks = kAlphaChecks, .on_observations = observe_alpha};
/// A plugin with one check and an observer.
constexpr Plugin kBeta{.init = ignore, .checks = kBetaChecks, .on_observations = observe_beta};
/// A plugin with no check and no observer.
constexpr Plugin kSilent{.init = ignore, .checks = {}};
/// A plugin whose check puts a value in the context.
constexpr Plugin kWriter{.init = ignore, .checks = kWriterChecks};
/// A plugin whose observer takes that value from the context.
constexpr Plugin kReader{.init = ignore, .checks = {}, .on_observations = take_value};

/// The observation of the built-in checks that every test gives `run_plugins`.
///
/// @return One jb.fork_ok observation, false, read through fork.
[[nodiscard]] Observation builtin() { return observed("jb.fork_ok", "fork", false); }

/// Clears the records before each test.
class RunPluginsTest : public testing::Test {
 protected:
  /// Clears the records.
  void SetUp() override {
    received().clear();
    value_taken().reset();
  }
};

TEST_F(RunPluginsTest, runPlugins_whenThereIsNoPlugin_returnsTheBuiltInObservations) {
  Context context;

  EXPECT_EQ(run_plugins({}, {builtin()}, context), std::vector<Observation>{builtin()});
}

TEST_F(RunPluginsTest, runPlugins_whenPluginsHaveChecks_addsTheirObservationsAfterTheBuiltInOnesInOrder) {
  const std::array<const Plugin*, 2> plugins{&kAlpha, &kBeta};
  Context context;

  const std::vector<Observation> observations = run_plugins(plugins, {builtin()}, context);

  EXPECT_EQ(observations, (std::vector<Observation>{
                              builtin(),
                              observed("alpha.first", "test", true),
                              observed("alpha.second", "test", std::int64_t{2}),
                              observed("beta.only", "test", false),
                          }));
}

TEST_F(RunPluginsTest, runPlugins_whenPluginsObserve_givesEachObserverAllTheObservations) {
  const std::array<const Plugin*, 2> plugins{&kAlpha, &kBeta};
  Context context;

  const std::vector<Observation> observations = run_plugins(plugins, {builtin()}, context);

  EXPECT_EQ(received(), (Received{
                            {"alpha", observations},
                            {"beta", observations},
                        }));
}

TEST_F(RunPluginsTest, runPlugins_whenAPluginHasNoCheckAndNoObserver_returnsTheBuiltInObservations) {
  const std::array<const Plugin*, 1> plugins{&kSilent};
  Context context;

  EXPECT_EQ(run_plugins(plugins, {builtin()}, context), std::vector<Observation>{builtin()});
}

TEST_F(RunPluginsTest, runPlugins_whenAPluginsCheckPutsAValue_givesItToAnotherPluginsObserverThroughTheContext) {
  const std::array<const Plugin*, 2> plugins{&kReader, &kWriter};
  Context context;

  static_cast<void>(run_plugins(plugins, {builtin()}, context));

  EXPECT_EQ(value_taken(), "written by the writer's check");
  EXPECT_EQ(context.get(kWritten), std::nullopt);
}

}  // namespace
}  // namespace rasp::plugins
