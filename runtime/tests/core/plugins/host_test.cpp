/// Tests for Host, against test plugins that record what they receive.

#include "rasp/plugins/host.h"

#include <array>
#include <cstdint>
#include <gtest/gtest.h>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "rasp/observation.h"
#include "rasp/plugin.h"

namespace rasp::plugins {
namespace {

/// What the test plugins received during one test.
struct Record {
  /// The config every `init` received, as `<plugin>=<config>`, in call order.
  std::vector<std::string> configs;
  /// The observations every `on_observations` received, with the plugin's name, in call order.
  std::vector<std::pair<std::string, std::vector<Observation>>> received;
};

/// The record of the running test.
///
/// @return The record, which lives as long as the test process.
[[nodiscard]] Record& record() {
  static Record value;
  return value;
}

/// Records the config `plugin` received, and accepts it when `accept` is `true`.
///
/// @param plugin The plugin's name.
/// @param config The config it received.
/// @param accept What its `init` returns.
/// @return `accept`.
[[nodiscard]] bool init(std::string_view plugin, std::string_view config, bool accept) {
  record().configs.push_back(std::string(plugin) + "=" + std::string(config));
  return accept;
}

/// Records the observations `plugin` received.
///
/// @param plugin The plugin's name.
/// @param observations The observations it received.
void observe(std::string_view plugin, std::span<const Observation> observations) {
  record().received.emplace_back(std::string(plugin),
                                 std::vector<Observation>(observations.begin(), observations.end()));
}

/// The `init` of the alpha plugin, which accepts every config.
///
/// @param config The config it received.
/// @return `true`.
[[nodiscard]] bool init_alpha(std::string_view config) { return init("alpha", config, true); }

/// The first check of the alpha plugin.
///
/// @return One alpha.first observation, true, read through test.
[[nodiscard]] std::vector<Observation> alpha_first() { return {observed("alpha.first", "test", true)}; }

/// The second check of the alpha plugin.
///
/// @return One alpha.second observation, 2, read through test.
[[nodiscard]] std::vector<Observation> alpha_second() { return {observed("alpha.second", "test", std::int64_t{2})}; }

/// The `on_observations` of the alpha plugin.
///
/// @param observations The observations it received.
void observe_alpha(std::span<const Observation> observations) { observe("alpha", observations); }

/// The `init` of the beta plugin, which accepts every config.
///
/// @param config The config it received.
/// @return `true`.
[[nodiscard]] bool init_beta(std::string_view config) { return init("beta", config, true); }

/// The check of the beta plugin.
///
/// @return One beta.only observation, false, read through test.
[[nodiscard]] std::vector<Observation> beta_only() { return {observed("beta.only", "test", false)}; }

/// The `on_observations` of the beta plugin.
///
/// @param observations The observations it received.
void observe_beta(std::span<const Observation> observations) { observe("beta", observations); }

/// The `init` of the declining plugin, which declines every config.
///
/// @param config The config it received.
/// @return `false`.
[[nodiscard]] bool init_declining(std::string_view config) { return init("declining", config, false); }

/// The check of the declining plugin, which must never run.
///
/// @return One declining.ran observation, true, read through test.
[[nodiscard]] std::vector<Observation> declining_ran() { return {observed("declining.ran", "test", true)}; }

/// The `on_observations` of the declining plugin, which must never be called.
///
/// @param observations The observations it received.
void observe_declining(std::span<const Observation> observations) { observe("declining", observations); }

/// The `init` of the silent plugin, which accepts every config.
///
/// @param config The config it received.
/// @return `true`.
[[nodiscard]] bool init_silent(std::string_view config) { return init("silent", config, true); }

/// The checks of the alpha plugin.
constexpr std::array<Check, 2> kAlphaChecks{alpha_first, alpha_second};
/// The checks of the beta plugin.
constexpr std::array<Check, 1> kBetaChecks{beta_only};
/// The checks of the declining plugin.
constexpr std::array<Check, 1> kDecliningChecks{declining_ran};

/// A plugin with two checks and an observer.
constexpr Plugin kAlpha{.name = "alpha", .init = init_alpha, .checks = kAlphaChecks, .on_observations = observe_alpha};
/// A plugin with one check and an observer.
constexpr Plugin kBeta{.name = "beta", .init = init_beta, .checks = kBetaChecks, .on_observations = observe_beta};
/// A plugin that declines its config.
constexpr Plugin kDeclining{
    .name = "declining",
    .init = init_declining,
    .checks = kDecliningChecks,
    .on_observations = observe_declining,
};
/// A plugin with no check and no observer.
constexpr Plugin kSilent{.name = "silent", .init = init_silent, .checks = {}};

/// A config reader that gives every plugin a config of its own.
///
/// @param name The plugin's name.
/// @return `config of <name>`.
[[nodiscard]] std::string config_of(std::string_view name) { return "config of " + std::string(name); }

/// The observation of the built-in checks that every test passes to `run`.
///
/// @return One jb.fork_ok observation, false, read through fork.
[[nodiscard]] Observation builtin() { return observed("jb.fork_ok", "fork", false); }

/// The `plugin.load` observation of a plugin that accepted its config.
///
/// @param plugin The plugin's name.
/// @return The observation, with status `kOk` and no value.
[[nodiscard]] Observation loaded(std::string_view plugin) { return observed(kLoadSignal, plugin, Value{}); }

/// Clears the record before each test.
class HostTest : public testing::Test {
 protected:
  /// Clears the record.
  void SetUp() override { record() = Record{}; }
};

TEST_F(HostTest, run_whenThereIsNoPlugin_returnsTheBuiltInObservations) {
  const Host host({}, config_of);

  EXPECT_EQ(host.run({builtin()}), std::vector<Observation>{builtin()});
}

TEST_F(HostTest, construct_whenGivenPlugins_givesEachInitTheConfigReadForItsName) {
  const std::array<const Plugin*, 3> plugins{&kAlpha, &kDeclining, &kBeta};

  const Host host(plugins, config_of);

  EXPECT_EQ(record().configs, (std::vector<std::string>{"alpha=config of alpha", "declining=config of declining",
                                                        "beta=config of beta"}));
}

TEST_F(HostTest, run_whenPluginsAccept_addsTheirLoadObservationsThenTheirChecksInOrder) {
  const std::array<const Plugin*, 2> plugins{&kAlpha, &kBeta};
  const Host host(plugins, config_of);

  const std::vector<Observation> observations = host.run({builtin()});

  EXPECT_EQ(observations, (std::vector<Observation>{
                              builtin(),
                              loaded("alpha"),
                              loaded("beta"),
                              observed("alpha.first", "test", true),
                              observed("alpha.second", "test", std::int64_t{2}),
                              observed("beta.only", "test", false),
                          }));
}

TEST_F(HostTest, run_whenAPluginDeclines_reportsAnErrorAndNeitherRunsNorNotifiesIt) {
  const std::array<const Plugin*, 2> plugins{&kDeclining, &kBeta};
  const Host host(plugins, config_of);

  const std::vector<Observation> observations = host.run({builtin()});

  EXPECT_EQ(observations, (std::vector<Observation>{
                              builtin(),
                              failed(kLoadSignal, "declining"),
                              loaded("beta"),
                              observed("beta.only", "test", false),
                          }));
  ASSERT_EQ(record().received.size(), 1U);
  EXPECT_EQ(record().received.front().first, "beta");
}

TEST_F(HostTest, run_whenPluginsObserve_givesEachObserverAllTheObservations) {
  const std::array<const Plugin*, 2> plugins{&kAlpha, &kBeta};
  const Host host(plugins, config_of);

  const std::vector<Observation> observations = host.run({builtin()});

  EXPECT_EQ(record().received, (std::vector<std::pair<std::string, std::vector<Observation>>>{
                                   {"alpha", observations},
                                   {"beta", observations},
                               }));
}

TEST_F(HostTest, run_whenRunTwice_initialisesOnceAndReportsTheLoadEachTime) {
  const std::array<const Plugin*, 1> plugins{&kAlpha};
  const Host host(plugins, config_of);

  const std::vector<Observation> first = host.run({builtin()});
  const std::vector<Observation> second = host.run({builtin()});

  EXPECT_EQ(record().configs, std::vector<std::string>{"alpha=config of alpha"});
  EXPECT_EQ(first, second);
  ASSERT_GE(second.size(), 2U);
  EXPECT_EQ(second[1], loaded("alpha"));
}

TEST_F(HostTest, run_whenAPluginHasNoCheckAndNoObserver_reportsOnlyItsLoad) {
  const std::array<const Plugin*, 1> plugins{&kSilent};
  const Host host(plugins, config_of);

  EXPECT_EQ(host.run({builtin()}), (std::vector<Observation>{builtin(), loaded("silent")}));
}

}  // namespace
}  // namespace rasp::plugins
