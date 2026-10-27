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

/// The observations every `on_observations` received, with the plugin's name, in call order.
using Received = std::vector<std::pair<std::string, std::vector<Observation>>>;

/// What the test plugins received during the running test.
///
/// @return The record, which lives as long as the test process.
[[nodiscard]] Received& received() {
  static Received value;
  return value;
}

/// Records the observations `plugin` received.
///
/// @param plugin The plugin's name.
/// @param observations The observations it received.
void observe(std::string_view plugin, std::span<const Observation> observations) {
  received().emplace_back(std::string(plugin), std::vector<Observation>(observations.begin(), observations.end()));
}

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

/// The check of the beta plugin.
///
/// @return One beta.only observation, false, read through test.
[[nodiscard]] std::vector<Observation> beta_only() { return {observed("beta.only", "test", false)}; }

/// The `on_observations` of the beta plugin.
///
/// @param observations The observations it received.
void observe_beta(std::span<const Observation> observations) { observe("beta", observations); }

/// The checks of the alpha plugin.
constexpr std::array<Check, 2> kAlphaChecks{alpha_first, alpha_second};
/// The checks of the beta plugin.
constexpr std::array<Check, 1> kBetaChecks{beta_only};

/// A plugin with two checks and an observer.
constexpr Plugin kAlpha{.checks = kAlphaChecks, .on_observations = observe_alpha};
/// A plugin with one check and an observer.
constexpr Plugin kBeta{.checks = kBetaChecks, .on_observations = observe_beta};
/// A plugin with no check and no observer.
constexpr Plugin kSilent{.checks = {}};

/// The observation of the built-in checks that every test passes to `run`.
///
/// @return One jb.fork_ok observation, false, read through fork.
[[nodiscard]] Observation builtin() { return observed("jb.fork_ok", "fork", false); }

/// Clears the record before each test.
class HostTest : public testing::Test {
 protected:
  /// Clears the record.
  void SetUp() override { received().clear(); }
};

TEST_F(HostTest, run_whenThereIsNoPlugin_returnsTheBuiltInObservations) {
  const Host host({});

  EXPECT_EQ(host.run({builtin()}), std::vector<Observation>{builtin()});
}

TEST_F(HostTest, run_whenPluginsHaveChecks_addsTheirObservationsAfterTheBuiltInOnesInOrder) {
  const std::array<const Plugin*, 2> plugins{&kAlpha, &kBeta};
  const Host host(plugins);

  const std::vector<Observation> observations = host.run({builtin()});

  EXPECT_EQ(observations, (std::vector<Observation>{
                              builtin(),
                              observed("alpha.first", "test", true),
                              observed("alpha.second", "test", std::int64_t{2}),
                              observed("beta.only", "test", false),
                          }));
}

TEST_F(HostTest, run_whenPluginsObserve_givesEachObserverAllTheObservations) {
  const std::array<const Plugin*, 2> plugins{&kAlpha, &kBeta};
  const Host host(plugins);

  const std::vector<Observation> observations = host.run({builtin()});

  EXPECT_EQ(received(), (Received{
                            {"alpha", observations},
                            {"beta", observations},
                        }));
}

TEST_F(HostTest, run_whenAPluginHasNoCheckAndNoObserver_returnsTheBuiltInObservations) {
  const std::array<const Plugin*, 1> plugins{&kSilent};
  const Host host(plugins);

  EXPECT_EQ(host.run({builtin()}), std::vector<Observation>{builtin()});
}

}  // namespace
}  // namespace rasp::plugins
