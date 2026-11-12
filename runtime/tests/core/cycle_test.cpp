/// Tests the finite production monitor and plugin dispatch with owned snapshots.

#include "rasp/cycle.h"

#include <array>
#include <bit>
#include <cstdint>
#include <gtest/gtest.h>
#include <limits>
#include <memory>
#include <optional>
#include <semaphore>
#include <span>
#include <string>
#include <thread>
#include <vector>

#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/observation.h"
#include "rasp/plugin.h"
#include "rasp/plugins/registry.h"

namespace {

/// One known output in a finite catalogue.
constexpr std::array kOutputs{rasp::CycleOutput{.group = "debugger", .signal = "dbg.traced", .source = "sysctl"}};
/// Catalogue identity for seam tests; platform production tests use the generated catalogue.
constexpr rasp::CycleCatalogue kCatalogue{.platform = "ios", .catalogue_id = "test-catalogue", .outputs = kOutputs};
/// No plugins, with typed empty arguments for native analysis.
constexpr std::array<const rasp::plugins::Plugin*, 0> kNoPlugins{};
/// Missing selection, without conflating it with an empty configured selection.
rasp::Config unknown_config() { return {}; }
/// Absent catalogue, with no invented expected outputs.
rasp::CycleCatalogue unknown_catalogue() { return {}; }
/// An owned snapshot retained by the fake asynchronous consumer.
constexpr rasp::plugins::Key<std::shared_ptr<const rasp::CycleSnapshot>> kRetained{"test.retained"};
/// The trace of synchronous callback ordering.
constexpr rasp::plugins::Key<std::string> kOrder{"test.order"};

/// Produces one selected builtin with a failed status; failure is still present coverage.
std::vector<rasp::Observation> builtins(const rasp::Config& config, const void* /*unused*/) {
  return rasp::is_check_enabled(config, "debugger") ? std::vector{rasp::failed("dbg.traced", "sysctl")}
                                                    : std::vector<rasp::Observation>{};
}

/// Produces no builtins, exposing missing coverage.
std::vector<rasp::Observation> empty_builtins(const rasp::Config& /*unused*/, const void* /*unused*/) { return {}; }

/// A plugin output deliberately collides with a builtin identity.
std::vector<rasp::Observation> plugin_check(rasp::plugins::Context& context) {
  EXPECT_FALSE(context.get(rasp::plugins::kCycleSnapshot).has_value());
  context.put(kOrder, context.get(kOrder).value_or("") + "check;");
  return {rasp::unsupported("dbg.traced", "sysctl")};
}

/// Reads the atomic snapshot before asynchronous handoff and retains it.
void legacy_callback(std::span<const rasp::Observation> observations, rasp::plugins::Context& context) {
  const auto snapshot = context.get(rasp::plugins::kCycleSnapshot);
  ASSERT_TRUE(snapshot.has_value());
  EXPECT_EQ((*snapshot)->observations, std::vector(observations.begin(), observations.end()));
  EXPECT_TRUE((*snapshot)->metadata.execution_finished);
  context.put(kRetained, *snapshot);
  context.put(kOrder, context.get(kOrder).value_or("") + "legacy;");
}

/// Confirms the additive callback gets exactly the same immutable object.
void cycle_callback(const std::shared_ptr<const rasp::CycleSnapshot>& snapshot, rasp::plugins::Context& context) {
  const auto retained = context.get(kRetained);
  ASSERT_TRUE(retained.has_value());
  EXPECT_EQ(*retained, snapshot);
  context.put(kOrder, context.get(kOrder).value_or("") + "cycle;");
}

/// Returns equal monotonic ticks and a valid wall-clock boundary.
rasp::CycleClockReading equal_clock() { return {.monotonic_ns = 5, .unix_ms = 946684800000LL}; }
/// Returns unavailable clocks.
rasp::CycleClockReading failed_clock() { return {}; }
/// Returns an excluded wall-clock upper bound.
rasp::CycleClockReading invalid_wall_clock() { return {.monotonic_ns = 5, .unix_ms = 4102444800000LL}; }

TEST(Cycle, run_whenConsecutiveAndNextMonitor_ownsStableSessionUniqueRunsAndSnapshots) {
  rasp::CycleMonitor monitor;
  rasp::plugins::Context context;
  constexpr std::array kChecks{plugin_check};
  const rasp::plugins::Plugin plugin{
      .init = nullptr,
      .checks = kChecks,
      .on_observations = legacy_callback,
      .on_cycle = cycle_callback,
  };
  const std::array plugins{&plugin};
  const rasp::Config config{.build_id = "test", .checks = std::vector<std::string>{"debugger"}};
  const auto first = monitor.run(config, kCatalogue, plugins, context, builtins);
  EXPECT_EQ(first->observations.size(), 2U);
  EXPECT_TRUE(first->metadata.complete);
  EXPECT_EQ(first->metadata.status_counts[2], 1U);
  EXPECT_EQ(first->metadata.status_counts[1], 1U);
  EXPECT_EQ(first->metadata.plugin_observations, 1U);
  EXPECT_EQ(context.get(kOrder), "check;legacy;cycle;");
  EXPECT_FALSE(context.get(rasp::plugins::kCycleSnapshot).has_value());
  const auto second = monitor.run(config, kCatalogue, plugins, context, builtins);
  EXPECT_EQ(first->metadata.session_id, second->metadata.session_id);
  EXPECT_NE(first->metadata.run_id, second->metadata.run_id);
  EXPECT_EQ(first->metadata.sequence, 1U);
  EXPECT_EQ(second->metadata.sequence, 2U);
  EXPECT_EQ(first->observations.size(), 2U);
  EXPECT_NE(first, second);
  rasp::CycleMonitor next;
  EXPECT_NE(first->metadata.session_id,
            next.run(config, kCatalogue, kNoPlugins, context, builtins)->metadata.session_id);
}

TEST(Cycle, run_whenPluginMatchesMissingBuiltin_doesNotRepairCoverage) {
  rasp::CycleMonitor monitor;
  rasp::plugins::Context context;
  constexpr std::array kChecks{plugin_check};
  const rasp::plugins::Plugin plugin{.init = nullptr, .checks = kChecks};
  const std::array plugins{&plugin};
  const auto snapshot = monitor.run({.build_id = "test", .checks = std::vector<std::string>{"debugger"}}, kCatalogue,
                                    plugins, context, empty_builtins);
  EXPECT_FALSE(snapshot->metadata.complete);
  EXPECT_EQ(snapshot->metadata.missing.size(), 1U);
  EXPECT_EQ(snapshot->metadata.seen, 0U);
  EXPECT_EQ(snapshot->metadata.plugin_observations, 1U);
}

TEST(Cycle, run_whenDisabledUnknownOrUnavailable_distinguishesConfigStates) {
  rasp::CycleMonitor monitor;
  rasp::plugins::Context context;
  const auto disabled = monitor.run({.build_id = "test", .checks = std::vector<std::string>{}}, kCatalogue, kNoPlugins,
                                    context, builtins);
  EXPECT_TRUE(disabled->metadata.complete);
  EXPECT_EQ(disabled->metadata.expected, 0U);
  ASSERT_EQ(disabled->metadata.groups.size(), 1U);
  EXPECT_EQ(disabled->metadata.groups[0].enabled, false);
  const auto unknown = monitor.run(unknown_config(), kCatalogue, kNoPlugins, context, builtins);
  EXPECT_FALSE(unknown->metadata.complete);
  EXPECT_FALSE(unknown->metadata.expected.has_value());
  EXPECT_FALSE(unknown->metadata.groups[0].enabled.has_value());
  const auto foreign = monitor.run({.build_id = "test", .checks = std::vector<std::string>{"foreign"}}, kCatalogue, {},
                                   context, builtins);
  EXPECT_FALSE(foreign->metadata.complete);
  EXPECT_EQ(foreign->metadata.unknown_groups, 1U);
  const auto no_catalogue = monitor.run(unknown_config(), unknown_catalogue(), kNoPlugins, context, builtins);
  EXPECT_FALSE(no_catalogue->metadata.catalogue_known);
}

TEST(Cycle, run_whenClockOrSequenceFails_neverInventsValidTimingOrWraps) {
  rasp::plugins::Context context;
  const rasp::Config config{.build_id = "test", .checks = std::vector<std::string>{}};
  rasp::CycleMonitor equal(equal_clock);
  const auto valid = equal.run(config, kCatalogue, kNoPlugins, context, builtins);
  EXPECT_EQ(valid->metadata.duration_ns, 0U);
  EXPECT_TRUE(valid->metadata.complete);
  EXPECT_EQ(valid->metadata.observed_at_unix_ms, 946684800000LL);
  rasp::CycleMonitor failed(failed_clock);
  const auto invalid = failed.run(config, kCatalogue, kNoPlugins, context, builtins);
  EXPECT_FALSE(invalid->metadata.complete);
  EXPECT_FALSE(invalid->metadata.duration_ns.has_value());
  rasp::CycleMonitor wall(invalid_wall_clock);
  EXPECT_FALSE(wall.run(config, kCatalogue, kNoPlugins, context, builtins)->metadata.observed_at_unix_ms.has_value());
  rasp::CycleMonitor exhausted(equal_clock, std::numeric_limits<std::uint64_t>::max() - 1);
  const auto last = exhausted.run(config, kCatalogue, kNoPlugins, context, builtins);
  EXPECT_EQ(last->metadata.sequence, std::numeric_limits<std::uint64_t>::max());
  const auto overflow = exhausted.run(config, kCatalogue, kNoPlugins, context, builtins);
  EXPECT_FALSE(overflow->metadata.sequence.has_value());
  EXPECT_TRUE(overflow->metadata.overflow);
  EXPECT_FALSE(overflow->metadata.complete);
}

/// Produces more than the cycle limit and an oversized string.
std::vector<rasp::Observation> oversized(const rasp::Config& /*unused*/, const void* /*unused*/) {
  std::vector<rasp::Observation> observations(300, rasp::unsupported("extra", "test"));
  observations[0] = rasp::observed("extra", "test", std::string(1025, 'x'));
  return observations;
}

TEST(Cycle, run_whenCapped_reportsDropsExtrasAndPartial) {
  rasp::CycleMonitor monitor;
  rasp::plugins::Context context;
  const auto snapshot = monitor.run({.build_id = "test", .checks = std::vector<std::string>{}}, kCatalogue, kNoPlugins,
                                    context, oversized);
  EXPECT_EQ(snapshot->observations.size(), 256U);
  EXPECT_EQ(snapshot->metadata.dropped, 44U);
  EXPECT_EQ(snapshot->metadata.extra, 300U);
  EXPECT_FALSE(snapshot->metadata.complete);
  EXPECT_TRUE(snapshot->metadata.execution_finished);
}

TEST(Cycle, dispatch_whenLegacyDirect_hasNoMetadataAndDoesNotCallCycleCallback) {
  rasp::plugins::Context context;
  rasp::CycleMonitor monitor;
  static_cast<void>(monitor.run(unknown_config(), kCatalogue, kNoPlugins, context, builtins));
  const rasp::plugins::Plugin plugin{.init = nullptr, .checks = {}, .on_cycle = cycle_callback};
  const std::array plugins{&plugin};
  EXPECT_TRUE(rasp::plugins::run_plugins(plugins, {}, context).empty());
  EXPECT_FALSE(context.get(rasp::plugins::kCycleSnapshot).has_value());
}

TEST(Cycle, run_whenConcurrentOnSharedContext_serializesWithoutSnapshotBleed) {
  rasp::plugins::Context context;
  rasp::CycleMonitor first;
  rasp::CycleMonitor second;
  constexpr std::array kChecks{plugin_check};
  const rasp::plugins::Plugin plugin{
      .init = nullptr,
      .checks = kChecks,
      .on_observations = legacy_callback,
      .on_cycle = cycle_callback,
  };
  const std::array plugins{&plugin};
  const auto run = [&](rasp::CycleMonitor& monitor) {
    for (int index = 0; index < 20; ++index) {
      const auto snapshot = monitor.run(unknown_config(), kCatalogue, plugins, context, builtins);
      EXPECT_EQ(snapshot->observations.size(), 1U);
    }
  };
  std::thread other([&] { run(first); });
  run(second);
  other.join();
  EXPECT_FALSE(context.get(rasp::plugins::kCycleSnapshot).has_value());
}

/// Copies controlled builtin output through the actual monitor dispatch seam.
std::vector<rasp::Observation> supplied_builtins(const rasp::Config& /*unused*/, const void* argument) {
  return *static_cast<const std::vector<rasp::Observation>*>(argument);
}

/// Per-thread clock boundary for backwards and negative sample tests.
std::int64_t& clock_tick() {
  thread_local std::int64_t ticks = 2;
  return ticks;
}
/// Supplies decreasing monotonic readings and an invalid wall-clock lower bound.
rasp::CycleClockReading reverse_clock() { return {.monotonic_ns = clock_tick()--, .unix_ms = 946684799999LL}; }

TEST(Cycle, run_whenBackwardsOrNegativeClock_reportsUnavailableDuration) {
  const rasp::Config config{.build_id = "test", .checks = std::vector<std::string>{}};
  rasp::plugins::Context context;
  clock_tick() = 2;
  rasp::CycleMonitor reverse(reverse_clock);
  const auto backwards = reverse.run(config, kCatalogue, kNoPlugins, context, empty_builtins);
  EXPECT_FALSE(backwards->metadata.duration_ns.has_value());
  EXPECT_FALSE(backwards->metadata.observed_at_unix_ms.has_value());
  EXPECT_FALSE(backwards->metadata.complete);
  clock_tick() = -1;
  EXPECT_FALSE(reverse.run(config, kCatalogue, kNoPlugins, context, empty_builtins)->metadata.duration_ns.has_value());
}

TEST(Cycle, run_whenErrorUnsupportedAndTimeoutPresent_countsThemWithoutMissingCoverage) {
  constexpr std::array kStatusOutputs{
      rasp::CycleOutput{.group = "debugger", .signal = "one", .source = "test"},
      rasp::CycleOutput{.group = "debugger", .signal = "two", .source = "test"},
      rasp::CycleOutput{.group = "debugger", .signal = "three", .source = "test"},
  };
  const rasp::CycleCatalogue catalogue{.platform = "ios", .catalogue_id = "test", .outputs = kStatusOutputs};
  std::vector observations{
      rasp::failed("one", "test"),
      rasp::unsupported("two", "test"),
      rasp::failed("three", "test"),
  };
  observations[2].status = rasp::Status::kTimeout;
  rasp::plugins::Context context;
  rasp::CycleMonitor monitor;
  const auto snapshot = monitor.run({.build_id = "test", .checks = std::vector<std::string>{"debugger"}}, catalogue, {},
                                    context, supplied_builtins, &observations);
  EXPECT_TRUE(snapshot->metadata.complete);
  EXPECT_EQ(snapshot->metadata.seen, 3U);
  EXPECT_TRUE(snapshot->metadata.missing.empty());
  EXPECT_EQ(snapshot->metadata.status_counts, (std::array<std::uint64_t, 4>{0, 1, 1, 1}));
  observations[0].status = std::bit_cast<rasp::Status>(std::uint8_t{255});
  const auto invalid = monitor.run({.build_id = "test", .checks = std::vector<std::string>{"debugger"}}, catalogue, {},
                                   context, supplied_builtins, &observations);
  EXPECT_FALSE(invalid->metadata.complete);
  EXPECT_EQ(invalid->metadata.unknown_status, 1U);
}

TEST(Cycle, run_whenDuplicateDisabledOrForeignBuiltin_countsExtras) {
  std::vector observations{
      rasp::unsupported("dbg.traced", "sysctl"),
      rasp::unsupported("dbg.traced", "sysctl"),
      rasp::failed("foreign", "test"),
  };
  rasp::plugins::Context context;
  rasp::CycleMonitor monitor;
  const auto snapshot = monitor.run({.build_id = "test", .checks = std::vector<std::string>{"debugger"}}, kCatalogue,
                                    kNoPlugins, context, supplied_builtins, &observations);
  EXPECT_EQ(snapshot->metadata.seen, 1U);
  EXPECT_EQ(snapshot->metadata.extra, 2U);
  EXPECT_FALSE(snapshot->metadata.complete);
  const auto disabled = monitor.run({.build_id = "test", .checks = std::vector<std::string>{}}, kCatalogue, kNoPlugins,
                                    context, supplied_builtins, &observations);
  EXPECT_EQ(disabled->metadata.extra, 3U);
  EXPECT_EQ(disabled->metadata.expected, 0U);
}

TEST(Cycle, run_whenPayloadLimitsHit_dropsWholeObservationsAndBoundsText) {
  rasp::plugins::Context context;
  rasp::CycleMonitor monitor;
  const rasp::Config config{.build_id = "test", .checks = std::vector<std::string>{}};
  std::vector observations{rasp::observed("x", "s", std::string(1024, 'x'))};
  const auto text = monitor.run(config, kCatalogue, kNoPlugins, context, supplied_builtins, &observations);
  EXPECT_EQ(text->observations.size(), 1U);
  observations.push_back(rasp::observed("x", "s", std::vector<std::string>(65, "")));
  observations.push_back(rasp::observed(std::string(97, 'x'), "s", false));
  const auto oversized_items = monitor.run(config, kCatalogue, kNoPlugins, context, supplied_builtins, &observations);
  EXPECT_EQ(oversized_items->observations.size(), 1U);
  EXPECT_EQ(oversized_items->metadata.dropped, 2U);
  observations = std::vector(100, rasp::observed("x", "s", std::string(1024, 'x')));
  const auto bytes = monitor.run(config, kCatalogue, kNoPlugins, context, supplied_builtins, &observations);
  EXPECT_EQ(bytes->observations.size(), 63U);
  EXPECT_EQ(bytes->metadata.dropped, 37U);
  EXPECT_FALSE(bytes->metadata.complete);
}

TEST(Cycle, run_whenCatalogueHasDuplicateIdentities_keepsCoverageUnknownWithoutClaimingTruncation) {
  const std::array outputs{kOutputs[0], kOutputs[0]};
  const rasp::CycleCatalogue catalogue{.platform = "ios", .catalogue_id = "test", .outputs = outputs};
  rasp::plugins::Context context;
  rasp::CycleMonitor monitor;
  const auto snapshot = monitor.run({.build_id = "test", .checks = std::vector<std::string>{"debugger"}}, catalogue,
                                    kNoPlugins, context, builtins);
  EXPECT_TRUE(snapshot->metadata.execution_finished);
  EXPECT_FALSE(snapshot->metadata.catalogue_known);
  EXPECT_FALSE(snapshot->metadata.catalogue_truncated);
  EXPECT_FALSE(snapshot->metadata.complete);
  EXPECT_FALSE(snapshot->metadata.expected.has_value());
  EXPECT_TRUE(snapshot->metadata.missing.empty());
  EXPECT_EQ(snapshot->metadata.dropped, 0U);
}

TEST(Cycle, run_whenConfigOrCatalogueExceedsBounds_reportsTruncationAndUnknownCoverage) {
  rasp::plugins::Context context;
  rasp::CycleMonitor monitor;
  const auto config = monitor.run({.build_id = "test", .checks = std::vector<std::string>(65, "debugger")}, kCatalogue,
                                  kNoPlugins, context, builtins);
  EXPECT_TRUE(config->metadata.config_truncated);
  EXPECT_FALSE(config->metadata.config_known);
  EXPECT_FALSE(config->metadata.expected.has_value());
  const std::vector outputs(257, kOutputs[0]);
  const rasp::CycleCatalogue catalogue{.platform = "ios", .catalogue_id = "test", .outputs = outputs};
  const auto too_many = monitor.run(unknown_config(), catalogue, kNoPlugins, context, empty_builtins);
  EXPECT_TRUE(too_many->metadata.catalogue_truncated);
  EXPECT_FALSE(too_many->metadata.catalogue_known);
  EXPECT_FALSE(too_many->metadata.complete);
  EXPECT_TRUE(too_many->metadata.groups.empty());
}

/// Checks immutable data after the real consumer has waited across multiple runs.
void check_first_snapshot(const rasp::CycleSnapshot& snapshot) {
  EXPECT_EQ(snapshot.metadata.sequence, 1U);
  EXPECT_EQ(snapshot.observations, (std::vector{rasp::failed("dbg.traced", "sysctl")}));
}

TEST(Cycle, run_whenDelayedConsumerRetainsFirstSnapshot_laterCyclesCannotChangeIt) {
  rasp::plugins::Context context;
  rasp::CycleMonitor monitor;
  const rasp::plugins::Plugin plugin{.init = nullptr, .checks = {}, .on_observations = legacy_callback};
  const std::array plugins{&plugin};
  const rasp::Config config{.build_id = "test", .checks = std::vector<std::string>{"debugger"}};
  const auto first = monitor.run(config, kCatalogue, plugins, context, builtins);
  const auto held = context.get(kRetained);
  ASSERT_TRUE(held.has_value());
  const auto& retained = *held;
  ASSERT_EQ(first, retained);
  std::binary_semaphore ready(0);
  std::thread consumer([retained, &ready] {
    ready.acquire();
    check_first_snapshot(*retained);
  });
  for (int index = 0; index < 3; ++index) {
    static_cast<void>(monitor.run(config, kCatalogue, plugins, context, builtins));
  }
  ready.release();
  consumer.join();
  const auto later = context.get(kRetained);
  ASSERT_TRUE(later.has_value());
  EXPECT_NE(*later, retained);
}

TEST(Cycle, dispatch_whenMultiplePlugins_finishesEveryCheckBeforeOrderedCallbacks) {
  rasp::plugins::Context context;
  rasp::CycleMonitor monitor;
  constexpr std::array kChecks{plugin_check};
  const rasp::plugins::Plugin plugin{
      .init = nullptr,
      .checks = kChecks,
      .on_observations = legacy_callback,
      .on_cycle = cycle_callback,
  };
  const std::array plugins{&plugin, &plugin};
  const auto snapshot = monitor.run(unknown_config(), kCatalogue, plugins, context, empty_builtins);
  EXPECT_EQ(context.get(kOrder), "check;check;legacy;cycle;legacy;cycle;");
  EXPECT_EQ(snapshot->observations.size(), 2U);
}

/// Gates a real synchronous check while the test inspects its unpublished state.
struct WaitingCheck {
  /// Signals that the measurement has started.
  mutable std::binary_semaphore entered{0};
  /// Allows the measurement to return.
  mutable std::binary_semaphore release{0};
};

/// Waits at the measurement boundary without manufacturing a timeout observation.
std::vector<rasp::Observation> waiting_builtins([[maybe_unused]] const rasp::Config& config, const void* argument) {
  const auto& check = *static_cast<const WaitingCheck*>(argument);
  check.entered.release();
  check.release.acquire();
  return {};
}

TEST(Cycle, run_whenMeasurementHasNotReturned_doesNotPublishFinishedSnapshot) {
  rasp::plugins::Context context;
  rasp::CycleMonitor monitor;
  WaitingCheck check;
  std::shared_ptr<const rasp::CycleSnapshot> result;
  const rasp::plugins::Plugin plugin{.init = nullptr, .checks = {}, .on_observations = legacy_callback};
  const std::array plugins{&plugin};
  std::thread measurement(
      [&] { result = monitor.run(unknown_config(), kCatalogue, plugins, context, waiting_builtins, &check); });
  check.entered.acquire();
  EXPECT_FALSE(context.get(rasp::plugins::kCycleSnapshot).has_value());
  EXPECT_FALSE(context.get(kRetained).has_value());
  check.release.release();
  measurement.join();
  ASSERT_NE(result, nullptr);
  EXPECT_TRUE(result->metadata.execution_finished);
}

TEST(Cycle, run_whenCollectorReturns128EntryList_reportsWholeDropAndLegacyCallbackLimit) {
  constexpr std::array kServiceOutputs{
      rasp::CycleOutput{.group = "services", .signal = "service.list", .source = "fixture"},
  };
  const rasp::CycleCatalogue catalogue{.platform = "android", .catalogue_id = "fixture", .outputs = kServiceOutputs};
  const std::vector observations{rasp::observed("service.list", "fixture", std::vector<std::string>(128, "service"))};
  rasp::plugins::Context context;
  rasp::CycleMonitor monitor;
  const rasp::plugins::Plugin plugin{.init = nullptr, .checks = {}, .on_observations = legacy_callback};
  const std::array plugins{&plugin};
  const auto snapshot = monitor.run({.build_id = "test", .checks = std::vector<std::string>{"services"}}, catalogue,
                                    plugins, context, supplied_builtins, &observations);
  EXPECT_TRUE(snapshot->observations.empty());
  EXPECT_EQ(snapshot->metadata.dropped, 1U);
  EXPECT_EQ(snapshot->metadata.seen, 1U);
  EXPECT_TRUE(snapshot->metadata.missing.empty());
  EXPECT_FALSE(snapshot->metadata.complete);
  const auto legacy = rasp::plugins::run_plugins(kNoPlugins, observations, context);
  EXPECT_EQ(legacy, observations);
}

}  // namespace
