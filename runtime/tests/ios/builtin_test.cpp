/// Compiled tests of iOS check selection and dispatch, including the integrity group.

#include "builtin.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <memory>
#include <span>
#include <string>
#include <variant>
#include <vector>

#include "capture/capture_events.h"
#include "checks/capture.h"
#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/cycle.h"
#include "rasp/decision.h"
#include "rasp/observation.h"
#include "rasp/plugin.h"

namespace rasp::ios {
namespace {
TEST(Builtin, runChecks_whenIntegritySelected_dispatchesTypedObservations) {
  Config config;
  config.checks = {"integrity"};
  EXPECT_EQ(run_checks(config, ""), (std::vector<Observation>{unsupported("integ.text_sha256", "file"),
                                                              unsupported("integ.text_sha256", "memory")}));
}
TEST(Builtin, runChecks_whenIntegrityNotSelected_doesNotDispatchIntegrity) {
  Config config;
  config.checks = {"debugger"};
  const auto observations = run_checks(config, "");
  ASSERT_FALSE(observations.empty());
  for (const auto& observation : observations) {
    EXPECT_NE(observation.signal, "integ.text_sha256");
  }
}
TEST(Builtin, runChecks_whenCaptureGroupsSelected_emitsEveryUnsupportedIdentityOffIOS) {
  Config config;
  config.checks = {"screenshot", "screen_recording"};
  const auto observations = run_checks(config, "");
  ASSERT_EQ(observations.size(), 26U);
  for (const auto& observation : observations) {
    EXPECT_EQ(observation.status, Status::kUnsupported);
    EXPECT_TRUE(std::holds_alternative<std::monostate>(observation.value));
  }
}

/// Constant checked clock for finite freshness and selected-drain integration tests.
CycleClockReading capture_clock() { return {.monotonic_ns = 0}; }
/// Extracts a scalar while retaining a failed lookup as a test failure.
Value capture_value(const std::vector<Observation>& observations, std::string_view signal, std::string_view source) {
  const auto found = std::ranges::find_if(
      observations, [&](const Observation& value) { return value.signal == signal && value.source == source; });
  EXPECT_NE(found, observations.end());
  return found == observations.end() ? Value{} : found->value;
}
TEST(Builtin, runChecks_whenSupportedAndHostAbsent_reportsUnavailableInsteadOfNegative) {
  capture::CaptureEvents events(capture_clock);
  const capture::Input input{.events = &events, .platform = capture::Platform::kScene};
  Config config;
  config.checks = {"screenshot", "screen_recording"};
  const auto rows = run_checks(config, "", &input);
  ASSERT_EQ(rows.size(), 26U);
  EXPECT_EQ(capture_value(rows, "capture.recording.observer_state", "uikit_capture_observer"),
            Value(std::string("never_started")));
  EXPECT_EQ(capture_value(rows, "capture.recording.state", "uikit_scene_trait"), Value{});
  EXPECT_EQ(rows[13].status, Status::kError);
}
TEST(Builtin, runChecks_whenSingleSourceSelected_doesNotConsumeAnotherGroupOrIdentityDefaults) {
  capture::CaptureEvents events(capture_clock);
  const auto session = events.start(true, true);
  events.screenshot_ready(session, true);
  events.screenshot(session);
  const auto generation = events.open(session, capture::Scope::kScene);
  events.registered(session, generation);
  events.sample(session, generation, events.ticket(session, generation), capture::SampleKind::kInitial, 1);
  events.sample(session, generation, events.ticket(session, generation), capture::SampleKind::kCallback, 0);
  const capture::Input input{.events = &events, .platform = capture::Platform::kScene};
  EXPECT_TRUE(run_checks(Config{}, "", &input).empty());
  Config config;
  config.checks = {"identity"};
  static_cast<void>(run_checks(config, "", &input));
  config.checks = {"unknown"};
  EXPECT_TRUE(run_checks(config, "", &input).empty());
  config.checks = {"screen_recording"};
  EXPECT_EQ(
      capture_value(run_checks(config, "", &input), "capture.recording.callback_events", "uikit_capture_observer"),
      Value(std::int64_t{1}));
  config.checks = {"screenshot"};
  EXPECT_EQ(
      capture_value(run_checks(config, "", &input), "capture.screenshot.callback_events", "uiapplication_screenshot"),
      Value(std::int64_t{1}));
}
TEST(Builtin, runChecks_whenLegacySelectedScreen_keepsSceneUnsupportedAndScreenScopeExplicit) {
  capture::CaptureEvents events(capture_clock);
  const auto session = events.start(false, true);
  const auto generation = events.open(session, capture::Scope::kScreen);
  events.registered(session, generation);
  events.sample(session, generation, events.ticket(session, generation), capture::SampleKind::kInitial, 0);
  const capture::Input input{.events = &events, .platform = capture::Platform::kLegacy};
  Config config;
  config.checks = {"screen_recording"};
  const auto rows = run_checks(config, "", &input);
  EXPECT_EQ(rows[4].status, Status::kUnsupported);
  EXPECT_EQ(capture_value(rows, "capture.recording.state", "uikit_screen_capture"), Value(false));
  EXPECT_EQ(capture_value(rows, "capture.recording.scope", "uikit_capture_observer"),
            Value(std::string("selected_screen")));
}
constexpr plugins::Key<std::shared_ptr<const CycleSnapshot>> kCaptureLegacy{"test.ios.capture.legacy"};
/// Legacy callback retains the same snapshot owner as the additive callback.
void capture_legacy(std::span<const Observation> rows, plugins::Context& context) {
  const auto snapshot = context.get(plugins::kCycleSnapshot);
  ASSERT_TRUE(snapshot.has_value());
  EXPECT_EQ(rows.data(), (*snapshot)->observations.data());
  EXPECT_EQ((*snapshot)->local_decisions.reason, LocalReason::kNone);
  EXPECT_EQ((*snapshot)->local_decisions.builtin_observations, rows.size());
  EXPECT_EQ((*snapshot)->local_decisions.predicates_evaluated, 0U);
  std::size_t capture_rules = 0;
  for (const auto& decision : (*snapshot)->local_decisions.rows) {
    if (decision.rule_id.starts_with("local.ios.capture.")) {
      ++capture_rules;
      EXPECT_EQ(decision.verdict, LocalVerdict::kUnknown);
      EXPECT_EQ(decision.severity, LocalSeverity::kUnknown);
      EXPECT_FALSE(decision.predicate_evaluated);
    }
  }
  EXPECT_EQ(capture_rules, 26U);

  context.put(kCaptureLegacy, *snapshot);
}
/// Additive callback verifies the shared immutable owner during actual dispatch.
void capture_cycle(const std::shared_ptr<const CycleSnapshot>& snapshot, plugins::Context& context) {
  const auto retained = context.get(kCaptureLegacy);
  ASSERT_TRUE(retained.has_value());
  EXPECT_EQ(*retained, snapshot);
  context.put(kCaptureLegacy, snapshot);
}
TEST(Builtin, monitor_whenCaptureDrainsAgain_retainsEarlierOwnedCycleAfterContextDestruction) {
  capture::CaptureEvents events(capture_clock);
  const auto session = events.start(true, true);
  events.screenshot_ready(session, true);
  events.screenshot(session);
  const capture::Input input{.events = &events, .platform = capture::Platform::kScene};
  Config config;
  config.checks = {"screenshot", "screen_recording"};
  const plugins::Plugin plugin{
      .init = nullptr,
      .checks = {},
      .on_observations = capture_legacy,
      .on_cycle = capture_cycle,
  };
  const std::array<const plugins::Plugin*, 1> plugins{&plugin};
  std::shared_ptr<const CycleSnapshot> retained;
  {
    plugins::Context context;
    CycleMonitor monitor;
    const auto builtin = [](const Config& selection, const void* state) {
      return run_checks(selection, "", static_cast<const capture::Input*>(state));
    };
    retained = monitor.run(config, cycle_catalogue("ios"), plugins, context, builtin, &input);
    ASSERT_TRUE(retained->metadata.complete);
    ASSERT_EQ(retained->observations.size(), 26U);
    const auto later = monitor.run(config, cycle_catalogue("ios"), plugins, context, builtin, &input);
    EXPECT_EQ(capture_value(later->observations, "capture.screenshot.callback_events", "uiapplication_screenshot"),
              Value(std::int64_t{0}));
    EXPECT_FALSE(context.get(plugins::kCycleSnapshot).has_value());
  }
  events.stop(session);
  EXPECT_EQ(capture_value(retained->observations, "capture.screenshot.callback_events", "uiapplication_screenshot"),
            Value(std::int64_t{1}));
}

TEST(Builtin, monitor_whenMeasuredCaptureGroupIsEnabled_preservesUnknownDecisionAndDisabledDrain) {
  capture::CaptureEvents events(capture_clock);
  const auto session = events.start(true, true);
  events.screenshot_ready(session, true);
  events.screenshot(session);
  const auto generation = events.open(session, capture::Scope::kScene);
  events.registered(session, generation);
  events.sample(session, generation, events.ticket(session, generation), capture::SampleKind::kInitial, 1);
  const capture::Input input{.events = &events, .platform = capture::Platform::kScene};
  CycleMonitor monitor;
  plugins::Context context;
  Config config;
  config.checks = {"screenshot"};
  const auto builtin = [](const Config& selection, const void* state) {
    return run_checks(selection, "", static_cast<const capture::Input*>(state));
  };
  const auto disabled = monitor.run(config, cycle_catalogue("ios"), {}, context, builtin, &input);
  ASSERT_EQ(disabled->local_decisions.reason, LocalReason::kNone);
  const std::string capture_rule = "local.ios.capture.recording.state.uikit_scene_trait";
  const auto first = std::ranges::find(disabled->local_decisions.rows, capture_rule, &LocalDecision::rule_id);
  ASSERT_NE(first, disabled->local_decisions.rows.end());
  EXPECT_EQ(first->reason, LocalReason::kConfigDisabled);
  config.checks = {"screen_recording"};
  const auto measured = monitor.run(config, cycle_catalogue("ios"), {}, context, builtin, &input);
  ASSERT_EQ(measured->local_decisions.reason, LocalReason::kNone);
  EXPECT_TRUE(measured->metadata.complete);
  EXPECT_EQ(capture_value(measured->observations, "capture.recording.state", "uikit_scene_trait"),
            Value(std::string("active")));
  EXPECT_EQ(capture_value(measured->observations, "capture.recording.initial_samples", "uikit_capture_observer"),
            Value(std::int64_t{1}));
  const auto second = std::ranges::find(measured->local_decisions.rows, capture_rule, &LocalDecision::rule_id);
  ASSERT_NE(second, measured->local_decisions.rows.end());
  EXPECT_EQ(second->reason, LocalReason::kUnregisteredRule);
  EXPECT_EQ(second->verdict, LocalVerdict::kUnknown);
  EXPECT_EQ(second->severity, LocalSeverity::kUnknown);
  EXPECT_FALSE(second->predicate_evaluated);
  EXPECT_EQ(measured->local_decisions.predicates_evaluated, 0U);
}
TEST(Builtin, runChecks_whenNoChecksSelected_returnsNoObservations) { EXPECT_TRUE(run_checks(Config{}, "").empty()); }
TEST(Builtin, runChecks_whenOwnedMonitorDispatchesRealIntegrity_preservesUnsupportedWithoutCleanVerdict) {
  CycleMonitor monitor;
  plugins::Context context;
  const Config config{.build_id = "test", .checks = std::vector<std::string>{"integrity"}};
  const auto snapshot = monitor.run(config, cycle_catalogue("ios"), {}, context,
                                    [](const Config& selection, const void*) { return run_checks(selection, ""); });
  EXPECT_EQ(snapshot->local_decisions.builtin_observations, 2U);
  EXPECT_EQ(snapshot->local_decisions.coverage, LocalCoverage::kComplete);
  EXPECT_EQ(snapshot->local_decisions.predicates_evaluated, 0U);
  for (const auto& decision : snapshot->local_decisions.rows) {
    EXPECT_EQ(decision.verdict, LocalVerdict::kUnknown);
  }
}
}  // namespace
}  // namespace rasp::ios
