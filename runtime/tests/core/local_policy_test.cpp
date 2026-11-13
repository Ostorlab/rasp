/// Policy denial is tested before the real host-owned receipt operation, using actual typed cycles.
#include "rasp/local_policy.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <gtest/gtest.h>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "decision_registry.h"
#include "local_policy_clock.h"
#include "local_policy_selectors.h"
#include "local_policy_state.h"
#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/cycle.h"
#include "rasp/decision.h"
#include "rasp/local_policy_host.h"
#include "rasp/observation.h"
#include "rasp/parse_config.h"
#include "rasp/plugin.h"

namespace {
/// Deterministic boundary clock, never a replacement evaluator or action result.
std::int64_t& fixture_tick() {
  static thread_local std::int64_t value = 1000000000;
  return value;
}
/// Read injected external clock data.
std::optional<std::int64_t> clock_tick() { return fixture_tick() < 0 ? std::nullopt : std::optional(fixture_tick()); }
/// Exact final-parent policy; enabling only debugger keeps coverage assertions meaningful.
rasp::Config configuration(std::string_view mode = "gate") {
  return rasp::parse_config(
      std::string(
          R"({"build_id":"test","checks":["debugger"],"local_policy":{"schema_version":1,"engine_version":1,"policy_id":"demo","policy_version":1,"mode":")") +
      std::string(mode) +
      R"(","scope":"host_calls_only","platform":"android","catalogue_id":"fce392826ee1d9e5bab8046ca1584e2755af0eb3fd26922769eb20c64e32f736","report_schema_version":1,"report_reason_version":1,"native_metadata_version":1,"operations":[{"name":"append_demo_receipt","max_evidence_age_ms":75000,"max_cycle_duration_ms":5000,"rules":[{"rule_id":"native.android.dbg.tracer_pid.proc_status","rule_version":1}]}]}})");
}
/// All actual selected builtin identities, including unrelated baseline/context rows.
std::vector<rasp::Observation> observations(std::int64_t tracer, rasp::Status status = rasp::Status::kOk) {
  return {
      {.signal = "dbg.tracer_pid", .source = "proc_status", .status = status, .value = tracer},
      rasp::observed("dbg.tracer_pid", "proc_status_syscall", std::int64_t{0}),
      rasp::observed("dbg.java_debugger", "debug_api", false),
      rasp::observed("dbg.java_debugger", "jdwp_threads", std::vector<std::string>{}),
  };
}
/// Produce an actual owned typed report via the unchanged production evaluator.
std::shared_ptr<const rasp::CycleSnapshot> cycle(const rasp::Config& config,
                                                 const std::vector<rasp::Observation>& input) {
  rasp::CycleMonitor monitor;
  rasp::plugins::Context context;
  return monitor.run(
      config, rasp::cycle_catalogue("android"), {}, context,
      [](const rasp::Config&, const void* argument) {
        return *static_cast<const std::vector<rasp::Observation>*>(argument);
      },
      &input);
}
/// Request includes a host-compiled policy expectation, never a report/score.
struct RaspLocalGateRequestV1 request(const rasp::Config& config) {
  struct RaspLocalGateRequestV1 value{};
  value.abi_version = 1;
  value.struct_size = sizeof(value);
  std::ranges::copy(std::string_view("append_demo_receipt"), std::span(value.operation).begin());
  const auto hash = rasp::local_policy_hash(config.local_policy.canonical_json);
  std::ranges::copy(hash, std::span(value.expected_policy_sha256).begin());
  return value;
}
/// A real harmless host operation guarded at its actual call site.
void append_receipt(std::vector<int>& book, rasp::LocalPolicyState& state, const struct RaspLocalGateRequestV1& input) {
  auto output = std::make_unique<struct RaspLocalGateResultV1>();
  if (state.gate(input, *output) == RASP_LOCAL_OK && output->action == RASP_LOCAL_ALLOW) {
    book.push_back(1);
  }
}
TEST(LocalPolicy, gate_whenActualTypedPredicateChanges_gatesTheHostOperation) {
  for (const std::int64_t tracer : {0, 42}) {
    fixture_tick() = 1000000000;
    const auto config = configuration();
    ASSERT_EQ(config.local_policy.state, rasp::LocalPolicyStateKind::kGate);
    rasp::LocalPolicyState state(config, "android", clock_tick);
    state.begin_cycle();
    state.finish_cycle(cycle(config, observations(tracer)));
    std::vector<int> book;
    append_receipt(book, state, request(config));
    EXPECT_EQ(book.size(), tracer == 0 ? 1U : 0U);
  }
}
TEST(LocalPolicy, gate_whenCollectionUnavailable_deniesForgedPositiveAndZero) {
  for (const auto status : {rasp::Status::kUnsupported, rasp::Status::kError, rasp::Status::kTimeout}) {
    const auto config = configuration();
    rasp::LocalPolicyState state(config, "android", clock_tick);
    state.begin_cycle();
    state.finish_cycle(cycle(config, observations(0, status)));
    std::vector<int> book;
    append_receipt(book, state, request(config));
    EXPECT_TRUE(book.empty());
  }
}
TEST(LocalPolicy, gate_whenStartupOrStale_deniesBeforeOperation) {
  fixture_tick() = 1000000000;
  const auto config = configuration();
  rasp::LocalPolicyState state(config, "android", clock_tick);
  std::vector<int> book;
  append_receipt(book, state, request(config));
  EXPECT_TRUE(book.empty());
  state.begin_cycle();
  state.finish_cycle(cycle(config, observations(0)));
  fixture_tick() += 75000000000LL;
  append_receipt(book, state, request(config));
  ASSERT_EQ(book.size(), 1U);
  ++fixture_tick();
  append_receipt(book, state, request(config));
  EXPECT_EQ(book.size(), 1U);
}
TEST(LocalPolicy, gate_whenClockFails_cannotRevivePriorPublication) {
  fixture_tick() = 1000000000;
  const auto config = configuration();
  rasp::LocalPolicyState state(config, "android", clock_tick);
  state.begin_cycle();
  state.finish_cycle(cycle(config, observations(0)));
  std::vector<int> book;
  fixture_tick() = -1;
  append_receipt(book, state, request(config));
  fixture_tick() = 2000000000;
  append_receipt(book, state, request(config));
  EXPECT_TRUE(book.empty());
  state.begin_cycle();
  state.finish_cycle(cycle(config, observations(0)));
  append_receipt(book, state, request(config));
  EXPECT_EQ(book.size(), 1U);
}
TEST(LocalPolicy, gate_whenReportOnly_doesNotClaimDenial) {
  fixture_tick() = 1000000000;
  const auto config = configuration("report_only");
  rasp::LocalPolicyState state(config, "android", clock_tick);
  auto output = std::make_unique<struct RaspLocalGateResultV1>();
  EXPECT_EQ(state.gate(request(config), *output), RASP_LOCAL_OK);
  EXPECT_EQ(output->action, RASP_LOCAL_REPORT);
  EXPECT_EQ(output->candidate_action, RASP_LOCAL_DENY);
  std::vector<int> book;
  append_receipt(book, state, request(config));
  EXPECT_TRUE(book.empty());
  state.begin_cycle();
  state.finish_cycle(cycle(config, observations(0)));
  ASSERT_EQ(state.gate(request(config), *output), RASP_LOCAL_OK);
  EXPECT_EQ(output->action, RASP_LOCAL_REPORT);
  EXPECT_EQ(output->candidate_action, RASP_LOCAL_ALLOW);
  append_receipt(book, state, request(config));
  EXPECT_TRUE(book.empty());
}
/// The callback proves actual publication happened before callbacks under Context's dispatch lock.
constexpr rasp::plugins::Key<rasp::LocalPolicyState*> kPolicyState{"test.policy.state"};
/// Querying the gate from a callback never recursively takes Context's dispatch lock.
constexpr rasp::plugins::Key<bool> kPublished{"test.policy.published"};
void published(const std::shared_ptr<const rasp::CycleSnapshot>& snapshot, rasp::plugins::Context& context) {
  context.put(kPublished, true);
  const auto state = context.get(kPolicyState);
  if (!state.has_value()) {
    FAIL();
    return;
  }
  auto output = std::make_unique<struct RaspLocalGateResultV1>();
  const auto config = configuration();
  EXPECT_EQ((*state)->gate(request(config), *output), RASP_LOCAL_OK);
  EXPECT_EQ(output->action, RASP_LOCAL_ALLOW);
  EXPECT_STREQ(std::span(output->run_id).data(), snapshot->metadata.run_id.c_str());
  EXPECT_GE(snapshot.use_count(), 4);
}
TEST(LocalPolicy, publish_whenActualMonitorCompletes_ownsSnapshotBeforeCallbacks) {
  fixture_tick() = 1000000000;
  const auto config = configuration();
  rasp::LocalPolicyState state(config, "android", clock_tick);
  rasp::CycleMonitor monitor;
  rasp::plugins::Context context;
  context.put(kPolicyState, &state);
  const rasp::plugins::Plugin plugin{.init = nullptr, .checks = {}, .on_observations = nullptr, .on_cycle = published};
  const std::array<const rasp::plugins::Plugin*, 1> plugins{&plugin};
  const auto input = observations(0);
  auto snapshot = monitor.run(
      config, rasp::cycle_catalogue("android"), plugins, context,
      [](const rasp::Config&, const void* argument) {
        return *static_cast<const std::vector<rasp::Observation>*>(argument);
      },
      &input, &state);
  EXPECT_EQ(context.get(kPublished), true);
  const std::weak_ptr<const rasp::CycleSnapshot> retained = snapshot;
  snapshot.reset();
  EXPECT_FALSE(retained.expired());
  state.begin_cycle();
  state.finish_cycle(nullptr);
  EXPECT_TRUE(retained.expired());
}
TEST(LocalPolicy, info_whenCanonicalized_matchesIndependentPythonFixtureHashes) {
  const auto config = configuration();
  const rasp::LocalPolicyState state(config, "android", clock_tick);
  auto output = std::make_unique<struct RaspLocalPolicyInfoV1>();
  ASSERT_EQ(state.info(*output), RASP_LOCAL_OK);
  EXPECT_STREQ(std::span(output->policy_sha256).data(),
               "174e5db59a8f1bd3a657d8263d971b1507c66017b2513a2acda442deaa798cb0");
  EXPECT_STREQ(std::span(output->effective_config_sha256).data(),
               "bf0a61e97c74a069e5fac2b5fc5e622bbcfd63aa9668b38cd6ab606c326c8c8a");
}
TEST(LocalPolicy, parse_whenExplicitFieldsMalformed_cannotDowngradeToReportOnly) {
  const auto config = configuration();
  const std::string json =
      R"({"build_id":"test","checks":["debugger"],"local_policy":)" + config.local_policy.canonical_json + '}';
  constexpr std::array<std::pair<std::string_view, std::string_view>, 12> kMutations{
      {
          {R"("schema_version":1)", R"("schema_version":2)"},
          {R"("engine_version":1)", R"("engine_version":true)"},
          {R"("policy_version":1)", R"("policy_version":1e0)"},
          {R"("policy_version":1)", R"("policy_version":-0)"},
          {R"("mode":"gate")", R"("mode":"gate","mode":"gate")"},
          {R"("mode":"gate")", R"("mode":"kill")"},
          {R"("max_evidence_age_ms":75000)", R"("max_evidence_age_ms":999)"},
          {R"("max_cycle_duration_ms":5000)", R"("max_cycle_duration_ms":0)"},
          {R"("rule_version":1)", R"("rule_version":2)"},
          {
              "native.android.dbg.tracer_pid.proc_status",
              "local.android.capture.screenshot.observer_state.activity_screen_capture",
          },
          {R"("scope":"host_calls_only")", R"("scope":"every_operation")"},
          {R"("policy_id":"demo")", R"("policy_id":"bad\u0000name")"},
      },
  };
  for (const auto& [before, after] : kMutations) {
    std::string input = json;
    const auto offset = input.find(before);
    ASSERT_NE(offset, std::string::npos);
    input.replace(offset, before.size(), after);
    const auto parsed = rasp::parse_config(input);
    EXPECT_TRUE(parsed.local_policy.state == rasp::LocalPolicyStateKind::kInvalid ||
                parsed.local_policy.state == rasp::LocalPolicyStateKind::kUnsupported)
        << input;
    rasp::LocalPolicyState state(parsed, "android", clock_tick);
    auto output = std::make_unique<struct RaspLocalGateResultV1>();
    EXPECT_NE(state.gate(request(config), *output), RASP_LOCAL_OK);
    EXPECT_EQ(output->action, RASP_LOCAL_DENY);
  }
}
TEST(LocalPolicy, gate_whenNewPublicationIsIncomplete_neverFallsBackToOldBenign) {
  fixture_tick() = 1000000000;
  const auto config = configuration();
  rasp::LocalPolicyState state(config, "android", clock_tick);
  state.begin_cycle();
  state.finish_cycle(cycle(config, observations(0)));
  auto input = observations(42);
  input.pop_back();
  state.begin_cycle();
  state.finish_cycle(cycle(config, input));
  auto output = std::make_unique<struct RaspLocalGateResultV1>();
  ASSERT_EQ(state.gate(request(config), *output), RASP_LOCAL_OK);
  EXPECT_EQ(output->action, RASP_LOCAL_DENY);
  EXPECT_EQ(output->reason, RASP_LOCAL_COVERAGE_UNAVAILABLE);
  ASSERT_EQ(output->detail_count, 1U);
  EXPECT_EQ(output->details[0].verdict, static_cast<std::uint32_t>(rasp::LocalVerdict::kThreat));
}
TEST(LocalPolicy, gate_whenSlowCycleAtBoundary_checksNanosecondsWithoutFlooring) {
  for (const std::int64_t extra : {0, 1}) {
    fixture_tick() = 1000000000;
    const auto config = configuration();
    rasp::LocalPolicyState state(config, "android", clock_tick);
    state.begin_cycle();
    fixture_tick() += 5000000000LL + extra;
    state.finish_cycle(cycle(config, observations(0)));
    auto output = std::make_unique<struct RaspLocalGateResultV1>();
    ASSERT_EQ(state.gate(request(config), *output), RASP_LOCAL_OK);
    EXPECT_EQ(output->action, extra == 0 ? RASP_LOCAL_ALLOW : RASP_LOCAL_DENY);
  }
}
TEST(LocalPolicy, gate_whenReportBindingChanges_doesNotInheritSemantics) {
  for (const auto* const mode : {"gate", "report_only"}) {
    const auto config = configuration(mode);
    const auto snapshot = std::make_shared<rasp::CycleSnapshot>(*cycle(config, observations(0)));
    snapshot->local_decisions.schema_version = 2;
    rasp::LocalPolicyState state(config, "android", clock_tick);
    state.begin_cycle();
    state.finish_cycle(snapshot);
    auto output = std::make_unique<struct RaspLocalGateResultV1>();
    EXPECT_EQ(state.gate(request(config), *output), RASP_LOCAL_OK);
    EXPECT_EQ(output->action, config.local_policy.state == rasp::LocalPolicyStateKind::kReportOnly ? RASP_LOCAL_REPORT
                                                                                                   : RASP_LOCAL_DENY);
    EXPECT_EQ(output->candidate_action, RASP_LOCAL_DENY);
    EXPECT_EQ(output->reason, RASP_LOCAL_BINDING_MISMATCH);
  }
}
TEST(LocalPolicy, selectors_whenComparedToActualRegistry_excludeEveryUnknownOrContextPredicate) {
  ASSERT_EQ(rasp::policy_internal::kSelectors.size(), 20U);
  for (const auto& selector : rasp::policy_internal::kSelectors) {
    const auto* const found =
        std::ranges::find(rasp::decision_internal::kRules, selector.rule_id, &rasp::decision_internal::Rule::rule_id);
    ASSERT_NE(found, rasp::decision_internal::kRules.end());
    EXPECT_EQ(found->platform, selector.platform);
    EXPECT_EQ(found->group, selector.group);
    using rasp::decision_internal::Predicate;
    EXPECT_TRUE(found->predicate == Predicate::kTrue || found->predicate == Predicate::kPositive ||
                found->predicate == Predicate::kStrings || found->predicate == Predicate::kJdwp ||
                found->predicate == Predicate::kInline || found->predicate == Predicate::kThreads);
  }
}
TEST(LocalPolicy, clockConversion_whenInvalidOrOverflowed_returnsUnavailable) {
  using rasp::policy_internal::clock_nanoseconds;
  EXPECT_EQ(clock_nanoseconds(0, {.numerator = 1, .denominator = 1}), 0);
  EXPECT_EQ(clock_nanoseconds(3, {.numerator = 125, .denominator = 3}), 125);
  EXPECT_EQ(clock_nanoseconds(3, {.numerator = 1, .denominator = 2}), 1);
  EXPECT_FALSE(clock_nanoseconds(1, {.numerator = 0, .denominator = 1}).has_value());
  EXPECT_FALSE(clock_nanoseconds(1, {.numerator = 1, .denominator = 0}).has_value());
  EXPECT_FALSE(
      clock_nanoseconds(std::numeric_limits<std::uint64_t>::max(), {.numerator = 1, .denominator = 1}).has_value());
  EXPECT_EQ(clock_nanoseconds(static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()),
                              {.numerator = 1, .denominator = 1}),
            std::numeric_limits<std::int64_t>::max());
}
TEST(LocalPolicy, gate_whenReadersRacePublication_preservesBoundedOwnedResults) {
  fixture_tick() = 1000000000;
  const auto config = configuration();
  rasp::LocalPolicyState state(config, "android", clock_tick);
  state.begin_cycle();
  state.finish_cycle(cycle(config, observations(0)));
  const auto input = request(config);
  std::atomic<std::uint32_t> failures{0};
  std::array<std::jthread, 12> threads;
  for (auto& thread : threads) {
    thread = std::jthread([&] {
      auto output = std::make_unique<struct RaspLocalGateResultV1>();
      for (std::uint32_t call = 0; call < 200; ++call) {
        const auto status = state.gate(input, *output);
        if ((status == RASP_LOCAL_OK && output->action != RASP_LOCAL_ALLOW) ||
            (status == RASP_LOCAL_BUSY && output->action != RASP_LOCAL_DENY) ||
            (status != RASP_LOCAL_OK && status != RASP_LOCAL_BUSY)) {
          failures.fetch_add(1);
        }
      }
    });
  }
  for (std::uint32_t publication = 0; publication < 20; ++publication) {
    state.begin_cycle();
    state.finish_cycle(cycle(config, observations(0)));
  }
  for (auto& thread : threads) {
    thread.join();
  }
  EXPECT_EQ(failures.load(), 0U);
}
}  // namespace
