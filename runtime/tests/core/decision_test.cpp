/// Tests local typed decisions through the real owned cycle dispatcher.
#include "rasp/decision.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <yyjson.h>

#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/cycle.h"
#include "rasp/observation.h"
#include "rasp/plugin.h"
#include "rasp/util/read_file.h"

namespace {
/// Returns supplied builtins at the production dispatcher boundary.
std::vector<rasp::Observation> supplied(const rasp::Config& /*unused*/, const void* argument) {
  return *static_cast<const std::vector<rasp::Observation>*>(argument);
}
/// Runs a finite real cycle with a known catalogue and selected groups.
std::shared_ptr<const rasp::CycleSnapshot> run(std::string_view platform, std::vector<std::string> groups,
                                               const std::vector<rasp::Observation>& observations) {
  rasp::CycleMonitor monitor;
  rasp::plugins::Context context;
  constexpr std::array<const rasp::plugins::Plugin*, 0> kPlugins{};
  return monitor.run({.build_id = "test", .checks = std::move(groups)}, rasp::cycle_catalogue(platform), kPlugins,
                     context, supplied, &observations);
}
/// Finds one exact rule, failing the test without changing production visibility.
const rasp::LocalDecision* row(const rasp::LocalDecisionReport& report, std::string_view rule_id) {
  for (const auto& decision : report.rows) {
    if (decision.rule_id == rule_id) {
      return &decision;
    }
  }
  ADD_FAILURE() << "Missing rule " << rule_id;
  return nullptr;
}
TEST(LocalDecision, evaluate_whenSelectionEmpty_emitsUnknownRowsWithoutEvaluatedPredicates) {
  const auto snapshot = run("android", {}, {});
  EXPECT_EQ(snapshot->local_decisions.predicates_evaluated, 0U);
  ASSERT_EQ(snapshot->local_decisions.rows.size(), 75U);
  for (const auto& decision : snapshot->local_decisions.rows) {
    EXPECT_EQ(decision.verdict, rasp::LocalVerdict::kUnknown);
    EXPECT_EQ(decision.reason, rasp::LocalReason::kConfigDisabled);
  }
}
TEST(LocalDecision, evaluate_whenStatusUnavailable_doesNotInterpretForgedPositiveValue) {
  for (const auto status : {rasp::Status::kUnsupported, rasp::Status::kError, rasp::Status::kTimeout}) {
    const auto snapshot =
        run("android", {"debugger"},
            {{.signal = "dbg.tracer_pid", .source = "proc_status", .status = status, .value = std::int64_t{42}}});
    const auto* decision = row(snapshot->local_decisions, "native.android.dbg.tracer_pid.proc_status");
    ASSERT_NE(decision, nullptr);
    EXPECT_EQ(decision->verdict, rasp::LocalVerdict::kUnknown);
    EXPECT_EQ(decision->reason, rasp::LocalReason::kStatusUnavailable);
    EXPECT_EQ(decision->status, status);
    EXPECT_EQ(snapshot->local_decisions.predicates_evaluated, 0U);
  }
}
TEST(LocalDecision, evaluate_whenPairedHashesDiffer_reportsMismatchWithoutTrustedBaseline) {
  const auto first = run("ios", {"integrity"},
                         {
                             rasp::observed("integ.text_sha256", "file", std::string(64, 'a')),
                             rasp::observed("integ.text_sha256", "memory", std::string(64, 'b')),
                         });
  const auto* mismatch = row(first->local_decisions, "local.ios.integrity_pair");
  ASSERT_NE(mismatch, nullptr);
  EXPECT_EQ(mismatch->reason, rasp::LocalReason::kHashesDiffer);
  EXPECT_EQ(mismatch->verdict, rasp::LocalVerdict::kThreat);
  const auto second = run("ios", {"integrity"},
                          {
                              rasp::observed("integ.text_sha256", "file", std::string(64, 'a')),
                              rasp::observed("integ.text_sha256", "memory", std::string(64, 'a')),
                          });
  const auto* equal = row(second->local_decisions, "local.ios.integrity_pair");
  ASSERT_NE(equal, nullptr);
  EXPECT_EQ(equal->reason, rasp::LocalReason::kHashesEqualUntrusted);
  EXPECT_EQ(equal->verdict, rasp::LocalVerdict::kUnknown);
  EXPECT_EQ(mismatch->reason, rasp::LocalReason::kHashesDiffer);
}
/// Decodes native integer wrappers without treating unsigned overflow or booleans as integers.
rasp::Value fixture_integer(const yyjson_val* value, std::string_view kind) {
  if (!yyjson_is_int(value) ||
      (yyjson_is_uint(value) &&
       yyjson_get_uint(value) > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))) {
    return {};
  }
  const std::int64_t number = yyjson_is_uint(value) ? static_cast<std::int64_t>(yyjson_get_uint(value))
                                                    : static_cast<std::int64_t>(yyjson_get_sint(value));
  if (kind == "int" &&
      (number > std::numeric_limits<std::int32_t>::max() || number < std::numeric_limits<std::int32_t>::min())) {
    return {};
  }
  return number;
}
/// Converts one fixture wrapper without coercion; the evaluator never parses JSON.
rasp::Value fixture_value(yyjson_val const* wrapped) {
  if (!yyjson_is_obj(wrapped) || yyjson_obj_size(wrapped) != 1) {
    return {};
  }
  yyjson_val const* value = yyjson_obj_get(wrapped, "bool");
  if (value != nullptr) {
    return yyjson_is_bool(value) ? rasp::Value(yyjson_get_bool(value)) : rasp::Value{};
  }
  for (const char* kind : {"int", "long"}) {
    value = yyjson_obj_get(wrapped, kind);
    if (value != nullptr) {
      return fixture_integer(value, kind);
    }
  }
  value = yyjson_obj_get(wrapped, "string");
  if (value != nullptr) {
    return yyjson_is_str(value) ? rasp::Value(std::string(yyjson_get_str(value), yyjson_get_len(value)))
                                : rasp::Value{};
  }
  value = yyjson_obj_get(wrapped, "strings");
  if (!yyjson_is_arr(value)) {
    return {};
  }
  std::vector<std::string> list;
  for (std::size_t index = 0; index < yyjson_arr_size(value); ++index) {
    yyjson_val const* item = yyjson_arr_get(value, index);
    if (!yyjson_is_str(item)) {
      return {};
    }
    list.emplace_back(yyjson_get_str(item), yyjson_get_len(item));
  }
  return list;
}
/// Reads mandatory fixture strings; malformed fixture input fails without production coercion.
std::string text(yyjson_val const* object, const char* key) {
  yyjson_val const* value = yyjson_obj_get(object, key);
  if (!yyjson_is_str(value)) {
    ADD_FAILURE() << key;
    return {};
  }
  return {yyjson_get_str(value), yyjson_get_len(value)};
}
/// Preserves known and unknown collection statuses from portable server vectors.
rasp::Status fixture_status(std::string_view status) {
  if (status == "ok") {
    return rasp::Status::kOk;
  }
  if (status == "error") {
    return rasp::Status::kError;
  }
  if (status == "unsupported") {
    return rasp::Status::kUnsupported;
  }
  if (status == "timeout") {
    return rasp::Status::kTimeout;
  }
  return std::bit_cast<rasp::Status>(std::uint8_t{255});
}
TEST(LocalDecision, evaluate_whenPinnedServerVectorsOverlap_preservesVersionOneSemantics) {
  const auto bytes = rasp::util::read_file(RASP_ASSESSMENT_VECTORS, std::size_t{1024} * 1024);
  ASSERT_TRUE(bytes.has_value());
  std::unique_ptr<yyjson_doc, decltype(&yyjson_doc_free)> const document(yyjson_read(bytes->data(), bytes->size(), 0),
                                                                         yyjson_doc_free);
  ASSERT_NE(document, nullptr);
  yyjson_val const* cases = yyjson_doc_get_root(document.get());
  ASSERT_EQ(yyjson_arr_size(cases), 289U);
  std::size_t compared = 0;
  std::size_t unregistered = 0;
  std::size_t transport_only = 0;
  std::size_t retention_boundaries = 0;
  for (std::size_t index = 0; index < yyjson_arr_size(cases); ++index) {
    const yyjson_val* example = yyjson_arr_get(cases, index);
    SCOPED_TRACE(text(example, "case"));
    const yyjson_val* input = yyjson_obj_get(example, "observation");
    const yyjson_val* expected = yyjson_obj_get(example, "expected");
    const std::string platform = text(example, "platform");
    const std::string signal = text(input, "name");
    const std::string source = text(input, "source");
    const std::string reason = text(expected, "reason_code");
    if (reason == "unsupported_transport") {
      ++transport_only;
      continue;
    }
    const std::string status = text(input, "status");
    const rasp::Status native_status = fixture_status(status);
    const auto catalogue = rasp::cycle_catalogue(platform);
    std::vector<std::string> groups;
    for (const auto& output : catalogue.outputs) {
      if (std::ranges::find(groups, output.group) == groups.end()) {
        groups.emplace_back(output.group);
      }
    }
    const auto snapshot = run(platform, std::move(groups),
                              {
                                  {
                                      .signal = signal,
                                      .source = source,
                                      .status = native_status,
                                      .value = fixture_value(yyjson_obj_get(input, "value")),
                                  },
                              });
    if (reason == "unregistered_rule") {
      ++unregistered;
      EXPECT_TRUE(std::ranges::none_of(snapshot->local_decisions.rows,
                                       [](const auto& decision) { return decision.predicate_evaluated; }));
      continue;
    }
    const auto* decision = row(snapshot->local_decisions, text(expected, "rule_id"));
    ASSERT_NE(decision, nullptr);
    if (snapshot->metadata.dropped != 0) {
      EXPECT_EQ(reason, "invalid_value");
      EXPECT_EQ(decision->reason, rasp::LocalReason::kMissingObservation);
      EXPECT_EQ(decision->verdict, rasp::LocalVerdict::kUnknown);
      EXPECT_EQ(snapshot->local_decisions.coverage, rasp::LocalCoverage::kIncomplete);
      ++retention_boundaries;
      continue;
    }
    constexpr std::array kVerdicts{"threat", "benign", "unknown"};
    constexpr std::array kSeverities{"high", "medium", "info", "none", "unknown"};
    constexpr std::array kConfidence{"limited", "unavailable"};
    EXPECT_EQ(std::span(kVerdicts)[static_cast<std::size_t>(decision->verdict)], text(expected, "verdict"));
    EXPECT_EQ(std::span(kSeverities)[static_cast<std::size_t>(decision->severity)], text(expected, "severity"));
    EXPECT_EQ(std::span(kConfidence)[static_cast<std::size_t>(decision->confidence)], text(expected, "confidence"));
    EXPECT_EQ(rasp::local_reason_name(decision->reason), reason);
    EXPECT_EQ(decision->rule_version, 1U);
    ++compared;
  }
  EXPECT_GT(compared, 150U);
  EXPECT_GT(unregistered, 0U);
  EXPECT_GT(transport_only, 0U);
  EXPECT_EQ(retention_boundaries, 2U);
  EXPECT_EQ(compared + unregistered + transport_only + retention_boundaries, 289U);
}
TEST(LocalDecision, evaluate_whenCatalogueSyntheticFutureOrForeign_refusesFallbackSemantics) {
  const auto snapshot = run("android", {}, {});
  auto catalogue = rasp::cycle_catalogue("android");
  catalogue.outputs = catalogue.outputs.first(1);
  EXPECT_EQ(rasp::evaluate_local_decisions(snapshot->metadata, {}, catalogue).reason,
            rasp::LocalReason::kCatalogueUnknown);
  catalogue = rasp::cycle_catalogue("android");
  catalogue.catalogue_id = "future";
  EXPECT_EQ(rasp::evaluate_local_decisions(snapshot->metadata, {}, catalogue).reason,
            rasp::LocalReason::kCatalogueUnknown);
  auto metadata = snapshot->metadata;
  metadata.catalogue_id = "fce392826ee1d9e5bab8046ca1584e2755af0eb3fd26922769eb20c64e32f736";
  catalogue.catalogue_id = metadata.catalogue_id;
  EXPECT_EQ(rasp::evaluate_local_decisions(metadata, {}, catalogue).reason, rasp::LocalReason::kCatalogueUnknown);
  metadata.catalogue_id = "c6ed667281a13f3072a886b6b1cbc10d352b354299266669438239045a5b6daf";
  catalogue.catalogue_id = metadata.catalogue_id;
  EXPECT_EQ(rasp::evaluate_local_decisions(metadata, {}, catalogue).reason, rasp::LocalReason::kCatalogueUnknown);
  EXPECT_EQ(run("future", {}, {})->local_decisions.reason, rasp::LocalReason::kCatalogueUnknown);
}
TEST(LocalDecision, evaluate_whenConfigUnknownOrOutputMissing_emitsExplicitUnknownRows) {
  rasp::CycleMonitor monitor;
  rasp::plugins::Context context;
  const std::vector<rasp::Observation> empty;
  const rasp::Config missing_config;
  const auto unknown = monitor.run(missing_config, rasp::cycle_catalogue("android"), {}, context, supplied, &empty);
  EXPECT_EQ(unknown->local_decisions.coverage, rasp::LocalCoverage::kUnknown);
  EXPECT_EQ(unknown->local_decisions.predicates_evaluated, 0U);
  for (const auto& decision : unknown->local_decisions.rows) {
    EXPECT_EQ(decision.reason, rasp::LocalReason::kConfigUnknown);
  }
  const auto missing = run("android", {"debugger"}, {});
  const auto* decision = row(missing->local_decisions, "native.android.dbg.tracer_pid.proc_status");
  ASSERT_NE(decision, nullptr);
  EXPECT_EQ(decision->reason, rasp::LocalReason::kMissingObservation);
  EXPECT_EQ(missing->local_decisions.coverage, rasp::LocalCoverage::kIncomplete);
}
TEST(LocalDecision, evaluate_whenDuplicateWrongVariantOrInvalidDigest_abstains) {
  for (const rasp::Value& value : {rasp::Value(true), rasp::Value(std::string("42")), rasp::Value(std::int64_t{-1})}) {
    const auto snapshot = run("android", {"debugger"}, {rasp::observed("dbg.tracer_pid", "proc_status", value)});
    const auto* decision = row(snapshot->local_decisions, "native.android.dbg.tracer_pid.proc_status");
    ASSERT_NE(decision, nullptr);
    EXPECT_EQ(decision->reason, rasp::LocalReason::kInvalidValue);
  }
  const auto duplicate = run("android", {"debugger"},
                             {
                                 rasp::observed("dbg.tracer_pid", "proc_status", std::int64_t{0}),
                                 rasp::observed("dbg.tracer_pid", "proc_status", std::int64_t{42}),
                             });
  const auto* decision = row(duplicate->local_decisions, "native.android.dbg.tracer_pid.proc_status");
  ASSERT_NE(decision, nullptr);
  EXPECT_EQ(decision->reason, rasp::LocalReason::kDuplicateObservation);
  const auto malformed = run("ios", {"integrity"},
                             {
                                 rasp::observed("integ.text_sha256", "file", std::string(64, 'A')),
                                 rasp::observed("integ.text_sha256", "memory", std::string(64, 'b')),
                             });
  const auto* pair = row(malformed->local_decisions, "local.ios.integrity_pair");
  ASSERT_NE(pair, nullptr);
  EXPECT_EQ(pair->reason, rasp::LocalReason::kComparisonUnavailable);
}
TEST(LocalDecision, evaluate_whenPureInputExceedsBounds_returnsFiniteUnavailableReport) {
  const auto snapshot = run("android", {}, {});
  const auto catalogue = rasp::cycle_catalogue("android");
  std::vector<rasp::Observation> inputs(257);
  EXPECT_EQ(rasp::evaluate_local_decisions(snapshot->metadata, inputs, catalogue).reason,
            rasp::LocalReason::kInputLimit);
  inputs = {rasp::observed("a", "b", std::string(1025, 'x'))};
  EXPECT_EQ(rasp::evaluate_local_decisions(snapshot->metadata, inputs, catalogue).reason,
            rasp::LocalReason::kInputLimit);
  inputs = {rasp::observed("a", "b", std::vector<std::string>(65, "x"))};
  EXPECT_EQ(rasp::evaluate_local_decisions(snapshot->metadata, inputs, catalogue).reason,
            rasp::LocalReason::kInputLimit);
  auto metadata = snapshot->metadata;
  metadata.groups.resize(65);
  EXPECT_EQ(rasp::evaluate_local_decisions(metadata, {}, catalogue).reason, rasp::LocalReason::kMetadataInvalid);
  metadata = snapshot->metadata;
  metadata.status_counts[0] = std::numeric_limits<std::uint64_t>::max();
  EXPECT_EQ(rasp::evaluate_local_decisions(metadata, {}, catalogue).reason, rasp::LocalReason::kMetadataInvalid);
}
TEST(LocalDecision, evaluate_whenMetadataClaimsUnretainedCoverage_doesNotTrustCompleteFlag) {
  const auto snapshot = run("ios", {"integrity"},
                            {
                                rasp::observed("integ.text_sha256", "file", std::string(64, 'a')),
                                rasp::observed("integ.text_sha256", "memory", std::string(64, 'a')),
                            });
  ASSERT_TRUE(snapshot->metadata.complete);
  const auto report = rasp::evaluate_local_decisions(snapshot->metadata, {}, rasp::cycle_catalogue("ios"));
  EXPECT_NE(report.coverage, rasp::LocalCoverage::kComplete);
}
TEST(LocalDecision, evaluate_whenSourcesDisagree_preservesFactsWithoutElevatingConfidence) {
  const auto snapshot = run("android", {"debugger"},
                            {
                                rasp::observed("dbg.tracer_pid", "proc_status", std::int64_t{0}),
                                rasp::observed("dbg.tracer_pid", "proc_status_syscall", std::int64_t{42}),
                            });
  ASSERT_EQ(snapshot->local_decisions.relations.size(), 1U);
  EXPECT_EQ(snapshot->local_decisions.relations[0].state, rasp::LocalRelationState::kDisagree);
  const auto* present = row(snapshot->local_decisions, "local.android.dbg.tracer_pid.proc_status_syscall");
  ASSERT_NE(present, nullptr);
  EXPECT_EQ(present->verdict, rasp::LocalVerdict::kThreat);
  EXPECT_EQ(present->confidence, rasp::LocalConfidence::kLimited);
}
TEST(LocalDecision, evaluate_whenAssistiveVpnKeyboardSharingOrRootPackagesPresent_preservesNeutralContext) {
  const auto snapshot =
      run("android", {"accessibility", "input_method", "root_packages", "mitm"},
          {
              rasp::observed("a11y.enabled_services", "accessibility_manager",
                             std::vector<std::string>{"com.google.talkback/.Service capabilities=1 flags=1"}),
              rasp::observed("ime.current_component", "input_method_manager",
                             std::string("com.password.manager/.Keyboard")),
              rasp::observed("root.manager_packages_v1", "package_manager",
                             std::vector<std::string>{"com.topjohnwu.magisk"}),
              rasp::observed("mitm.tunnels", "getifaddrs", std::vector<std::string>{"tun0"}),
          });
  for (const auto& decision : snapshot->local_decisions.rows) {
    EXPECT_NE(decision.verdict, rasp::LocalVerdict::kThreat);
  }
}
/// Produces every exact overlay grammar field, including independent observer coverage.
std::vector<rasp::Observation> overlay(std::string state = "active", std::string coverage = "best_effort",
                                       std::int64_t dropped = 0) {
  std::vector<rasp::Observation> inputs{
      rasp::observed("overlay.observer_state", "window_callback", std::move(state)),
      rasp::observed("overlay.coverage", "window_callback", std::move(coverage)),
  };
  constexpr std::array kNames{
      "active_windows", "touch_events", "obscured_touch_events", "partially_obscured_touch_events",
      "dropped_events", "lost_windows", "invalid_events",        "interval_ms",
  };
  const std::array<std::int64_t, 8> values{1, 2, 1, 0, dropped, 0, 0, 100};
  for (std::size_t index = 0; index < kNames.size(); ++index) {
    inputs.push_back(rasp::observed("overlay." + std::string(std::span(kNames)[index]), "window_callback",
                                    std::span(values)[index]));
  }
  return inputs;
}
/// Independent expected outcomes for valid, lost, inconsistent and inactive fixture contexts.
rasp::LocalReason expected_overlay_reason(const std::vector<rasp::Observation>& inputs) {
  if (std::get<std::int64_t>(inputs[6].value) > 0) {
    return std::get<std::string>(inputs[1].value) == "loss_detected" ? rasp::LocalReason::kObserverLoss
                                                                     : rasp::LocalReason::kObserverInconsistent;
  }
  return std::get<std::string>(inputs[0].value) == "active" ? rasp::LocalReason::kContextObserved
                                                            : rasp::LocalReason::kObserverUnavailable;
}
TEST(LocalDecision, evaluate_whenOverlayContextHasLossOrInconsistentClosure_neverAssertsAttack) {
  for (const auto& inputs : {
           overlay(),
           overlay("active", "loss_detected", 1),
           overlay("active", "best_effort", 1),
           overlay("deactivated", "unknown"),
       }) {
    const auto snapshot = run("android", {"overlay"}, inputs);
    const auto* decision = row(snapshot->local_decisions, "local.android.overlay_context");
    ASSERT_NE(decision, nullptr);
    EXPECT_EQ(decision->verdict, rasp::LocalVerdict::kUnknown);
    EXPECT_EQ(decision->evidence.size(), 10U);
    EXPECT_EQ(decision->reason, expected_overlay_reason(inputs));
  }
}
TEST(LocalDecision, evaluate_whenEveryCanonicalTupleEnumerated_hasClosedFiniteInventory) {
  std::size_t total = 0;
  std::size_t diagnostic_only = 0;
  for (const auto* const platform : {"android", "ios"}) {
    const auto catalogue = rasp::cycle_catalogue(platform);
    const auto snapshot = run(platform, {}, {});
    for (const auto& output : catalogue.outputs) {
      const std::string suffix =
          "." + std::string(platform) + "." + std::string(output.signal) + "." + std::string(output.source);
      const bool provenance =
          output.signal.starts_with("hook.exec_modules") || output.signal.starts_with("hook.loader_chain");
      EXPECT_EQ(std::ranges::count_if(snapshot->local_decisions.rows,
                                      [&](const auto& decision) { return decision.rule_id.ends_with(suffix); }),
                provenance ? 0 : 1);
      if (provenance) {
        ++diagnostic_only;
      } else {
        ++total;
      }
    }
    EXPECT_LE(snapshot->local_decisions.rows.capacity(), 256U);
    EXPECT_LE(snapshot->local_decisions.relations.capacity(), 16U);
    EXPECT_LE(snapshot->local_decisions.issues.capacity(), 16U);
    for (const auto& decision : snapshot->local_decisions.rows) {
      EXPECT_LE(decision.evidence.size(), 10U);
      EXPECT_LE(decision.evidence.capacity(), 10U);
    }
  }
  EXPECT_EQ(total, 125U);
  EXPECT_EQ(diagnostic_only, 8U);
}
/// Owning callback handoff used by a real plugin consumer.
constexpr rasp::plugins::Key<std::shared_ptr<const rasp::CycleSnapshot>> kRetained{"test.decision.retained"};
/// A plugin tries to forge a missing builtin pair and a positive debugger fact.
std::vector<rasp::Observation> colliding_plugin(rasp::plugins::Context& /*unused*/) {
  return {
      rasp::observed("integ.text_sha256", "file", std::string(64, 'b')),
      rasp::observed("integ.text_sha256", "memory", std::string(64, 'c')),
      rasp::observed("dbg.tracer_pid", "proc_status", std::int64_t{42}),
  };
}
/// Retains the exact snapshot exposed to both new and legacy synchronous callbacks.
void retain_cycle(const std::shared_ptr<const rasp::CycleSnapshot>& snapshot, rasp::plugins::Context& context) {
  const auto published = context.get(rasp::plugins::kCycleSnapshot);
  ASSERT_TRUE(published.has_value());
  EXPECT_EQ(*published, snapshot);
  context.put(kRetained, snapshot);
}
TEST(LocalDecision, run_whenPluginsCollideAndCyclesAreRetained_usesOnlyActualBuiltinPrefix) {
  rasp::CycleMonitor monitor;
  rasp::plugins::Context context;
  constexpr std::array kChecks{colliding_plugin};
  const rasp::plugins::Plugin plugin{.init = nullptr, .checks = kChecks, .on_cycle = retain_cycle};
  const std::array plugins{&plugin};
  const rasp::Config config{.build_id = "test", .checks = std::vector<std::string>{"integrity", "debugger"}};
  const std::vector first_inputs{
      rasp::observed("integ.text_sha256", "file", std::string(64, 'a')),
      rasp::observed("integ.text_sha256", "memory", std::string(64, 'a')),
  };
  const auto first = monitor.run(config, rasp::cycle_catalogue("android"), plugins, context, supplied, &first_inputs);
  EXPECT_EQ(context.get(kRetained), first);
  EXPECT_EQ(first->local_decisions.builtin_observations, 2U);
  ASSERT_EQ(first->observations.size(), 5U);
  const auto* pair = row(first->local_decisions, "local.android.integrity_pair");
  ASSERT_NE(pair, nullptr);
  EXPECT_EQ(pair->reason, rasp::LocalReason::kHashesEqualUntrusted);
  const auto* tracer = row(first->local_decisions, "native.android.dbg.tracer_pid.proc_status");
  ASSERT_NE(tracer, nullptr);
  EXPECT_EQ(tracer->reason, rasp::LocalReason::kMissingObservation);
  const std::vector<rasp::Observation> second_inputs;
  const auto second = monitor.run(config, rasp::cycle_catalogue("android"), plugins, context, supplied, &second_inputs);
  EXPECT_EQ(context.get(kRetained), second);
  EXPECT_EQ(second->metadata.sequence, 2U);
  const auto* missing = row(second->local_decisions, "local.android.integrity_pair");
  ASSERT_NE(missing, nullptr);
  EXPECT_EQ(missing->reason, rasp::LocalReason::kComparisonUnavailable);
  EXPECT_EQ(pair->reason, rasp::LocalReason::kHashesEqualUntrusted);
  EXPECT_EQ(first->observations.size(), 5U);
  EXPECT_FALSE(context.get(rasp::plugins::kCycleSnapshot).has_value());
}
TEST(LocalDecision, evaluate_whenNativeOnlyCapabilitiesAreUnavailable_evenOkPayloadCannotClaimSuccess) {
  for (const auto& observation : {
           rasp::observed("debug.adb_enabled_v1", "settings_global", true),
           rasp::observed("debug.developer_options_enabled_v1", "settings_global", false),
       }) {
    const auto snapshot = run("android", {"developer_settings"}, {observation});
    EXPECT_EQ(snapshot->local_decisions.predicates_evaluated, 0U);
  }
  const auto trust =
      run("ios", {"mitm"}, {rasp::observed("mitm.user_cas", "trust_store", std::vector<std::string>{"ca"})});
  EXPECT_EQ(trust->local_decisions.predicates_evaluated, 0U);
}
TEST(LocalDecision, evaluate_whenSequenceOverflowsOrMetadataVersionUnknown_refusesWholeReport) {
  const auto snapshot = run("android", {}, {});
  auto metadata = snapshot->metadata;
  metadata.overflow = true;
  EXPECT_EQ(rasp::evaluate_local_decisions(metadata, {}, rasp::cycle_catalogue("android")).reason,
            rasp::LocalReason::kOverflow);
  metadata = snapshot->metadata;
  metadata.version = 2;
  EXPECT_EQ(rasp::evaluate_local_decisions(metadata, {}, rasp::cycle_catalogue("android")).reason,
            rasp::LocalReason::kMetadataInvalid);
}
TEST(LocalDecision, evaluate_whenNativeThreadMarkerCaseVaries_preservesNativeCaseInsensitiveContract) {
  const auto snapshot =
      run("android", {"hooks"}, {rasp::observed("hook.threads", "proc_task", std::vector<std::string>{"POOL-FRIDA"})});
  const auto* decision = row(snapshot->local_decisions, "local.android.hook.threads.proc_task");
  ASSERT_NE(decision, nullptr);
  EXPECT_EQ(decision->reason, rasp::LocalReason::kIndicatorPresent);
}
TEST(LocalDecision,
     evaluate_whenApprovedCaptureRowsEmitPositivePayloads_keepsAllTwentyOneUnregisteredWithoutEvaluation) {
  std::vector<rasp::Observation> inputs;
  for (const auto& output : rasp::cycle_catalogue("android").outputs) {
    if (output.group == "screenshot" || output.group == "screen_recording") {
      inputs.push_back(rasp::observed(output.signal, output.source, true));
    }
  }
  ASSERT_EQ(inputs.size(), 21U);
  const auto snapshot = run("android", {"screenshot", "screen_recording"}, inputs);
  EXPECT_EQ(snapshot->local_decisions.predicates_evaluated, 0U);
  EXPECT_EQ(snapshot->local_decisions.coverage, rasp::LocalCoverage::kComplete);
  for (const auto& input : inputs) {
    const auto* decision = row(snapshot->local_decisions, "local.android." + input.signal + "." + input.source);
    ASSERT_NE(decision, nullptr);
    EXPECT_EQ(decision->reason, rasp::LocalReason::kUnregisteredRule);
    EXPECT_EQ(decision->verdict, rasp::LocalVerdict::kUnknown);
    EXPECT_EQ(decision->confidence, rasp::LocalConfidence::kUnavailable);
    EXPECT_FALSE(decision->predicate_evaluated);
  }
}
TEST(LocalDecision,
     evaluate_whenCaptureMissingDisabledOrUnavailable_preservesEligibilityBeforeUnregisteredDisposition) {
  const std::string rule_id = "local.android.capture.screenshot.callback_events.activity_screen_capture";
  const auto missing = run("android", {"screenshot"}, {});
  const auto* missing_row = row(missing->local_decisions, rule_id);
  ASSERT_NE(missing_row, nullptr);
  EXPECT_EQ(missing_row->reason, rasp::LocalReason::kMissingObservation);
  for (const auto status : {rasp::Status::kUnsupported, rasp::Status::kError, rasp::Status::kTimeout}) {
    const auto snapshot = run("android", {"screenshot"},
                              {
                                  {
                                      .signal = "capture.screenshot.callback_events",
                                      .source = "activity_screen_capture",
                                      .status = status,
                                      .value = std::int64_t{99},
                                  },
                              });
    const auto* decision = row(snapshot->local_decisions, rule_id);
    ASSERT_NE(decision, nullptr);
    EXPECT_EQ(decision->reason, rasp::LocalReason::kStatusUnavailable);
    EXPECT_EQ(snapshot->local_decisions.predicates_evaluated, 0U);
  }
}

TEST(LocalDecision, evaluate_whenIOSCaptureRegistered_keepsAllTwentySixUnknownWithoutPredicates) {
  std::vector<rasp::Observation> inputs;
  for (const auto& output : rasp::cycle_catalogue("ios").outputs) {
    if (output.group == "screenshot" || output.group == "screen_recording") {
      inputs.push_back(rasp::observed(output.signal, output.source, true));
    }
  }
  ASSERT_EQ(inputs.size(), 26U);
  const auto snapshot = run("ios", {"screenshot", "screen_recording"}, inputs);
  ASSERT_EQ(snapshot->local_decisions.reason, rasp::LocalReason::kNone);
  EXPECT_EQ(snapshot->local_decisions.predicates_evaluated, 0U);
  EXPECT_EQ(snapshot->local_decisions.coverage, rasp::LocalCoverage::kComplete);
  for (const auto& input : inputs) {
    const auto* decision = row(snapshot->local_decisions, "local.ios." + input.signal + "." + input.source);
    ASSERT_NE(decision, nullptr);
    EXPECT_EQ(decision->reason, rasp::LocalReason::kUnregisteredRule);
    EXPECT_EQ(decision->verdict, rasp::LocalVerdict::kUnknown);
    EXPECT_EQ(decision->severity, rasp::LocalSeverity::kUnknown);
    EXPECT_EQ(decision->confidence, rasp::LocalConfidence::kUnavailable);
    EXPECT_FALSE(decision->predicate_evaluated);
  }
}
TEST(LocalDecision, evaluate_whenIOSCaptureEligibilityFails_appliesEligibilityBeforeUnregistered) {
  const std::string rule_id = "local.ios.capture.screenshot.callback_events.uiapplication_screenshot";
  const auto absent = run("ios", {"screenshot"}, {});
  ASSERT_EQ(absent->local_decisions.reason, rasp::LocalReason::kNone);
  const auto* missing = row(absent->local_decisions, rule_id);
  ASSERT_NE(missing, nullptr);
  EXPECT_EQ(missing->reason, rasp::LocalReason::kMissingObservation);
  const std::vector<rasp::Observation> inputs{
      rasp::observed("capture.screenshot.callback_events", "uiapplication_screenshot", true),
  };
  const auto disabled = run("ios", {}, inputs);
  const auto* disabled_row = row(disabled->local_decisions, rule_id);
  ASSERT_NE(disabled_row, nullptr);
  EXPECT_EQ(disabled_row->reason, rasp::LocalReason::kConfigDisabled);
  rasp::CycleMonitor monitor;
  rasp::plugins::Context context;
  const rasp::Config missing_config;
  const auto unknown = monitor.run(missing_config, rasp::cycle_catalogue("ios"), {}, context, supplied, &inputs);
  const auto* unknown_row = row(unknown->local_decisions, rule_id);
  ASSERT_NE(unknown_row, nullptr);
  EXPECT_EQ(unknown_row->reason, rasp::LocalReason::kConfigUnknown);
  const auto duplicate = run("ios", {"screenshot"}, {inputs[0], inputs[0]});
  const auto* duplicate_row = row(duplicate->local_decisions, rule_id);
  ASSERT_NE(duplicate_row, nullptr);
  EXPECT_EQ(duplicate_row->reason, rasp::LocalReason::kDuplicateObservation);
  for (const auto status : {rasp::Status::kUnsupported, rasp::Status::kError, rasp::Status::kTimeout}) {
    const auto snapshot =
        run("ios", {"screenshot"},
            {{.signal = inputs[0].signal, .source = inputs[0].source, .status = status, .value = true}});
    const auto* decision = row(snapshot->local_decisions, rule_id);
    ASSERT_NE(decision, nullptr);
    EXPECT_EQ(decision->reason, rasp::LocalReason::kStatusUnavailable);
    EXPECT_EQ(snapshot->local_decisions.predicates_evaluated, 0U);
  }
}
}  // namespace
