/// Pure bounded interpretation of explicitly adopted native evidence; no enforcement or external authority.
#include "rasp/decision.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "decision_registry.h"
#include "rasp/cycle.h"
#include "rasp/observation.h"

namespace rasp {
namespace {
using decision_internal::Predicate;
using decision_internal::Rule;
/// No caller-supplied loop, allocation or result size exceeds these native limits.
constexpr std::size_t kMaxObservations = 256;
/// Full text budget includes identities and values, as in the owning dispatcher.
constexpr std::size_t kMaxTextBytes = 65536;
/// Strict pinned native JDWP names; availability threads do not imply attachment.
constexpr auto kJdwpNames =
    std::to_array<std::string_view>({"ADB-JDWP Connec", "JDWP Transport ", "JDWP Event Help", "JDWP Command Re"});
/// Exactly the 32 entries watched by the adopted native prologue collector.
constexpr auto kInlineNames = std::to_array<std::string_view>({
    "open",
    "openat",
    "read",
    "fopen",
    "fread",
    "access",
    "faccessat",
    "stat",
    "lstat",
    "fstat",
    "fstatat",
    "readlink",
    "opendir",
    "readdir",
    "syscall",
    "ptrace",
    "fork",
    "kill",
    "exit",
    "_exit",
    "abort",
    "pthread_create",
    "mmap",
    "connect",
    "__system_property_get",
    "__system_property_find",
    "__system_property_read_callback",
    "dlopen",
    "android_dlopen_ext",
    "dlsym",
    "dladdr",
    "dl_iterate_phdr",
});

/// Adds one bounded length without overflow.
[[nodiscard]] bool add_text(std::size_t& total, std::size_t size, std::size_t limit) {
  if (size > limit || size > kMaxTextBytes - total) {
    return false;
  }
  total += size;
  return true;
}
/// Validates the envelope before inspecting any predicate or allocating results.
[[nodiscard]] bool bounded(std::span<const Observation> observations) {
  if (observations.size() > kMaxObservations) {
    return false;
  }
  std::size_t total = 0;
  for (const auto& observation : observations) {
    if (!add_text(total, observation.signal.size(), 96) || !add_text(total, observation.source.size(), 96)) {
      return false;
    }
    if (const auto* text = std::get_if<std::string>(&observation.value);
        text != nullptr && !add_text(total, text->size(), 1024)) {
      return false;
    }
    if (const auto* list = std::get_if<std::vector<std::string>>(&observation.value); list != nullptr) {
      if (list->size() > 64) {
        return false;
      }
      for (const auto& text : *list) {
        if (!add_text(total, text.size(), 1024)) {
          return false;
        }
      }
    }
  }
  return true;
}
/// Requires exact compiled definitions as well as the explicitly adopted semantic digest.
[[nodiscard]] bool bound_catalogue(const CycleMetadata& metadata, const CycleCatalogue& catalogue) {
  if (!metadata.catalogue_known || metadata.catalogue_truncated ||
      metadata.catalogue_id != decision_internal::kCatalogueId || catalogue.catalogue_id != metadata.catalogue_id ||
      catalogue.platform != metadata.platform || (metadata.platform != "android" && metadata.platform != "ios")) {
    return false;
  }
  const CycleCatalogue expected = cycle_catalogue(metadata.platform);
  return expected.catalogue_id == decision_internal::kCatalogueId &&
         std::ranges::equal(catalogue.outputs, expected.outputs, [](const CycleOutput& left, const CycleOutput& right) {
           return left.group == right.group && left.signal == right.signal && left.source == right.source;
         });
}
/// Reads a previously validated unique selected-group state.
[[nodiscard]] std::optional<bool> selected(const CycleMetadata& metadata, std::string_view group) {
  const auto found = std::ranges::find(metadata.groups, group, &CycleGroup::name);
  return found == metadata.groups.end() ? std::nullopt : found->enabled;
}
/// Validates unique known group names and tri-state selection before lookup.
[[nodiscard]] bool valid_groups(const CycleMetadata& metadata, const CycleCatalogue& catalogue) {
  for (std::size_t index = 0; index < metadata.groups.size(); ++index) {
    const auto& group = metadata.groups[index];
    if (group.name.empty() || group.name.size() > 96 ||
        std::ranges::find(catalogue.outputs, group.name, &CycleOutput::group) == catalogue.outputs.end() ||
        group.enabled.has_value() != metadata.config_known) {
      return false;
    }
    for (std::size_t previous = 0; previous < index; ++previous) {
      if (metadata.groups[previous].name == group.name) {
        return false;
      }
    }
  }
  return true;
}
/// Checks exact selected expected counts against pre-retention coverage.
[[nodiscard]] bool valid_expected(const CycleMetadata& metadata, const CycleCatalogue& catalogue) {
  std::uint64_t expected = 0;
  for (const auto& output : catalogue.outputs) {
    if (std::ranges::find(metadata.groups, output.group, &CycleGroup::name) == metadata.groups.end()) {
      return false;
    }
    if (selected(metadata, output.group) == true) {
      ++expected;
    }
  }
  if (metadata.config_known) {
    if (metadata.config_truncated || metadata.expected != expected || metadata.seen > expected ||
        metadata.missing.size() != expected - metadata.seen) {
      return false;
    }
  } else if (metadata.expected.has_value() || metadata.seen != 0 || !metadata.missing.empty()) {
    return false;
  }
  return true;
}
/// Verifies that unretained builtin identities are accounted for by recorded loss.
[[nodiscard]] bool valid_retained(const CycleMetadata& metadata, std::span<const Observation> observations,
                                  const CycleCatalogue& catalogue) {
  if (metadata.config_known) {
    std::uint64_t retained_seen = 0;
    auto retained_extra = static_cast<std::uint64_t>(observations.size());
    for (const auto& output : catalogue.outputs) {
      if (selected(metadata, output.group) == true && std::ranges::any_of(observations, [&](const Observation& entry) {
            return entry.signal == output.signal && entry.source == output.source;
          })) {
        ++retained_seen;
        --retained_extra;
      }
    }
    if (metadata.seen < retained_seen || metadata.seen - retained_seen > metadata.dropped ||
        metadata.extra < retained_extra) {
      return false;
    }
  }
  return true;
}
/// Validates missing identities independently from retained source status.
[[nodiscard]] bool valid_missing(const CycleMetadata& metadata, std::span<const Observation> observations,
                                 const CycleCatalogue& catalogue) {
  for (std::size_t index = 0; index < metadata.missing.size(); ++index) {
    const auto& missing = metadata.missing[index];
    if (missing.signal.size() > 96 || missing.source.size() > 96) {
      return false;
    }
    const auto output = std::ranges::find_if(catalogue.outputs, [&](const CycleOutput& entry) {
      return entry.signal == missing.signal && entry.source == missing.source;
    });
    if (output == catalogue.outputs.end() || selected(metadata, output->group) != true ||
        std::ranges::any_of(observations, [&](const Observation& entry) {
          return entry.signal == missing.signal && entry.source == missing.source;
        })) {
      return false;
    }
    for (std::size_t previous = 0; previous < index; ++previous) {
      if (metadata.missing[previous].signal == missing.signal && metadata.missing[previous].source == missing.source) {
        return false;
      }
    }
  }
  return true;
}
/// Validates bounded status totals, including the additional plugin suffix.
[[nodiscard]] bool valid_status_counts(const CycleMetadata& metadata, std::span<const Observation> observations) {
  std::size_t retained = 0;
  for (const auto count : metadata.status_counts) {
    if (count > kMaxObservations - retained) {
      return false;
    }
    retained += static_cast<std::size_t>(count);
  }
  if (metadata.unknown_status > kMaxObservations - retained) {
    return false;
  }
  retained += static_cast<std::size_t>(metadata.unknown_status);
  if (observations.size() > retained) {
    return false;
  }
  std::array<std::uint64_t, 4> counts{};
  std::uint64_t unknown = 0;
  for (const auto& observation : observations) {
    const auto status = static_cast<std::size_t>(observation.status);
    if (status < counts.size()) {
      ++std::span(counts)[status];
    } else {
      ++unknown;
    }
  }
  for (std::size_t index = 0; index < counts.size(); ++index) {
    if (std::span(counts)[index] > std::span(metadata.status_counts)[index]) {
      return false;
    }
  }
  return unknown <= metadata.unknown_status;
}
/// Checks bounded final metadata without treating present failed statuses as protection success.
[[nodiscard]] bool valid_metadata(const CycleMetadata& metadata, std::span<const Observation> observations,
                                  const CycleCatalogue& catalogue) {
  if (metadata.version != 1 || !metadata.execution_finished || metadata.overflow || metadata.groups.size() > 64 ||
      metadata.missing.size() > 256 || (metadata.sequence.has_value() && *metadata.sequence == 0)) {
    return false;
  }
  const bool complete = metadata.config_known && metadata.catalogue_known && metadata.sequence.has_value() &&
                        metadata.duration_ns.has_value() && metadata.unknown_groups == 0 && metadata.missing.empty() &&
                        metadata.extra == 0 && metadata.dropped == 0 && metadata.unknown_status == 0 &&
                        !metadata.overflow;
  if (metadata.complete != complete) {
    return false;
  }
  return valid_groups(metadata, catalogue) && valid_expected(metadata, catalogue) &&
         valid_retained(metadata, observations, catalogue) && valid_missing(metadata, observations, catalogue) &&
         valid_status_counts(metadata, observations);
}
/// Validates exact lowercase ASCII digests, without claiming a trusted baseline.
[[nodiscard]] bool digest(std::string_view text, std::size_t length) {
  return text.size() == length && std::ranges::all_of(text, [](char value) {
           return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f');
         });
}
/// Requires distinct bounded entries for new closed-list predicates.
[[nodiscard]] bool distinct(std::span<const std::string> list) {
  for (std::size_t index = 0; index < list.size(); ++index) {
    if (std::ranges::find(list.first(index), list[index]) != list.first(index).end()) {
      return false;
    }
  }
  return true;
}
/// Applies native filtered-list contracts without coercion or partial acceptance.
[[nodiscard]] bool valid_thread(std::string_view entry) {
  if (entry.empty() || entry.size() > 15 ||
      !std::ranges::all_of(entry, [](char byte) { return byte >= 32 && byte <= 126; })) {
    return false;
  }
  std::string lowered(entry);
  std::ranges::transform(lowered, lowered.begin(), [](char byte) {
    return byte >= 'A' && byte <= 'Z' ? static_cast<char>(byte + ('a' - 'A')) : byte;
  });
  return lowered.contains("gum-js-loop") || lowered.contains("frida");
}
/// Applies native filtered-list contracts without coercion or partial acceptance.
[[nodiscard]] std::optional<bool> list_indicator(Predicate predicate, const Value& value) {
  const auto* list = std::get_if<std::vector<std::string>>(&value);
  if (list == nullptr || std::ranges::any_of(*list, [](const std::string& entry) { return entry.empty(); })) {
    return std::nullopt;
  }
  if (predicate == Predicate::kJdwp) {
    if (!std::ranges::all_of(*list,
                             [](const std::string& entry) { return std::ranges::contains(kJdwpNames, entry); })) {
      return std::nullopt;
    }
    return std::ranges::contains(*list, "JDWP Command Re");
  }
  if (predicate == Predicate::kBaselineDigests &&
      (list->empty() || !distinct(*list) ||
       !std::ranges::all_of(*list, [](const std::string& entry) { return digest(entry, 64); }))) {
    return std::nullopt;
  }
  if (predicate == Predicate::kInline &&
      (list->size() > 32 || !distinct(*list) || !std::ranges::all_of(*list, [](const std::string& entry) {
         return std::ranges::contains(kInlineNames, entry);
       }))) {
    return std::nullopt;
  }
  if (predicate == Predicate::kThreads &&
      (list->size() > 32 || !distinct(*list) || !std::ranges::all_of(*list, valid_thread))) {
    return std::nullopt;
  }
  return !list->empty();
}
/// Interprets the exact variant; no coercion, default value or partial success.
[[nodiscard]] std::optional<bool> indicator(const Rule& rule, const Value& value) {
  switch (rule.predicate) {
    case Predicate::kTrue:
    case Predicate::kContextBool:
    case Predicate::kContextFalse: {
      const auto* flag = std::get_if<bool>(&value);
      if (flag == nullptr) {
        return std::nullopt;
      }
      return rule.predicate == Predicate::kContextFalse ? !*flag : *flag;
    }
    case Predicate::kPositive:
    case Predicate::kContextInt:
    case Predicate::kBaselineInt:
    case Predicate::kOpaqueInt: {
      const auto* number = std::get_if<std::int64_t>(&value);
      if (number == nullptr || *number < 0) {
        return std::nullopt;
      }
      return *number > 0;
    }
    case Predicate::kContextString:
    case Predicate::kOpaqueString:
    case Predicate::kBaselineString: {
      const auto* text = std::get_if<std::string>(&value);
      if (text == nullptr || (rule.predicate == Predicate::kBaselineString && text->empty())) {
        return std::nullopt;
      }
      if ((rule.signal == "sig.cert_sha256" || rule.signal == "integ.text_sha256") && !digest(*text, 64)) {
        return std::nullopt;
      }
      if (rule.signal == "id.cdhash" && !digest(*text, 40)) {
        return std::nullopt;
      }
      return !text->empty();
    }
    case Predicate::kUnavailable:
      return std::nullopt;
    case Predicate::kStrings:
    case Predicate::kContextStrings:
    case Predicate::kJdwp:
    case Predicate::kOpaqueStrings:
    case Predicate::kBaselineDigests:
    case Predicate::kThreads:
    case Predicate::kInline:
      return list_indicator(rule.predicate, value);
  }
  return std::nullopt;
}
/// Resolves one unique producer observation without first/last-wins behavior.
[[nodiscard]] LocalDecision evaluate(const Rule& rule, const CycleMetadata& metadata,
                                     std::span<const Observation> observations) {
  LocalDecision result{.rule_id = std::string(rule.rule_id), .evidence = {}};
  if (!metadata.config_known || !selected(metadata, rule.group).has_value()) {
    result.reason = LocalReason::kConfigUnknown;
    return result;
  }
  if (selected(metadata, rule.group) == false) {
    result.reason = LocalReason::kConfigDisabled;
    return result;
  }
  std::optional<std::size_t> found;
  for (std::size_t index = 0; index < observations.size(); ++index) {
    if (observations[index].signal == rule.signal && observations[index].source == rule.source) {
      if (found.has_value()) {
        result.reason = LocalReason::kDuplicateObservation;
        return result;
      }
      found = index;
    }
  }
  if (!found.has_value()) {
    return result;
  }
  result.evidence.push_back(*found);
  const Observation& observation = observations[*found];
  result.status = observation.status;
  if (observation.status != Status::kOk || rule.predicate == Predicate::kUnavailable) {
    result.reason = LocalReason::kStatusUnavailable;
    return result;
  }
  const std::optional<bool> present = indicator(rule, observation.value);
  if (!present.has_value()) {
    result.reason = LocalReason::kInvalidValue;
    return result;
  }
  result.predicate_evaluated = true;
  result.confidence = LocalConfidence::kLimited;
  if (rule.predicate == Predicate::kBaselineString || rule.predicate == Predicate::kBaselineInt ||
      rule.predicate == Predicate::kBaselineDigests) {
    result.reason = LocalReason::kBaselineRequired;
    return result;
  }
  if (rule.predicate == Predicate::kOpaqueString || rule.predicate == Predicate::kOpaqueStrings ||
      rule.predicate == Predicate::kOpaqueInt) {
    result.reason = LocalReason::kContextRequired;
    result.severity = LocalSeverity::kInfo;
    return result;
  }
  if (!*present) {
    result.verdict = LocalVerdict::kBenign;
    result.reason = LocalReason::kIndicatorAbsent;
    result.severity = LocalSeverity::kNone;
  } else if (rule.severity == LocalSeverity::kInfo) {
    result.reason = LocalReason::kContextRequired;
    result.severity = LocalSeverity::kInfo;
  } else {
    result.verdict = LocalVerdict::kThreat;
    result.reason = LocalReason::kIndicatorPresent;
    result.severity = rule.severity;
  }
  return result;
}
/// Finds an evaluated exact source row; a failed row cannot supply comparison facts.
[[nodiscard]] const LocalDecision* evaluated(const LocalDecisionReport& report,
                                             std::span<const Observation> observations, std::string_view signal,
                                             std::string_view source) {
  const auto found = std::ranges::find_if(report.rows, [&](const LocalDecision& row) {
    return row.predicate_evaluated && row.evidence.size() == 1 && observations[row.evidence[0]].signal == signal &&
           observations[row.evidence[0]].source == source;
  });
  return found == report.rows.end() ? nullptr : &*found;
}
/// Adds one derived row and its actual evaluated count, within the explicit result budget.
void add_row(LocalDecisionReport& report, LocalDecision row) {
  if (row.predicate_evaluated) {
    ++report.predicates_evaluated;
  }
  report.rows.push_back(std::move(row));
}
/// Distinguishes unknown and disabled selection from eligible unavailable evidence.
[[nodiscard]] LocalReason selection_reason(std::optional<bool> enabled, LocalReason eligible) {
  if (!enabled.has_value()) {
    return LocalReason::kConfigUnknown;
  }
  return *enabled ? eligible : LocalReason::kConfigDisabled;
}
/// Paired same-run hashes describe equality or mismatch, never trusted baseline integrity.
void integrity_pair(LocalDecisionReport& report, const CycleMetadata& metadata,
                    std::span<const Observation> observations) {
  LocalDecision row{.rule_id = "local." + report.platform + ".integrity_pair", .evidence = {}};
  const auto enabled = selected(metadata, "integrity");
  row.reason = selection_reason(enabled, LocalReason::kComparisonUnavailable);
  const auto* file = evaluated(report, observations, "integ.text_sha256", "file");
  const auto* memory = evaluated(report, observations, "integ.text_sha256", "memory");
  if (file != nullptr && memory != nullptr) {
    row.evidence = {file->evidence[0], memory->evidence[0]};
    const bool equal = observations[row.evidence[0]].value == observations[row.evidence[1]].value;
    row.predicate_evaluated = true;
    row.confidence = LocalConfidence::kLimited;
    row.reason = equal ? LocalReason::kHashesEqualUntrusted : LocalReason::kHashesDiffer;
    row.verdict = equal ? LocalVerdict::kUnknown : LocalVerdict::kThreat;
    row.severity = equal ? LocalSeverity::kUnknown : LocalSeverity::kHigh;
  }
  add_row(report, std::move(row));
}
/// Closed comparable-source identities, never arbitrary same-signal cross products.
struct RelationRule {
  std::string_view platform;
  std::string_view signal;
  std::string_view first;
  std::string_view second;
};
/// At most eleven pairs, independent of the number of untrusted records.
constexpr auto kRelations = std::to_array<RelationRule>({
    {.platform = "android", .signal = "root.fs_paths", .first = "access", .second = "stat"},
    {.platform = "android", .signal = "root.fs_paths", .first = "access", .second = "faccessat_syscall"},
    {.platform = "android", .signal = "root.fs_paths", .first = "stat", .second = "faccessat_syscall"},
    {.platform = "android", .signal = "root.mounts", .first = "proc_mounts", .second = "proc_mounts_syscall"},
    {.platform = "android", .signal = "root.rw_mounts", .first = "proc_mounts", .second = "proc_mounts_syscall"},
    {.platform = "android", .signal = "dbg.tracer_pid", .first = "proc_status", .second = "proc_status_syscall"},
    {.platform = "android", .signal = "hook.maps_hits", .first = "proc_maps", .second = "proc_maps_syscall"},
    {.platform = "android", .signal = "dbg.java_debugger", .first = "debug_api", .second = "jdwp_threads"},
    {.platform = "ios", .signal = "dbg.traced", .first = "sysctl", .second = "sysctl_syscall"},
    {.platform = "ios", .signal = "dbg.parent", .first = "getppid", .second = "sysctl_syscall"},
    {.platform = "ios", .signal = "id.bundle_id", .first = "CFBundle", .second = "Info.plist"},
});
/// Compares lists as sets without copying raw evidence or losing duplicate tuple checks.
[[nodiscard]] bool equal_facts(const Value& first, const Value& second) {
  const auto* left = std::get_if<std::vector<std::string>>(&first);
  const auto* right = std::get_if<std::vector<std::string>>(&second);
  if (left == nullptr || right == nullptr) {
    return first == second;
  }
  return std::ranges::all_of(*left, [&](const std::string& entry) { return std::ranges::contains(*right, entry); }) &&
         std::ranges::all_of(*right, [&](const std::string& entry) { return std::ranges::contains(*left, entry); });
}
/// Preserves disagreement separately; confidence never increases with source count.
void source_relations(LocalDecisionReport& report, std::span<const Observation> observations) {
  for (const auto& rule : kRelations) {
    if (rule.platform != report.platform) {
      continue;
    }
    const auto* first = evaluated(report, observations, rule.signal, rule.first);
    const auto* second = evaluated(report, observations, rule.signal, rule.second);
    if (first == nullptr || second == nullptr) {
      continue;
    }
    const bool java = rule.signal == "dbg.java_debugger";
    const bool equal =
        java ? first->verdict == second->verdict
             : equal_facts(observations[first->evidence[0]].value, observations[second->evidence[0]].value);
    const bool absent =
        first->reason == LocalReason::kIndicatorAbsent && second->reason == LocalReason::kIndicatorAbsent;
    LocalRelationState state = LocalRelationState::kDisagree;
    if (equal) {
      state = absent ? LocalRelationState::kAgreeAbsent : LocalRelationState::kAgreePresent;
    }
    report.relations.push_back({
        .first_rule_id = first->rule_id,
        .second_rule_id = second->rule_id,
        .state = state,
        .evidence = {first->evidence[0], second->evidence[0]},
    });
  }
}
/// Mirrors producer coverage after counter type validation.
[[nodiscard]] std::string_view observer_coverage(bool loss, std::string_view state, std::int64_t windows) {
  if (loss) {
    return "loss_detected";
  }
  return state == "active" && windows > 0 ? "best_effort" : "unknown";
}
/// Interprets only the complete closed overlay grammar, never isolated positive counters.
void overlay_context(LocalDecisionReport& report, const CycleMetadata& metadata,
                     std::span<const Observation> observations) {
  if (report.platform != "android") {
    return;
  }
  LocalDecision row{.rule_id = "local.android.overlay_context", .evidence = {}};
  const auto enabled = selected(metadata, "overlay");
  row.reason = selection_reason(enabled, LocalReason::kObserverUnavailable);
  constexpr auto kNames = std::to_array<std::string_view>({
      "overlay.observer_state",
      "overlay.coverage",
      "overlay.active_windows",
      "overlay.touch_events",
      "overlay.obscured_touch_events",
      "overlay.partially_obscured_touch_events",
      "overlay.dropped_events",
      "overlay.lost_windows",
      "overlay.invalid_events",
      "overlay.interval_ms",
  });
  row.evidence.reserve(kNames.size());
  for (const auto name : kNames) {
    const auto* input = evaluated(report, observations, name, "window_callback");
    if (input == nullptr) {
      add_row(report, std::move(row));
      return;
    }
    row.evidence.push_back(input->evidence[0]);
  }
  const auto& state = std::get<std::string>(observations[row.evidence[0]].value);
  const auto& coverage = std::get<std::string>(observations[row.evidence[1]].value);
  constexpr auto kStates =
      std::to_array<std::string_view>({"never_started", "active", "deactivated", "error", "unsupported"});
  constexpr auto kCoverages = std::to_array<std::string_view>({"unknown", "best_effort", "loss_detected"});
  const auto number = [&](std::size_t index) {
    return std::get<std::int64_t>(observations[row.evidence[index]].value);
  };
  const bool loss = number(6) > 0 || number(7) > 0 || number(8) > 0;
  const std::string_view expected = observer_coverage(loss, state, number(2));
  if (!std::ranges::contains(kStates, state) || !std::ranges::contains(kCoverages, coverage) || coverage != expected ||
      number(4) > number(3) || number(5) > number(3)) {
    row.reason = LocalReason::kObserverInconsistent;
  } else {
    row.predicate_evaluated = true;
    row.confidence = LocalConfidence::kLimited;
    row.severity = LocalSeverity::kInfo;
    row.reason = LocalReason::kContextObserved;
    if (loss) {
      row.reason = LocalReason::kObserverLoss;
    } else if (state != "active" || coverage != "best_effort") {
      row.reason = LocalReason::kObserverUnavailable;
    }
  }
  add_row(report, std::move(row));
}
/// Retains distinct bounded coverage problems, never classifying them as attacks.
void coverage_issues(LocalDecisionReport& report, const CycleMetadata& metadata) {
  if (!metadata.missing.empty()) {
    report.issues.push_back(LocalReason::kMissingObservation);
  }
  if (metadata.extra != 0) {
    report.issues.push_back(LocalReason::kExtraOutputs);
  }
  if (metadata.dropped != 0) {
    report.issues.push_back(LocalReason::kDroppedObservations);
  }
  if (metadata.unknown_status != 0) {
    report.issues.push_back(LocalReason::kUnknownStatus);
  }
  if (metadata.unknown_groups != 0) {
    report.issues.push_back(LocalReason::kUnknownGroups);
  }
  if (!metadata.duration_ns.has_value() || !metadata.sequence.has_value()) {
    report.issues.push_back(LocalReason::kInvalidClock);
  }
  if (!metadata.config_known) {
    report.issues.push_back(LocalReason::kConfigUnknown);
  }
}
}  // namespace

LocalDecisionReport evaluate_local_decisions(const CycleMetadata& metadata,
                                             std::span<const Observation> retained_builtins,
                                             const CycleCatalogue& catalogue) {
  LocalDecisionReport report;
  report.native_metadata_version = metadata.version;
  if (!bounded(retained_builtins)) {
    report.reason = LocalReason::kInputLimit;
    return report;
  }
  if (!bound_catalogue(metadata, catalogue)) {
    report.reason = LocalReason::kCatalogueUnknown;
    return report;
  }
  if (!valid_metadata(metadata, retained_builtins, catalogue)) {
    report.reason = metadata.overflow ? LocalReason::kOverflow : LocalReason::kMetadataInvalid;
    return report;
  }
  report.platform = metadata.platform;
  report.catalogue_id = metadata.catalogue_id;
  report.builtin_observations = retained_builtins.size();
  if (metadata.config_known) {
    report.coverage = metadata.complete ? LocalCoverage::kComplete : LocalCoverage::kIncomplete;
  }
  report.rows.reserve(catalogue.outputs.size() + 2);
  report.relations.reserve(kRelations.size());
  report.issues.reserve(8);
  coverage_issues(report, metadata);
  for (const auto& rule : decision_internal::kRules) {
    if (rule.platform == report.platform) {
      add_row(report, evaluate(rule, metadata, retained_builtins));
    }
  }
  integrity_pair(report, metadata, retained_builtins);
  source_relations(report, retained_builtins);
  overlay_context(report, metadata, retained_builtins);
  return report;
}

std::string_view local_reason_name(LocalReason reason) {
  constexpr auto kNames = std::to_array<std::string_view>({
      "none",
      "indicator_present",
      "indicator_absent",
      "context_required",
      "baseline_required",
      "unregistered_rule",
      "status_unavailable",
      "invalid_value",
      "config_disabled",
      "config_unknown",
      "catalogue_unknown",
      "missing_observation",
      "duplicate_observation",
      "input_limit",
      "metadata_invalid",
      "hashes_differ",
      "hashes_equal_untrusted",
      "comparison_unavailable",
      "context_observed",
      "observer_unavailable",
      "observer_loss",
      "observer_inconsistent",
      "extra_outputs",
      "dropped_observations",
      "overflow",
      "unknown_status",
      "unknown_groups",
      "invalid_clock",
  });
  const auto index = static_cast<std::size_t>(reason);
  return index < kNames.size() ? std::span(kNames)[index] : "unknown";
}
}  // namespace rasp
