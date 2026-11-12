/// Actual immutable typed-report policy evaluation and bounded process-lifetime publication.
#include "local_policy_state.h"

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include "local_policy_config.h"
#include "local_policy_selectors.h"
#include "rasp/config.h"
#include "rasp/cycle.h"
#include "rasp/decision.h"
#include "rasp/local_policy.h"
#include "rasp/local_policy_host.h"
#include "rasp/observation.h"
#include "rasp/parse_config.h"

namespace rasp {
namespace {
/// One intentionally process-lifetime installed owner; never replaced or destroyed.
std::atomic<LocalPolicyState*>& process_slot() {
  static constinit std::atomic<LocalPolicyState*> state{nullptr};
  return state;
}
/// Reparse canonical bytes so a public C++ config value cannot bypass parser bounds.
Config validated(Config config, std::string_view platform) {
  const auto kind = config.local_policy.state;
  if (platform != "android" && platform != "ios") {
    config.local_policy.state = LocalPolicyStateKind::kUnsupported;
    return config;
  }
  if (kind == LocalPolicyStateKind::kGate || kind == LocalPolicyStateKind::kReportOnly) {
    const std::string serialized = policy_internal::canonical_config(config);
    Config parsed = parse_config(serialized);
    if (parsed.local_policy.platform != platform) {
      parsed.local_policy.state = LocalPolicyStateKind::kUnsupported;
    }
    return parsed;
  }
  if (kind == LocalPolicyStateKind::kAbsentReportOnly) {
    config.local_policy = LocalPolicy{};
    if (policy_internal::canonical_config(config).empty()) {
      config.local_policy.state = LocalPolicyStateKind::kInvalid;
    }
  }
  return config;
}
/// Invalid config cannot advertise the default policy hash as a downgrade.
bool valid_policy(const Config& config) {
  return config.local_policy.state == LocalPolicyStateKind::kAbsentReportOnly ||
         config.local_policy.state == LocalPolicyStateKind::kReportOnly ||
         config.local_policy.state == LocalPolicyStateKind::kGate;
}
/// Copy bounded owned text without truncation or borrowed string lifetime.
bool copy_text(std::span<char> output, std::string_view value) {
  if (value.size() >= output.size()) {
    return false;
  }
  std::ranges::copy(value, output.begin());
  return true;
}
/// Validate operation/hash arrays before interpreting any request data.
std::optional<std::string_view> request_text(std::span<const char> bytes, bool hash) {
  const auto end = std::ranges::find(bytes, '\0');
  if (end == bytes.end() || end == bytes.begin()) {
    return std::nullopt;
  }
  const std::string_view value(bytes.data(), static_cast<std::size_t>(end - bytes.begin()));
  if (hash && value.size() != 64) {
    return std::nullopt;
  }
  if (!std::ranges::all_of(value, [hash](char character) {
        if (hash) {
          return (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f');
        }
        return (character >= '0' && character <= '9') || (character >= 'A' && character <= 'Z') ||
               (character >= 'a' && character <= 'z') || character == '_' || character == '.' || character == '-';
      })) {
    return std::nullopt;
  }
  return value;
}
/// Strict API failure state, independent of whether the caller wanted report-only.
struct GateFailure {
  std::int32_t status;
  std::uint32_t reason;
};
/// Preserve the distinction between API status and the primary gate reason.
std::int32_t fail(struct RaspLocalGateResultV1& output, GateFailure failure) {
  output.status = static_cast<std::uint32_t>(failure.status);
  output.reason = failure.reason;
  output.action = RASP_LOCAL_DENY;
  return failure.status;
}
/// Unknown evidence remains advisory only when the validated policy explicitly says so.
std::int32_t candidate(struct RaspLocalGateResultV1& output, std::uint32_t reason, bool report_only,
                       std::int32_t status = RASP_LOCAL_OK) {
  output.reason = reason;
  output.action = report_only ? RASP_LOCAL_REPORT : RASP_LOCAL_DENY;
  output.status = report_only ? RASP_LOCAL_OK : static_cast<std::uint32_t>(status);
  return static_cast<std::int32_t>(output.status);
}
/// Admission lease bounds all retained evaluation owners, including early returns.
class ReaderLease {
 public:
  /// One of at most eight bounded CAS attempts acquires an evaluation slot.
  explicit ReaderLease(std::atomic<std::uint32_t>& readers) : readers_(readers) {
    auto count = readers_.load(std::memory_order_relaxed);
    for (std::uint32_t attempt = 0; attempt < 8 && count < 8; ++attempt) {
      if (readers_.compare_exchange_strong(count, count + 1, std::memory_order_acq_rel)) {
        acquired_ = true;
        return;
      }
    }
  }
  ReaderLease(const ReaderLease&) = delete;
  ReaderLease& operator=(const ReaderLease&) = delete;
  ReaderLease(ReaderLease&&) = delete;
  ReaderLease& operator=(ReaderLease&&) = delete;
  /// Releasing occurs after the decision and its owner have been destroyed.
  ~ReaderLease() {
    if (acquired_) {
      readers_.fetch_sub(1, std::memory_order_release);
    }
  }
  /// Whether this call may retain an owner at all.
  [[nodiscard]] bool acquired() const { return acquired_; }

 private:
  std::atomic<std::uint32_t>& readers_;
  bool acquired_ = false;
};
/// Actual owner and its owned projection, const throughout the final host copyout.
struct LocalGateDecision {
  std::shared_ptr<const CycleSnapshot> owner;
  struct RaspLocalGateResultV1 projection{};
};
/// Reject report/metadata inconsistencies without interpreting raw observation payloads.
bool envelope(const CycleSnapshot& snapshot, std::string_view platform) {
  const auto& metadata = snapshot.metadata;
  const auto& report = snapshot.local_decisions;
  return metadata.version == 1 && metadata.platform == platform &&
         metadata.catalogue_id == policy_internal::kCatalogue && metadata.execution_finished && metadata.complete &&
         metadata.config_known && metadata.catalogue_known && !metadata.config_truncated &&
         !metadata.catalogue_truncated && !metadata.overflow && metadata.sequence.has_value() &&
         *metadata.sequence != 0 && metadata.duration_ns.has_value() && metadata.expected.has_value() &&
         metadata.seen == *metadata.expected && metadata.groups.size() <= 64 && metadata.missing.empty() &&
         metadata.extra == 0 && metadata.dropped == 0 && metadata.unknown_groups == 0 && metadata.unknown_status == 0 &&
         snapshot.observations.size() <= 256 && report.rows.size() <= 256 && report.relations.size() <= 16 &&
         report.issues.size() <= 16 && report.builtin_observations <= snapshot.observations.size() &&
         report.schema_version == 1 && report.reason_version == 1 && report.native_metadata_version == 1 &&
         report.platform == platform && report.catalogue_id == policy_internal::kCatalogue &&
         report.reason == LocalReason::kNone && report.evidence_trust == LocalEvidenceTrust::kUnverifiedClient &&
         report.coverage == LocalCoverage::kComplete;
}
/// Copy and validate one exact typed row without rereading raw observations.
LocalVerdict inspect_rule(const LocalPolicyRule& rule, const CycleSnapshot& snapshot,
                          struct RaspLocalGateDetailV1& detail) {
  static_cast<void>(copy_text(detail.rule_id, rule.rule_id));
  detail.rule_version = rule.rule_version;
  detail.verdict = static_cast<std::uint32_t>(LocalVerdict::kUnknown);
  detail.confidence = static_cast<std::uint32_t>(LocalConfidence::kUnavailable);
  detail.reason = static_cast<std::uint32_t>(LocalReason::kMissingObservation);
  const LocalDecision* found = nullptr;
  std::size_t count = 0;
  for (const auto& row : snapshot.local_decisions.rows) {
    if (row.rule_id == rule.rule_id) {
      found = &row;
      ++count;
    }
  }
  if (count != 1 || found == nullptr) {
    return LocalVerdict::kUnknown;
  }
  detail.rule_version = found->rule_version;
  detail.verdict = static_cast<std::uint32_t>(found->verdict);
  detail.reason = static_cast<std::uint32_t>(found->reason);
  detail.confidence = static_cast<std::uint32_t>(found->confidence);
  detail.status_present = found->status.has_value() ? 1 : 0;
  detail.status = found->status.has_value() ? static_cast<std::uint32_t>(*found->status) : 0;
  detail.predicate_evaluated = found->predicate_evaluated ? 1 : 0;
  const bool valid_evidence =
      !found->evidence.empty() && found->evidence.size() <= 10 &&
      std::ranges::all_of(found->evidence, [&](std::size_t index) {
        return index < snapshot.local_decisions.builtin_observations && index < snapshot.observations.size();
      });
  if (valid_evidence) {
    for (const auto index : found->evidence) {
      std::span(detail.evidence)[detail.evidence_count++] = static_cast<std::uint32_t>(index);
    }
  }
  const auto group = std::ranges::find(snapshot.metadata.groups, rule.group, &CycleGroup::name);
  if (found->rule_version != rule.rule_version || !found->predicate_evaluated || found->status != Status::kOk ||
      found->confidence != LocalConfidence::kLimited || !valid_evidence || group == snapshot.metadata.groups.end() ||
      group->enabled != true) {
    return LocalVerdict::kUnknown;
  }
  if (found->verdict == LocalVerdict::kThreat && found->reason == LocalReason::kIndicatorPresent) {
    return LocalVerdict::kThreat;
  }
  if (found->verdict == LocalVerdict::kBenign && found->reason == LocalReason::kIndicatorAbsent) {
    return LocalVerdict::kBenign;
  }
  return LocalVerdict::kUnknown;
}
/// Combine only selected supported predicates while retaining every copied row reason.
std::uint32_t selected(const LocalPolicyOperation& operation, const CycleSnapshot& snapshot,
                       struct RaspLocalGateResultV1& output) {
  bool unavailable = operation.rules.empty();
  bool threat = false;
  for (const auto& rule : operation.rules) {
    const auto verdict = inspect_rule(rule, snapshot, std::span(output.details)[output.detail_count++]);
    if (verdict == LocalVerdict::kUnknown) {
      unavailable = true;
    } else {
      ++output.evaluated;
      threat = threat || verdict == LocalVerdict::kThreat;
    }
  }
  if (unavailable) {
    return RASP_LOCAL_REQUIRED_UNAVAILABLE;
  }
  return threat ? RASP_LOCAL_INDICATOR_PRESENT : RASP_LOCAL_ALL_ABSENT;
}
/// Coherent samples from one private suspend-inclusive clock domain.
struct PublicationTiming {
  std::optional<std::int64_t> start;
  std::optional<std::int64_t> end;
  std::optional<std::int64_t> now;
  bool valid = false;
};
/// Pure evaluation of a captured owning publication; never changes report or clock health.
std::int32_t evaluate_publication(const CycleSnapshot& snapshot, const LocalPolicyOperation& operation,
                                  std::string_view platform, const PublicationTiming& timing, bool report_only,
                                  struct RaspLocalGateResultV1& output) {
  static_cast<void>(copy_text(output.session_id, snapshot.metadata.session_id));
  static_cast<void>(copy_text(output.run_id, snapshot.metadata.run_id));
  if (snapshot.local_decisions.schema_version != 1 || snapshot.local_decisions.reason_version != 1 ||
      snapshot.local_decisions.native_metadata_version != 1 ||
      snapshot.local_decisions.catalogue_id != policy_internal::kCatalogue ||
      snapshot.local_decisions.platform != platform ||
      snapshot.local_decisions.evidence_trust != LocalEvidenceTrust::kUnverifiedClient) {
    return candidate(output, RASP_LOCAL_BINDING_MISMATCH, report_only);
  }
  if (operation.rules.size() > 8) {
    return fail(output, GateFailure{.status = RASP_LOCAL_INVALID_POLICY, .reason = RASP_LOCAL_POLICY_INVALID});
  }
  std::uint32_t row_reason = RASP_LOCAL_REQUIRED_UNAVAILABLE;
  if (snapshot.local_decisions.rows.size() <= 256 && snapshot.metadata.groups.size() <= 64) {
    row_reason = selected(operation, snapshot, output);
  }
  if (!envelope(snapshot, platform)) {
    return candidate(output, RASP_LOCAL_COVERAGE_UNAVAILABLE, report_only);
  }
  output.coverage = static_cast<std::uint32_t>(snapshot.local_decisions.coverage);
  output.sequence_present = 1;
  if (!snapshot.metadata.sequence.has_value()) {
    return candidate(output, RASP_LOCAL_COVERAGE_UNAVAILABLE, report_only);
  }
  output.sequence = *snapshot.metadata.sequence;
  if (!timing.valid || !timing.start.has_value() || !timing.end.has_value() || !timing.now.has_value() ||
      *timing.start < 0 || *timing.end < *timing.start || *timing.now < *timing.end) {
    return candidate(output, RASP_LOCAL_CLOCK_UNAVAILABLE, report_only);
  }
  output.timing_present = 1;
  output.evidence_age_ns = static_cast<std::uint64_t>(*timing.now) - static_cast<std::uint64_t>(*timing.start);
  output.cycle_duration_ns = static_cast<std::uint64_t>(*timing.end) - static_cast<std::uint64_t>(*timing.start);
  if (output.evidence_age_ns > static_cast<std::uint64_t>(operation.max_evidence_age_ms) * 1000000) {
    return candidate(output, RASP_LOCAL_STALE, report_only);
  }
  if (output.cycle_duration_ns > static_cast<std::uint64_t>(operation.max_cycle_duration_ms) * 1000000) {
    return candidate(output, RASP_LOCAL_SLOW_CYCLE, report_only);
  }
  output.reason = row_reason;
  output.candidate_action = output.reason == RASP_LOCAL_ALL_ABSENT ? RASP_LOCAL_ALLOW : RASP_LOCAL_DENY;
  output.action = report_only ? RASP_LOCAL_REPORT : output.candidate_action;
  return RASP_LOCAL_OK;
}

}  // namespace

LocalPolicyState::LocalPolicyState(Config config, std::string platform, std::optional<std::int64_t> (*clock)())
    : config_(validated(std::move(config), platform)),
      platform_(std::move(platform)),
      policy_hash_(valid_policy(config_) ? local_policy_hash(config_.local_policy.canonical_json) : std::string{}),
      config_hash_(valid_policy(config_) ? local_policy_hash(policy_internal::canonical_config(config_))
                                         : std::string{}),
      clock_(clock) {}

std::optional<std::int64_t> LocalPolicyState::sample_clock() {
  const auto tick = clock_ == nullptr ? std::nullopt : clock_();
  if (!tick.has_value() || *tick < 0 || (last_tick_.has_value() && *tick < *last_tick_)) {
    if (faults_ == std::numeric_limits<std::uint64_t>::max()) {
      exhausted_ = true;
    } else {
      ++faults_;
    }
    last_tick_ = tick.has_value() && *tick >= 0 ? tick : std::nullopt;
    return std::nullopt;
  }
  last_tick_ = tick;
  return tick;
}
void LocalPolicyState::begin_cycle() {
  const std::scoped_lock lock(mutex_);
  start_ = sample_clock();
  start_faults_ = faults_;
}
void LocalPolicyState::finish_cycle(std::shared_ptr<const CycleSnapshot> snapshot) {
  std::shared_ptr<const CycleSnapshot> replaced;
  {
    const std::scoped_lock lock(mutex_);
    published_end_ = sample_clock();
    published_start_ = std::exchange(start_, std::nullopt);
    published_faults_ = start_faults_;
    replaced = std::exchange(snapshot_, std::move(snapshot));
  }
}
std::int32_t LocalPolicyState::info(struct RaspLocalPolicyInfoV1& output) const {
  std::memset(&output, 0, sizeof(output));
  output.abi_version = 1;
  output.struct_size = sizeof(output);
  output.config_state = static_cast<std::uint32_t>(config_.local_policy.state);
  output.policy_version = config_.local_policy.policy_version;
  output.policy_schema_version = 1;
  output.engine_version = 1;
  output.gate_reason_version = 1;
  output.report_schema_version = 1;
  output.report_reason_version = 1;
  output.native_metadata_version = 1;
  static_cast<void>(copy_text(output.policy_id, config_.local_policy.policy_id));
  static_cast<void>(copy_text(output.policy_sha256, policy_hash_));
  static_cast<void>(copy_text(output.effective_config_sha256, config_hash_));
  static_cast<void>(copy_text(output.catalogue_id, policy_internal::kCatalogue));
  static_cast<void>(copy_text(output.platform, platform_));
  if (config_.checks.has_value() && config_.checks->size() <= 64) {
    output.checks_known = 1;
    auto groups = *config_.checks;
    std::ranges::sort(groups);
    for (const auto& group : groups) {
      if (!copy_text(std::span(output.checks)[output.check_count].value, group)) {
        output.status = RASP_LOCAL_INVALID_POLICY;
        return RASP_LOCAL_INVALID_POLICY;
      }
      ++output.check_count;
    }
  }
  if (!valid_policy(config_)) {
    output.status = config_.local_policy.state == LocalPolicyStateKind::kUnsupported ? RASP_LOCAL_UNSUPPORTED_POLICY
                                                                                     : RASP_LOCAL_INVALID_POLICY;
  } else if (policy_hash_.empty() || config_hash_.empty()) {
    output.status = RASP_LOCAL_INTERNAL_ERROR;
  }
  return static_cast<std::int32_t>(output.status);
}
std::int32_t LocalPolicyState::gate(const struct RaspLocalGateRequestV1& request,
                                    struct RaspLocalGateResultV1& output) {
  std::memset(&output, 0, sizeof(output));
  output.abi_version = 1;
  output.struct_size = sizeof(output);
  output.gate_reason_version = 1;
  output.coverage = static_cast<std::uint32_t>(LocalCoverage::kUnknown);
  output.config_state = static_cast<std::uint32_t>(config_.local_policy.state);
  output.policy_version = config_.local_policy.policy_version;
  output.report_schema_version = 1;
  output.report_reason_version = 1;
  output.native_metadata_version = 1;
  static_cast<void>(copy_text(output.policy_id, config_.local_policy.policy_id));
  static_cast<void>(copy_text(output.policy_sha256, policy_hash_));
  static_cast<void>(copy_text(output.effective_config_sha256, config_hash_));
  static_cast<void>(copy_text(output.catalogue_id, policy_internal::kCatalogue));
  static_cast<void>(copy_text(output.platform, platform_));
  const auto operation_name = request_text(request.operation, false);
  const auto expected_hash = request_text(request.expected_policy_sha256, true);
  if (request.abi_version != 1 || request.struct_size != sizeof(request)) {
    return fail(output, GateFailure{.status = RASP_LOCAL_UNSUPPORTED_ABI, .reason = RASP_LOCAL_BAD_ARGUMENT});
  }
  if (!operation_name.has_value() || !expected_hash.has_value() ||
      std::ranges::any_of(request.reserved, [](auto byte) { return byte != 0; })) {
    return fail(output, GateFailure{.status = RASP_LOCAL_INVALID_ARGUMENT, .reason = RASP_LOCAL_BAD_ARGUMENT});
  }
  static_cast<void>(copy_text(output.operation, *operation_name));
  if (!valid_policy(config_)) {
    return fail(
        output,
        GateFailure{
            .status = config_.local_policy.state == LocalPolicyStateKind::kUnsupported ? RASP_LOCAL_UNSUPPORTED_POLICY
                                                                                       : RASP_LOCAL_INVALID_POLICY,
            .reason = static_cast<std::uint32_t>(config_.local_policy.state == LocalPolicyStateKind::kUnsupported
                                                     ? RASP_LOCAL_POLICY_UNSUPPORTED
                                                     : RASP_LOCAL_POLICY_INVALID),
        });
  }
  if (policy_hash_.empty() || config_hash_.empty()) {
    return fail(output, GateFailure{.status = RASP_LOCAL_INTERNAL_ERROR, .reason = RASP_LOCAL_POLICY_INVALID});
  }
  if (*expected_hash != policy_hash_) {
    return fail(output, GateFailure{.status = RASP_LOCAL_OK, .reason = RASP_LOCAL_HASH_MISMATCH});
  }
  const bool report_only = config_.local_policy.state != LocalPolicyStateKind::kGate;
  const auto operation =
      std::ranges::find(config_.local_policy.operations, *operation_name, &LocalPolicyOperation::name);
  if (operation == config_.local_policy.operations.end()) {
    return candidate(output,
                     config_.local_policy.operations.empty() ? RASP_LOCAL_NO_SELECTION : RASP_LOCAL_OPERATION_UNKNOWN,
                     report_only);
  }
  const ReaderLease lease(readers_);
  if (!lease.acquired()) {
    return fail(output, GateFailure{.status = RASP_LOCAL_BUSY, .reason = RASP_LOCAL_CONTENDED});
  }
  std::shared_ptr<const CycleSnapshot> owner;
  PublicationTiming timing;
  {
    const std::unique_lock lock(mutex_, std::try_to_lock);
    if (!lock.owns_lock()) {
      return fail(output, GateFailure{.status = RASP_LOCAL_BUSY, .reason = RASP_LOCAL_CONTENDED});
    }
    timing.now = sample_clock();
    owner = snapshot_;
    timing.start = published_start_;
    timing.end = published_end_;
    timing.valid = !exhausted_ && published_faults_ == faults_;
  }
  if (owner == nullptr) {
    return candidate(output, RASP_LOCAL_NO_PUBLICATION, report_only, RASP_LOCAL_NOT_READY);
  }
  const auto status = evaluate_publication(*owner, *operation, platform_, timing, report_only, output);
  const LocalGateDecision decision{.owner = std::move(owner), .projection = output};
  output = decision.projection;
  return status;
}
LocalPolicyState* install_local_policy(std::unique_ptr<LocalPolicyState> state) {
  if (state == nullptr) {
    return nullptr;
  }
  LocalPolicyState* expected = nullptr;
  if (!process_slot().compare_exchange_strong(expected, state.get(), std::memory_order_release,
                                              std::memory_order_acquire)) {
    return nullptr;
  }
  return state.release();
}
LocalPolicyState* process_local_policy() { return process_slot().load(std::memory_order_acquire); }
}  // namespace rasp
