/// Bounded report-only interpretation of owned native cycle evidence, never device attestation.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "rasp/observation.h"

namespace rasp {
struct CycleMetadata;
struct CycleCatalogue;
/// Per-indicator result; benign never means that the device is clean.
enum class LocalVerdict : std::uint8_t { kThreat, kBenign, kUnknown };
/// Indicator severity, independent of coverage and client trust.
enum class LocalSeverity : std::uint8_t { kHigh, kMedium, kInfo, kNone, kUnknown };
/// Evidence limitation category, never a probability.
enum class LocalConfidence : std::uint8_t { kLimited, kUnavailable };
/// Client evidence cannot establish server authority.
enum class LocalEvidenceTrust : std::uint8_t { kUnverifiedClient };
/// Selected output retention, not collection success or protection effectiveness.
enum class LocalCoverage : std::uint8_t { kComplete, kIncomplete, kUnknown };
/// Version-one closed reasons; collection failures never become findings.
enum class LocalReason : std::uint8_t {
  kNone,
  kIndicatorPresent,
  kIndicatorAbsent,
  kContextRequired,
  kBaselineRequired,
  kUnregisteredRule,
  kStatusUnavailable,
  kInvalidValue,
  kConfigDisabled,
  kConfigUnknown,
  kCatalogueUnknown,
  kMissingObservation,
  kDuplicateObservation,
  kInputLimit,
  kMetadataInvalid,
  kHashesDiffer,
  kHashesEqualUntrusted,
  kComparisonUnavailable,
  kContextObserved,
  kObserverUnavailable,
  kObserverLoss,
  kObserverInconsistent,
  kExtraOutputs,
  kDroppedObservations,
  kOverflow,
  kUnknownStatus,
  kUnknownGroups,
  kInvalidClock,
};
/// Comparable reports can agree without becoming independent trusted evidence.
enum class LocalRelationState : std::uint8_t { kAgreePresent, kAgreeAbsent, kDisagree, kUnavailable };
/// One exact versioned predicate result with indices into its enclosing owned snapshot.
struct LocalDecision {
  /// Static-vocabulary identifier, owned by the report.
  std::string rule_id;
  /// Semantic rule version, independent of report and native metadata versions.
  std::uint32_t rule_version = 1;
  /// Result for this indicator only.
  LocalVerdict verdict = LocalVerdict::kUnknown;
  /// Unavailable evidence has unknown severity.
  LocalSeverity severity = LocalSeverity::kUnknown;
  /// No result elevates client evidence above limited confidence.
  LocalConfidence confidence = LocalConfidence::kUnavailable;
  /// Exact abstention or interpretation reason.
  LocalReason reason = LocalReason::kMissingObservation;
  /// Actual status when a unique observation exists, including unknown enum values.
  std::optional<Status> status = std::nullopt;
  /// Whether a typed predicate ran; disabled/missing/unavailable rows do not count.
  bool predicate_evaluated = false;
  /// At most ten indices, all into retained builtins in this snapshot.
  std::vector<std::size_t> evidence;
};
/// Separate two-source comparison; disagreement does not assert an attack.
struct LocalRelation {
  /// Identifier of the first exact source rule.
  std::string first_rule_id;
  /// Identifier of the second exact source rule.
  std::string second_rule_id;
  /// Agreement, disagreement or unavailable prerequisites.
  LocalRelationState state = LocalRelationState::kUnavailable;
  /// At most two indices into the same snapshot.
  std::vector<std::size_t> evidence;
};
/// Immutable when published as part of a const CycleSnapshot; has no side effects or aggregate verdict.
struct LocalDecisionReport {
  /// Native local-report schema, independent of cycle wire formats.
  std::uint32_t schema_version = 1;
  /// Stable reason vocabulary version.
  std::uint32_t reason_version = 1;
  /// Input native metadata version.
  std::uint32_t native_metadata_version = 1;
  /// Always unverified client evidence.
  LocalEvidenceTrust evidence_trust = LocalEvidenceTrust::kUnverifiedClient;
  /// Exact recognized platform; empty on invalid binding.
  std::string platform;
  /// Explicitly supported catalogue digest; empty on invalid binding.
  std::string catalogue_id;
  /// Coverage and collection status remain independent.
  LocalCoverage coverage = LocalCoverage::kUnknown;
  /// Whole-report abstention, or none when per-rule rows are available.
  LocalReason reason = LocalReason::kNone;
  /// Actual retained producer prefix; plugin collisions cannot contribute.
  std::size_t builtin_observations = 0;
  /// Number of successfully typed predicates executed, never row count.
  std::size_t predicates_evaluated = 0;
  /// At most 256 native and derived rows, including explicit unavailable rows.
  std::vector<LocalDecision> rows;
  /// At most 16 closed comparable-source pairs.
  std::vector<LocalRelation> relations;
  /// At most 16 distinct coverage issues; none asserts compromise.
  std::vector<LocalReason> issues;
};
/// Interprets bounded builtins using exact compiled definitions and a pinned semantic catalogue.
/// @param metadata Completed metadata from the same finite run, never client authority.
/// @param retained_builtins Retained builtin prefix; no plugin observations.
/// @param catalogue Actual dispatcher catalogue, validated against compiled definitions and the supported digest.
/// @return Bounded report with explicit unavailable states; never performs policy actions or I/O.
[[nodiscard]] LocalDecisionReport evaluate_local_decisions(const CycleMetadata& metadata,
                                                           std::span<const Observation> retained_builtins,
                                                           const CycleCatalogue& catalogue);
/// Returns a stable version-one reason name, or unknown for an invalid enum.
/// @param reason Typed reason to describe.
/// @return Static vocabulary text, never an interpolated observation.
[[nodiscard]] std::string_view local_reason_name(LocalReason reason);
}  // namespace rasp
