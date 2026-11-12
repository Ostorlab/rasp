/// Primitive owned copyout ABI for explicitly adapted host operations; never a reusable permit.
#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Version-one action values; zero-initialized/error output always denies.
#define RASP_LOCAL_DENY INT32_C(0)
#define RASP_LOCAL_REPORT INT32_C(1)
#define RASP_LOCAL_ALLOW INT32_C(2)
/// Call status is separate from action; non-OK must never permit an operation.
#define RASP_LOCAL_OK INT32_C(0)
#define RASP_LOCAL_INVALID_ARGUMENT INT32_C(1)
#define RASP_LOCAL_UNSUPPORTED_ABI INT32_C(2)
#define RASP_LOCAL_NOT_READY INT32_C(3)
#define RASP_LOCAL_BUSY INT32_C(4)
#define RASP_LOCAL_INVALID_POLICY INT32_C(5)
#define RASP_LOCAL_UNSUPPORTED_POLICY INT32_C(6)
#define RASP_LOCAL_INTERNAL_ERROR INT32_C(7)
/// Stable gate reason vocabulary version one, separate from native local-decision reason values.
#define RASP_LOCAL_NO_SELECTION INT32_C(0)
#define RASP_LOCAL_POLICY_INVALID INT32_C(1)
#define RASP_LOCAL_POLICY_UNSUPPORTED INT32_C(2)
#define RASP_LOCAL_HASH_MISMATCH INT32_C(3)
#define RASP_LOCAL_OPERATION_UNKNOWN INT32_C(4)
#define RASP_LOCAL_NO_PUBLICATION INT32_C(5)
#define RASP_LOCAL_COVERAGE_UNAVAILABLE INT32_C(6)
#define RASP_LOCAL_CLOCK_UNAVAILABLE INT32_C(7)
#define RASP_LOCAL_STALE INT32_C(8)
#define RASP_LOCAL_SLOW_CYCLE INT32_C(9)
#define RASP_LOCAL_REQUIRED_UNAVAILABLE INT32_C(10)
#define RASP_LOCAL_INDICATOR_PRESENT INT32_C(11)
#define RASP_LOCAL_ALL_ABSENT INT32_C(12)
#define RASP_LOCAL_BINDING_MISMATCH INT32_C(13)
#define RASP_LOCAL_CONTENDED INT32_C(14)
#define RASP_LOCAL_BAD_ARGUMENT INT32_C(15)
/// Typed header-only constants for Swift, whose importer cannot consume INT32_C macros.
/// Internal linkage preserves the fixed function-only export set.
static const int32_t kRaspLocalDeny = RASP_LOCAL_DENY;
static const int32_t kRaspLocalReport = RASP_LOCAL_REPORT;
static const int32_t kRaspLocalAllow = RASP_LOCAL_ALLOW;
static const int32_t kRaspLocalOk = RASP_LOCAL_OK;
static const int32_t kRaspLocalInvalidArgument = RASP_LOCAL_INVALID_ARGUMENT;
static const int32_t kRaspLocalUnsupportedAbi = RASP_LOCAL_UNSUPPORTED_ABI;
static const int32_t kRaspLocalNotReady = RASP_LOCAL_NOT_READY;
static const int32_t kRaspLocalBusy = RASP_LOCAL_BUSY;
static const int32_t kRaspLocalInvalidPolicy = RASP_LOCAL_INVALID_POLICY;
static const int32_t kRaspLocalUnsupportedPolicy = RASP_LOCAL_UNSUPPORTED_POLICY;
static const int32_t kRaspLocalInternalError = RASP_LOCAL_INTERNAL_ERROR;
static const int32_t kRaspLocalNoSelection = RASP_LOCAL_NO_SELECTION;
static const int32_t kRaspLocalPolicyInvalid = RASP_LOCAL_POLICY_INVALID;
static const int32_t kRaspLocalPolicyUnsupported = RASP_LOCAL_POLICY_UNSUPPORTED;
static const int32_t kRaspLocalHashMismatch = RASP_LOCAL_HASH_MISMATCH;
static const int32_t kRaspLocalOperationUnknown = RASP_LOCAL_OPERATION_UNKNOWN;
static const int32_t kRaspLocalNoPublication = RASP_LOCAL_NO_PUBLICATION;
static const int32_t kRaspLocalCoverageUnavailable = RASP_LOCAL_COVERAGE_UNAVAILABLE;
static const int32_t kRaspLocalClockUnavailable = RASP_LOCAL_CLOCK_UNAVAILABLE;
static const int32_t kRaspLocalStale = RASP_LOCAL_STALE;
static const int32_t kRaspLocalSlowCycle = RASP_LOCAL_SLOW_CYCLE;
static const int32_t kRaspLocalRequiredUnavailable = RASP_LOCAL_REQUIRED_UNAVAILABLE;
static const int32_t kRaspLocalIndicatorPresent = RASP_LOCAL_INDICATOR_PRESENT;
static const int32_t kRaspLocalAllAbsent = RASP_LOCAL_ALL_ABSENT;
static const int32_t kRaspLocalBindingMismatch = RASP_LOCAL_BINDING_MISMATCH;
static const int32_t kRaspLocalContended = RASP_LOCAL_CONTENDED;
static const int32_t kRaspLocalBadArgument = RASP_LOCAL_BAD_ARGUMENT;
/// Exact version-one request, valid aligned memory borrowed only during the call.
struct RaspLocalGateRequestV1 {
  /// Exact primitive ABI version; callers set 1.
  uint32_t abi_version;
  /// Exact sizeof this versioned caller-owned structure.
  uint32_t struct_size;
  /// NUL-terminated ASCII operation name; at most 32 bytes.
  char operation[33];
  /// Host-compiled policy expectation; exactly 64 lowercase hex bytes.
  char expected_policy_sha256[65];
  /// Reserved bytes must remain zero.
  uint8_t reserved[6];
};
/// Selected typed native local-decision row; owned diagnostic indices, never pointers into runtime storage.
struct RaspLocalGateDetailV1 {
  /// Exact selected predicate semantic version.
  uint32_t rule_version;
  /// Native per-indicator verdict; never aggregate device health.
  uint32_t verdict;
  /// Versioned reason: gate vocabulary at top level, native vocabulary in details.
  uint32_t reason;
  /// One when the exact native collection status exists.
  uint32_t status_present;
  /// API status at top level; actual native collection status in a detail.
  uint32_t status;
  /// Native limited/unavailable confidence, never a probability.
  uint32_t confidence;
  /// One only when the native typed predicate actually ran.
  uint32_t predicate_evaluated;
  /// Number of diagnostic indices, at most ten.
  uint32_t evidence_count;
  /// Diagnostic indices into the retained internal snapshot, never pointers.
  uint32_t evidence[10];
  /// Exact owned ASCII semantic rule identifier.
  char rule_id[129];
  /// Reserved bytes must remain zero.
  uint8_t reserved[3];
};
/// All fields are owned copies; action applies only to the immediately adapted host call.
struct RaspLocalGateResultV1 {
  /// Exact primitive ABI version; callers set 1.
  uint32_t abi_version;
  /// Exact sizeof this versioned caller-owned structure.
  uint32_t struct_size;
  /// API status at top level; actual native collection status in a detail.
  uint32_t status;
  /// DENY=0, REPORT=1, ALLOW=2; non-OK status never permits work.
  uint32_t action;
  /// Advisory candidate; REPORT never becomes an enforced ALLOW.
  uint32_t candidate_action;
  /// Versioned reason: gate vocabulary at top level, native vocabulary in details.
  uint32_t reason;
  /// Absent report-only, explicit report-only/gate, invalid or unsupported.
  uint32_t config_state;
  /// Full uint32 deployment version; 1..4294967295, or zero when absent.
  uint32_t policy_version;
  /// Separately pinned native typed-report schema version.
  uint32_t report_schema_version;
  /// Separately pinned native reason vocabulary version.
  uint32_t report_reason_version;
  /// Separately pinned owned cycle metadata version.
  uint32_t native_metadata_version;
  /// Gate reason vocabulary version, independent of native row reasons.
  uint32_t gate_reason_version;
  /// Retained structural coverage, independent of collection status.
  uint32_t coverage;
  /// Number of selected successfully typed predicates; never row count.
  uint32_t evaluated;
  /// Number of owned selected details, at most eight.
  uint32_t detail_count;
  /// One when the owning cycle has a valid ordinal.
  uint32_t sequence_present;
  /// One when ordered private clock samples support age/duration.
  uint32_t timing_present;
  /// Always zero: unverified client evidence, never server authority.
  uint32_t evidence_trust;
  /// Process-local unsigned cycle ordinal; not a clock or replay permit.
  uint64_t sequence;
  /// Conservative cycle-start age in nanoseconds when timing is present.
  uint64_t evidence_age_ns;
  /// Private suspend-inclusive completed cycle duration in nanoseconds.
  uint64_t cycle_duration_ns;
  /// Owned human policy identifier; never an authenticated identity.
  char policy_id[65];
  /// Canonical policy equality hash, not authenticity.
  char policy_sha256[65];
  /// Normalized config hash excluding install identity.
  char effective_config_sha256[65];
  /// Exact supported observation catalogue digest.
  char catalogue_id[65];
  /// Actual target platform, NUL-terminated.
  char platform[8];
  /// NUL-terminated ASCII operation name; at most 32 bytes.
  char operation[33];
  /// Owned process session UUID from the same snapshot.
  char session_id[37];
  /// Owned execution UUID from the same snapshot.
  char run_id[37];
  /// Reserved bytes must remain zero.
  uint8_t reserved[1];
  /// Owned copied selected rows; no native lifetime escapes.
  struct RaspLocalGateDetailV1 details[8];
};
/// Fixed-width owned effective check name; identical C and C++ representation.
struct RaspLocalCheckNameV1 {
  /// NUL-terminated group name; at most 96 bytes.
  char value[97];
};
/// Configuration only; support is not attestation or proof of host adaptation.
struct RaspLocalPolicyInfoV1 {
  /// Exact primitive ABI version; callers set 1.
  uint32_t abi_version;
  /// Exact sizeof this versioned caller-owned structure.
  uint32_t struct_size;
  /// API status at top level; actual native collection status in a detail.
  uint32_t status;
  /// Absent report-only, explicit report-only/gate, invalid or unsupported.
  uint32_t config_state;
  /// Full uint32 deployment version; 1..4294967295, or zero when absent.
  uint32_t policy_version;
  /// Supported embedded policy schema version.
  uint32_t policy_schema_version;
  /// Supported policy engine semantic version.
  uint32_t engine_version;
  /// Gate reason vocabulary version, independent of native row reasons.
  uint32_t gate_reason_version;
  /// Separately pinned native typed-report schema version.
  uint32_t report_schema_version;
  /// Separately pinned native reason vocabulary version.
  uint32_t report_reason_version;
  /// Separately pinned owned cycle metadata version.
  uint32_t native_metadata_version;
  /// Actual effective check count, at most 64.
  uint32_t check_count;
  /// One for known selection; zero distinguishes unknown from empty.
  uint32_t checks_known;
  /// Owned human policy identifier; never an authenticated identity.
  char policy_id[65];
  /// Canonical policy equality hash, not authenticity.
  char policy_sha256[65];
  /// Normalized config hash excluding install identity.
  char effective_config_sha256[65];
  /// Exact supported observation catalogue digest.
  char catalogue_id[65];
  /// Actual target platform, NUL-terminated.
  char platform[8];
  /// Owned NUL-terminated effective group names.
  struct RaspLocalCheckNameV1 checks[64];
  /// Reserved bytes must remain zero.
  uint8_t reserved[4];
};
/// Copy effective immutable config; no waits, storage, network or host callbacks.
/// @param out Caller-owned writable aligned output; no runtime allocation escapes.
/// @param out_size Must exactly match sizeof(struct RaspLocalPolicyInfoV1).
/// @return Call status; never an operation permit. Runtime must remain loaded.
__attribute__((visibility("default"))) int32_t rasp_local_policy_info_v1(struct RaspLocalPolicyInfoV1* out,
                                                                         uint32_t out_size);
/// Evaluate the actual owned typed snapshot immediately before an adapted operation.
/// @param request Borrowed fixed-size versioned operation/hash request; no report input.
/// @param request_size Exact request size; unknown ABI/sizes fail closed.
/// @param out Caller-owned result, independent of all later native cycles.
/// @param out_size Exact output size. Null/short buffers are not written out of bounds.
/// @return Call status. Require OK and known action; non-OK always means do not proceed.
__attribute__((visibility("default"))) int32_t rasp_local_policy_gate_v1(const struct RaspLocalGateRequestV1* request,
                                                                         uint32_t request_size,
                                                                         struct RaspLocalGateResultV1* out,
                                                                         uint32_t out_size);

#ifdef __cplusplus
}
#endif
