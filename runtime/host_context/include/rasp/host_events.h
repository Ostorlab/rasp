/// Optional host-compiled local context; no runtime export, telemetry or server authority.
#pragma once
#include <stdint.h>

#include "local_policy_host.h"

#ifdef __cplusplus
extern "C" {
#endif

/// Context call status is independent of native gate action; only OK admits an effect.
#ifdef __cplusplus
enum class RaspHostStatusV1 : uint32_t {
#else
enum RaspHostStatusV1 {
#endif
  kRaspHostOk = 0,
  kRaspHostNoChange = 1,
  kRaspHostInvalidArgument = 2,
  kRaspHostUnsupportedVersion = 3,
  kRaspHostWrongThread = 4,
  kRaspHostOldGeneration = 5,
  kRaspHostOutOfOrder = 6,
  kRaspHostInvalidTransition = 7,
  kRaspHostExpired = 8,
  kRaspHostClockUnavailable = 9,
  kRaspHostNotReady = 10,
  kRaspHostExhausted = 11,
  kRaspHostNativeUnavailable = 12,
};
/// Closed transitions; each requires a canonical finite event, never content.
#ifdef __cplusplus
enum class RaspHostKindV1 : uint32_t {
#else
enum RaspHostKindV1 {
#endif
  kRaspHostStart = 1,
  kRaspHostBegin = 2,
  kRaspHostInput = 3,
  kRaspHostLifecycle = 4,
  kRaspHostEnd = 5,
  kRaspHostCancel = 6,
  kRaspHostRetry = 7,
  kRaspHostStop = 8,
};
/// Declared input/action purpose, not inferred from values or control names.
#ifdef __cplusplus
enum class RaspHostPurposeV1 : uint32_t {
#else
enum RaspHostPurposeV1 {
#endif
  kRaspHostPurposeUnknown = 0,
  kRaspHostCredential = 1,
  kRaspHostOtp = 2,
  kRaspHostPayment = 3,
  kRaspHostBeneficiary = 4,
  kRaspHostSessionChange = 5,
  kRaspHostOtherSensitive = 6,
};
/// Configuration only, never IME/OS trust or proof that content is protected.
#ifdef __cplusplus
enum class RaspHostSecureV1 : uint32_t {
#else
enum RaspHostSecureV1 {
#endif
  kRaspHostSecureUnknown = 0,
  kRaspHostConfigured = 1,
  kRaspHostNotConfigured = 2,
  kRaspHostUnsupported = 3,
  kRaspHostNotApplicable = 4,
};
/// Selected Activity/scene lifecycle, supplied explicitly by its host.
#ifdef __cplusplus
enum class RaspHostLifecycleV1 : uint32_t {
#else
enum RaspHostLifecycleV1 {
#endif
  kRaspHostLifecycleUnknown = 0,
  kRaspHostForeground = 1,
  kRaspHostInactive = 2,
  kRaspHostBackground = 3,
  kRaspHostDestroyed = 4,
};
/// Local state never represents a permit or authoritative server outcome.
#ifdef __cplusplus
enum class RaspHostStateV1 : uint32_t {
#else
enum RaspHostStateV1 {
#endif
  kRaspHostUninitialized = 0,
  kRaspHostReady = 1,
  kRaspHostActive = 2,
  kRaspHostFinished = 3,
  kRaspHostFailed = 4,
  kRaspHostCanceled = 5,
  kRaspHostStopped = 6,
  kRaspHostStateExpired = 7,
  kRaspHostFault = 8,
  kRaspHostAttempted = 9,
};
/// Context reason vocabulary1, distinct from native gate/report reasons.
#ifdef __cplusplus
enum class RaspHostReasonV1 : uint32_t {
#else
enum RaspHostReasonV1 {
#endif
  kRaspHostNone = 0,
  kRaspHostNoSession = 1,
  kRaspHostNoAction = 2,
  kRaspHostLifecycleUnavailable = 3,
  kRaspHostPurposeUnavailable = 4,
  kRaspHostSecureUnavailable = 5,
  kRaspHostSessionExpired = 6,
  kRaspHostActionExpired = 7,
  kRaspHostEventStale = 8,
  kRaspHostClockFault = 9,
  kRaspHostGenerationMismatch = 10,
  kRaspHostSequenceMismatch = 11,
  kRaspHostTransitionInvalid = 12,
  kRaspHostAttemptConsumed = 13,
  kRaspHostNativeCallFailed = 14,
  kRaspHostCounterExhausted = 15,
  kRaspHostStoppedReason = 16,
};
/// Natural native layout:80 bytes; alignment4 on Android x86,8 on other supported ABIs.
struct RaspHostEventV1 {
  /// Exact version1 and sizeof this structure.
  uint32_t version, struct_size;
  /// Closed kind, purpose, secure-entry configuration and lifecycle enums.
  uint32_t kind, purpose, secure_entry, lifecycle;
  /// Attempt1..3 for actions; completion0 except END FINISHED1/FAILED2.
  uint32_t attempt, completion;
  /// Nonzero positive signed64-range local generation and ordered event number.
  uint64_t generation, event_sequence;
  /// Opaque local random refs; zero when unused, never business identifiers/content.
  uint8_t session_ref[16], action_ref[16];
};
/// Owned120-byte readout. Status/action are separate; trust0 always means unverified host.
struct RaspHostContextViewV1 {
  /// Exact version1, size120, call status and context reason1.
  uint32_t version, struct_size, status, reason;
  /// Local state and finite declared facts.
  uint32_t state, purpose, secure_entry, lifecycle, attempt;
  /// Availability flags and unverified trust0; missing numbers must not mean fresh.
  uint32_t sequence_present, timing_present, trust;
  /// Owner-local identities and applicable suspend-inclusive ages in nanoseconds.
  uint64_t generation, event_sequence, session_age_ns, action_age_ns, last_event_age_ns;
  /// Owned random refs, redacted on errors and terminal readouts.
  uint8_t session_ref[16], action_ref[16];
};
/// Immutable116-byte compiled binding. Never learn the expected hash from runtime info.
struct RaspHostBindingV1 {
  /// Version1, size116, secure-input requirement0/1 and reserved0.
  uint32_t version, struct_size, require_secure_input, reserved;
  /// Exact existing HD02 operation grammar; NUL and unused tail must be zero.
  char operation[33];
  /// Exactly64 lowercase hex bytes plus NUL; equality pin, not authentication.
  char expected_policy_sha256[65];
  /// Must remain zero.
  uint8_t reserved_tail[2];
};
/// Host-owned finite source state, not an inter-binary ABI. Never copy a live owner.
struct RaspHostContextV1 {
  /// Immutable validated binding.
  struct RaspHostBindingV1 binding;
  /// Current private facts; use API readouts rather than inspecting or mutating this member.
  struct RaspHostContextViewV1 view;
  /// One accepted event or redacted terminal tombstone, never a history.
  struct RaspHostEventV1 last_event;
  /// Private platform ticks; no public event may supply these.
  int64_t session_start, action_start, event_tick, last_tick;
  /// One-shot initialization marker, clock availability and last-event presence.
  uint32_t initialized, has_clock, has_last;
};
/// Host platform boundary; returns1 and nonnegative suspend-inclusive nanoseconds or0.
/// @param out Valid writable tick, never retained. @return Clock availability.
__attribute__((visibility("hidden"))) int32_t rasp_host_clock_v1(int64_t* out);
/// Host platform boundary, not an SDK callback. @return1 only on the owner main thread.
__attribute__((visibility("hidden"))) int32_t rasp_host_is_owner_thread_v1(void);
/// Initialize zeroed host storage once; inputs/outputs must not alias.
/// @param owner Caller-owned <=512-byte state. @param binding Compiled expectation.
/// @param binding_size Exact116. @return Context status; never a permit.
__attribute__((visibility("hidden"))) int32_t rasp_host_context_init_v1(struct RaspHostContextV1* owner,
                                                                        const struct RaspHostBindingV1* binding,
                                                                        uint32_t binding_size);
/// Apply one finite event on main; old/foreign events never mutate a newer flow.
/// @param owner Initialized owner. @param event Borrowed canonical event. @param event_size Exact80.
/// @param out Owned view. @param out_size Exact120. @return Context status.
__attribute__((visibility("hidden"))) int32_t rasp_host_context_apply_v1(struct RaspHostContextV1* owner,
                                                                         const struct RaspHostEventV1* event,
                                                                         uint32_t event_size,
                                                                         struct RaspHostContextViewV1* out,
                                                                         uint32_t out_size);
/// Consume only admitted ACTIVE attempts, then synchronously invoke the real HD02 gate.
/// @param owner Initialized main-thread owner. @param generation Exact current generation.
/// @param sequence Exact last accepted sequence. @param attempt Exact current attempt.
/// @param out Owned view. @param out_size Exact120. @param gate_out Owned actual native result or unavailable sentinel.
/// @param gate_size Exact native result size. @return Context status; require native OK and known action too.
__attribute__((visibility("hidden"))) int32_t rasp_host_context_gate_v1(
    struct RaspHostContextV1* owner, uint64_t generation, uint64_t sequence, uint32_t attempt,
    struct RaspHostContextViewV1* out, uint32_t out_size, struct RaspLocalGateResultV1* gate_out, uint32_t gate_size);
/// Logically erase SDK facts on main; remove host callbacks before freeing storage.
/// @param owner Initialized caller-owned state. @return Status; disposed owners cannot restart.
__attribute__((visibility("hidden"))) int32_t rasp_host_context_dispose_v1(struct RaspHostContextV1* owner);

#ifdef __cplusplus
}
#endif
