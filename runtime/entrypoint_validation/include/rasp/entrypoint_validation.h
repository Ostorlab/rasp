/// Optional host-compiled entry-point classification; MATCH is never authorization.
#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Source-contract status, independent of native policy status/action.
#ifdef __cplusplus
enum class RaspEntryStatusV1 : uint32_t {
#else
enum RaspEntryStatusV1 {
#endif
  kRaspEntryMatch = 0,
  kRaspEntryRejected = 1,
  kRaspEntryUnavailable = 2,
  kRaspEntryUnsupported = 3,
  kRaspEntryNeedsHostFlow = 4,
};
/// Local finite reason vocabulary1; no input contents escape.
#ifdef __cplusplus
enum class RaspEntryReasonV1 : uint32_t {
#else
enum RaspEntryReasonV1 {
#endif
  kRaspEntryNone = 0,
  kRaspEntryBadArgument = 1,
  kRaspEntryBadBinding = 2,
  kRaspEntryTooLong = 3,
  kRaspEntryBadEncoding = 4,
  kRaspEntryBadAuthority = 5,
  kRaspEntryBadPath = 6,
  kRaspEntryQueryOrFragment = 7,
  kRaspEntryNoRoute = 8,
  kRaspEntryMethodMismatch = 9,
  kRaspEntryIntentShape = 10,
  kRaspEntryCallerUnknown = 11,
  kRaspEntryCallerMismatch = 12,
  kRaspEntryPermissionDenied = 13,
  kRaspEntryPlatformFailure = 14,
  kRaspEntryWrongThread = 15,
  kRaspEntryLifecycle = 16,
  kRaspEntryCanceled = 17,
  kRaspEntryStale = 18,
  kRaspEntryReplaySensitive = 19,
  kRaspEntryMultipleDeliveries = 20,
  kRaspEntryReentrant = 21,
};
/// Delivery provenance is a route constraint, not authenticated origin.
#ifdef __cplusplus
enum class RaspEntryDeliveryV1 : uint32_t {
#else
enum RaspEntryDeliveryV1 {
#endif
  kRaspEntryAndroidLink = 1,
  kRaspEntryAndroidBinder = 2,
  kRaspEntryAndroidProvider = 3,
  kRaspEntryIosCustom = 4,
  kRaspEntryIosWeb = 5,
};
/// Exact local dispatch methods; links do not carry an HTTP method.
#ifdef __cplusplus
enum class RaspEntryMethodV1 : uint32_t {
#else
enum RaspEntryMethodV1 {
#endif
  kRaspEntryOpen = 1,
  kRaspEntryQueryStatus = 2,
  kRaspEntryDemoCall = 3,
};
/// Host-compiled effect classification; sensitive mutations never dispatch directly.
#ifdef __cplusplus
enum class RaspEntryDispatchV1 : uint32_t {
#else
enum RaspEntryDispatchV1 {
#endif
  kRaspEntryPublicNavigation = 1,
  kRaspEntryRestricted = 2,
  kRaspEntryConfirmation = 3,
  kRaspEntrySensitiveReject = 4,
};
/// Fixed676-byte host-source rule; all text tails and reserved bytes must be zero.
struct RaspEntryRuleV1 {  /// Exact version1 and sizeof this structure.
  uint32_t version, struct_size;
  /// Route1..16, delivery1..5, method1..3, dispatch1..4, profile0..4, reserved0.
  uint32_t route_id, delivery, method, dispatch_class, caller_profile, reserved;
  /// Exact canonical literal tuple; all zero for Binder methods.
  char scheme[33], authority[254], path[257];
  /// Existing gate grammar and64-lowercase-hex equality expectation, never authenticity.
  char operation[33], expected_policy_sha256[65];
  /// Canonical reserved zero bytes.
  uint8_t reserved_tail[2];
};
/// Owned32-byte local diagnostics; no URL/identity or authorization token.
struct RaspEntryCheckV1 {
  /// Version1,size32,status,reason; exact source vocabulary above.
  uint32_t version, struct_size, status, reason;
  /// Route0 on failure; delivery/method are finite inputs, caller_state always0 here.
  uint32_t route_id, delivery, method, caller_state;
};
/// Match a bounded canonical tuple without performing caller authorization or policy evaluation.
/// @param rules Immutable aligned table,1..16 rules; no retained borrowed storage.
/// @param rule_count Number of rules. @param rule_size Exact676.
/// @param delivery Exact supported delivery. @param method Delivery-specific method.
/// @param url Borrowed bytes, or null only for Binder. @param url_size At most1024, zero only for Binder.
/// @param out Distinct aligned caller-owned diagnostics. @param out_size Exact32.
/// @return Classification status; never an operation permit. Invalid output framing is not written.
__attribute__((visibility("hidden"))) int32_t rasp_entry_classify_v1(const struct RaspEntryRuleV1* rules,
                                                                     uint32_t rule_count, uint32_t rule_size,
                                                                     uint32_t delivery, uint32_t method,
                                                                     const uint8_t* url, uint32_t url_size,
                                                                     struct RaspEntryCheckV1* out, uint32_t out_size);

#ifdef __cplusplus
}
#endif
