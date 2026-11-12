/// Opt-in companion ABI1; owned primitive records, never reusable authorization.
#ifndef RASP_SCOPED_KEY_PROPOSAL_V1_H
#define RASP_SCOPED_KEY_PROPOSAL_V1_H
#include <stdint.h>

#include "rasp/local_policy_host.h"
#define RASP_SK_ALIGN8 __attribute__((aligned(8)))
#ifdef __cplusplus
extern "C" {
#endif

/// Fields use uint32_t, never implementation-defined C enum storage.
/// ABI1 public C enum: frozen interoperable names and values require this declaration form.
/// NOLINTBEGIN(cppcoreguidelines-use-enum-class,readability-identifier-naming)
enum RaspScopedKeyCallStatusV1 {
  RASP_SK_CALL_OK = 0,
  RASP_SK_CALL_INVALID_ARGUMENT = 1,
  RASP_SK_CALL_UNSUPPORTED_ABI = 2,
  RASP_SK_CALL_NOT_READY = 3,
  RASP_SK_CALL_BUSY = 4,
  RASP_SK_CALL_WRONG_THREAD = 5,
  RASP_SK_CALL_RESOURCE_EXHAUSTED = 6,
  RASP_SK_CALL_NOT_FOUND = 7,
  RASP_SK_CALL_INTERNAL_ERROR = 8,
  RASP_SK_CALL_CLOSING = 9,
};
/// NOLINTEND(cppcoreguidelines-use-enum-class,readability-identifier-naming)
/// ABI1 public C enum: frozen interoperable names and values require this declaration form.
/// NOLINTBEGIN(cppcoreguidelines-use-enum-class,readability-identifier-naming)
enum RaspScopedKeyOperationStatusV1 {
  RASP_SK_OP_UNAVAILABLE = 0,
  RASP_SK_OP_OK = 1,
  RASP_SK_OP_INVALID_ARGUMENT = 2,
  RASP_SK_OP_UNSUPPORTED_ABI = 3,
  RASP_SK_OP_NOT_OPTED_IN = 4,
  RASP_SK_OP_NOT_READY = 5,
  RASP_SK_OP_UNSUPPORTED = 6,
  RASP_SK_OP_BUSY = 7,
  RASP_SK_OP_RESOURCE_EXHAUSTED = 8,
  RASP_SK_OP_WRONG_THREAD = 9,
  RASP_SK_OP_WRONG_NAMESPACE = 10,
  RASP_SK_OP_WRONG_PURPOSE = 11,
  RASP_SK_OP_STALE_HANDLE = 12,
  RASP_SK_OP_NOT_FOUND = 13,
  RASP_SK_OP_EXPIRED = 14,
  RASP_SK_OP_CLOCK_UNAVAILABLE = 15,
  RASP_SK_OP_LOCKED = 16,
  RASP_SK_OP_AUTH_REQUIRED = 17,
  RASP_SK_OP_AUTH_FAILED = 18,
  RASP_SK_OP_AUTH_UNAVAILABLE = 19,
  RASP_SK_OP_AUTH_LOCKOUT = 20,
  RASP_SK_OP_CANCELLED = 21,
  RASP_SK_OP_INVALIDATED = 22,
  RASP_SK_OP_GATE_REJECTED = 23,
  RASP_SK_OP_STORAGE_UNAVAILABLE = 24,
  RASP_SK_OP_STORAGE_CORRUPT = 25,
  RASP_SK_OP_PLATFORM_ERROR = 26,
  RASP_SK_OP_CLEANUP_PENDING = 27,
  RASP_SK_OP_INTERNAL_ERROR = 28,
};
/// NOLINTEND(cppcoreguidelines-use-enum-class,readability-identifier-naming)
/// ABI1 public C enum: frozen interoperable names and values require this declaration form.
/// NOLINTBEGIN(cppcoreguidelines-use-enum-class,readability-identifier-naming)
enum RaspScopedKeyAlgorithmV1 {
  RASP_SK_ALGORITHM_NONE = 0,
  RASP_SK_P256_SHA256_MESSAGE_DER = 1,
};
/// NOLINTEND(cppcoreguidelines-use-enum-class,readability-identifier-naming)
/// ABI1 public C enum: frozen interoperable names and values require this declaration form.
/// NOLINTBEGIN(cppcoreguidelines-use-enum-class,readability-identifier-naming)
enum RaspScopedKeyBackendRequirementV1 {
  RASP_SK_BACKEND_REQUIREMENT_NONE = 0,
  RASP_SK_PLATFORM_STORE = 1,
  RASP_SK_HARDWARE_REQUIRED = 2,
  RASP_SK_STRONGBOX_REQUIRED = 3,
};
/// NOLINTEND(cppcoreguidelines-use-enum-class,readability-identifier-naming)
/// ABI1 public C enum: frozen interoperable names and values require this declaration form.
/// NOLINTBEGIN(cppcoreguidelines-use-enum-class,readability-identifier-naming)
enum RaspScopedKeyAuthRequirementV1 {
  RASP_SK_AUTH_REQUIREMENT_UNKNOWN = 0,
  RASP_SK_AUTH_NONE = 1,
  RASP_SK_CURRENT_BIOMETRY_EACH_REQUEST = 2,
};
/// NOLINTEND(cppcoreguidelines-use-enum-class,readability-identifier-naming)
/// ABI1 public C enum: frozen interoperable names and values require this declaration form.
/// NOLINTBEGIN(cppcoreguidelines-use-enum-class,readability-identifier-naming)
enum RaspScopedKeyLockRequirementV1 {
  RASP_SK_LOCK_REQUIREMENT_UNKNOWN = 0,
  RASP_SK_PLATFORM_DEFAULT = 1,
  RASP_SK_UNLOCKED_REQUIRED = 2,
};
/// NOLINTEND(cppcoreguidelines-use-enum-class,readability-identifier-naming)
/// ABI1 public C enum: frozen interoperable names and values require this declaration form.
/// NOLINTBEGIN(cppcoreguidelines-use-enum-class,readability-identifier-naming)
enum RaspScopedKeyGateModeV1 {
  RASP_SK_GATE_MODE_NONE = 0,
  RASP_SK_REQUIRE_ALLOW = 1,
  RASP_SK_EXPLICIT_ADVISORY = 2,
};
/// NOLINTEND(cppcoreguidelines-use-enum-class,readability-identifier-naming)
/// ABI1 public C enum: frozen interoperable names and values require this declaration form.
/// NOLINTBEGIN(cppcoreguidelines-use-enum-class,readability-identifier-naming)
enum RaspScopedKeyInteractionV1 {
  RASP_SK_INTERACTION_NONE = 0,
  RASP_SK_FORBID = 1,
  RASP_SK_ALLOW_SYSTEM_BIOMETRY = 2,
};
/// NOLINTEND(cppcoreguidelines-use-enum-class,readability-identifier-naming)
/// ABI1 public C enum: frozen interoperable names and values require this declaration form.
/// NOLINTBEGIN(cppcoreguidelines-use-enum-class,readability-identifier-naming)
enum RaspScopedKeyOperationV1 {
  RASP_SK_OPERATION_NONE = 0,
  RASP_SK_CREATE = 1,
  RASP_SK_REOPEN = 2,
  RASP_SK_DESCRIBE = 3,
  RASP_SK_SIGN = 4,
  RASP_SK_DELETE = 5,
  RASP_SK_RESET_NAMESPACE = 6,
};
/// NOLINTEND(cppcoreguidelines-use-enum-class,readability-identifier-naming)
/// ABI1 public C enum: frozen interoperable names and values require this declaration form.
/// NOLINTBEGIN(cppcoreguidelines-use-enum-class,readability-identifier-naming)
enum RaspScopedKeyEffectV1 {
  RASP_SK_EFFECT_UNKNOWN = 0,
  RASP_SK_EFFECT_NONE = 1,
  RASP_SK_KEY_CREATED = 2,
  RASP_SK_KEY_ABSENT = 3,
  RASP_SK_NAMESPACE_EMPTY = 4,
  RASP_SK_EFFECT_PARTIAL = 5,
};
/// NOLINTEND(cppcoreguidelines-use-enum-class,readability-identifier-naming)
/// ABI1 public C enum: frozen interoperable names and values require this declaration form.
/// NOLINTBEGIN(cppcoreguidelines-use-enum-class,readability-identifier-naming)
enum RaspScopedKeyDurabilityV1 {
  RASP_SK_DURABILITY_NOT_APPLICABLE = 0,
  RASP_SK_IN_MEMORY_ONLY = 1,
  RASP_SK_TOMBSTONES_DURABLE = 2,
  RASP_SK_DELETION_CONFIRMED = 3,
  RASP_SK_DURABILITY_UNKNOWN = 4,
  RASP_SK_RESERVATION_DURABLE = 5,
  RASP_SK_LIVE_RECORD_DURABLE = 6,
};
/// NOLINTEND(cppcoreguidelines-use-enum-class,readability-identifier-naming)
/// ABI1 public C enum: frozen interoperable names and values require this declaration form.
/// NOLINTBEGIN(cppcoreguidelines-use-enum-class,readability-identifier-naming)
enum RaspScopedKeyAdmissionStateV1 {
  RASP_SK_ADMISSION_NONE = 0,
  RASP_SK_ACCEPTED = 1,
  RASP_SK_REJECTED = 2,
};
/// NOLINTEND(cppcoreguidelines-use-enum-class,readability-identifier-naming)
/// ABI1 public C enum: frozen interoperable names and values require this declaration form.
/// NOLINTBEGIN(cppcoreguidelines-use-enum-class,readability-identifier-naming)
enum RaspScopedKeyControlActionV1 {
  RASP_SK_CONTROL_NONE = 0,
  RASP_SK_CANCEL = 1,
  RASP_SK_RELEASE_KEY = 2,
  RASP_SK_CLOSE_CLIENT = 3,
};
/// NOLINTEND(cppcoreguidelines-use-enum-class,readability-identifier-naming)
/// ABI1 public C enum: frozen interoperable names and values require this declaration form.
/// NOLINTBEGIN(cppcoreguidelines-use-enum-class,readability-identifier-naming)
enum RaspScopedKeyControlOutcomeV1 {
  RASP_SK_CONTROL_UNAVAILABLE = 0,
  RASP_SK_APPLIED = 1,
  RASP_SK_ALREADY_CLOSED = 2,
  RASP_SK_TOO_LATE = 3,
  RASP_SK_CONTROL_NOT_FOUND = 4,
  RASP_SK_CONTROL_REJECTED = 5,
  RASP_SK_DRAINING = 6,
  RASP_SK_CLOSED = 7,
};
/// NOLINTEND(cppcoreguidelines-use-enum-class,readability-identifier-naming)
/// ABI1 public C enum: frozen interoperable names and values require this declaration form.
/// NOLINTBEGIN(cppcoreguidelines-use-enum-class,readability-identifier-naming)
enum RaspScopedKeyTakeStateV1 {
  RASP_SK_TAKE_NONE = 0,
  RASP_SK_PENDING = 1,
  RASP_SK_COMPLETED = 2,
  RASP_SK_UNKNOWN_REQUEST = 3,
};
/// NOLINTEND(cppcoreguidelines-use-enum-class,readability-identifier-naming)
/// ABI1 public C enum: frozen interoperable names and values require this declaration form.
/// NOLINTBEGIN(cppcoreguidelines-use-enum-class,readability-identifier-naming)
enum RaspScopedKeyValueTagV1 {
  RASP_SK_VALUE_NONE = 0,
  RASP_SK_VALUE_KEY = 1,
  RASP_SK_VALUE_INFO = 2,
  RASP_SK_VALUE_SIGNATURE = 3,
  RASP_SK_VALUE_DELETION = 4,
};
/// NOLINTEND(cppcoreguidelines-use-enum-class,readability-identifier-naming)
/// ABI1 public C enum: frozen interoperable names and values require this declaration form.
/// NOLINTBEGIN(cppcoreguidelines-use-enum-class,readability-identifier-naming)
enum RaspScopedKeyBackendV1 {
  RASP_SK_BACKEND_UNKNOWN = 0,
  RASP_SK_ANDROID_KEYSTORE = 1,
  RASP_SK_APPLE_KEYCHAIN = 2,
  RASP_SK_APPLE_SECURE_ENCLAVE = 3,
};
/// NOLINTEND(cppcoreguidelines-use-enum-class,readability-identifier-naming)
/// ABI1 public C enum: frozen interoperable names and values require this declaration form.
/// NOLINTBEGIN(cppcoreguidelines-use-enum-class,readability-identifier-naming)
enum RaspScopedKeySecurityLevelV1 {
  RASP_SK_SECURITY_UNKNOWN = 0,
  RASP_SK_UNKNOWN_SECURE = 1,
  RASP_SK_SOFTWARE = 2,
  RASP_SK_TEE = 3,
  RASP_SK_STRONGBOX = 4,
  RASP_SK_SECURE_ENCLAVE = 5,
};
/// NOLINTEND(cppcoreguidelines-use-enum-class,readability-identifier-naming)
/// ABI1 public C enum: frozen interoperable names and values require this declaration form.
/// NOLINTBEGIN(cppcoreguidelines-use-enum-class,readability-identifier-naming)
enum RaspScopedKeyProvenanceSourceV1 {
  RASP_SK_SOURCE_UNKNOWN = 0,
  RASP_SK_ANDROID_KEYINFO = 1,
  RASP_SK_APPLE_ATTRIBUTES_AND_CREATION = 2,
};
/// NOLINTEND(cppcoreguidelines-use-enum-class,readability-identifier-naming)
/// ABI1 public C enum: frozen interoperable names and values require this declaration form.
/// NOLINTBEGIN(cppcoreguidelines-use-enum-class,readability-identifier-naming)
enum RaspScopedKeyOriginV1 {
  RASP_SK_ORIGIN_UNKNOWN = 0,
  RASP_SK_GENERATED_IN_PLATFORM_STORE = 1,
};
/// NOLINTEND(cppcoreguidelines-use-enum-class,readability-identifier-naming)
/// ABI1 public C enum: frozen interoperable names and values require this declaration form.
/// NOLINTBEGIN(cppcoreguidelines-use-enum-class,readability-identifier-naming)
enum RaspScopedKeyExportV1 {
  RASP_SK_EXPORT_UNKNOWN = 0,
  RASP_SK_API_FORBIDS_EXPORT = 1,
  RASP_SK_PLATFORM_NONEXPORTABLE = 2,
};
/// NOLINTEND(cppcoreguidelines-use-enum-class,readability-identifier-naming)
/// ABI1 public C enum: frozen interoperable names and values require this declaration form.
/// NOLINTBEGIN(cppcoreguidelines-use-enum-class,readability-identifier-naming)
enum RaspScopedKeyAccessibilityV1 {
  RASP_SK_ACCESSIBILITY_UNKNOWN = 0,
  RASP_SK_ANDROID_PLATFORM_PROFILE = 1,
  RASP_SK_APPLE_PASSCODE_DEVICE_ONLY = 2,
};
/// NOLINTEND(cppcoreguidelines-use-enum-class,readability-identifier-naming)
/// ABI1 public C enum: frozen interoperable names and values require this declaration form.
/// NOLINTBEGIN(cppcoreguidelines-use-enum-class,readability-identifier-naming)
enum RaspScopedKeyBackupV1 {
  RASP_SK_BACKUP_UNKNOWN = 0,
  RASP_SK_NO_PORTABLE_KEY_EXPORT = 1,
  RASP_SK_APPLE_NO_SYNC_NO_BACKUP = 2,
};
/// NOLINTEND(cppcoreguidelines-use-enum-class,readability-identifier-naming)
/// ABI1 public C enum: frozen interoperable names and values require this declaration form.
/// NOLINTBEGIN(cppcoreguidelines-use-enum-class,readability-identifier-naming)
enum RaspScopedKeyAttestationV1 {
  RASP_SK_ATTESTATION_NOT_REQUESTED = 0,
};
/// NOLINTEND(cppcoreguidelines-use-enum-class,readability-identifier-naming)
/// ABI1 public C enum: frozen interoperable names and values require this declaration form.
/// NOLINTBEGIN(cppcoreguidelines-use-enum-class,readability-identifier-naming)
enum RaspScopedKeyPlatformV1 {
  RASP_SK_PLATFORM_NONE = 0,
  RASP_SK_PLATFORM_ANDROID = 1,
  RASP_SK_PLATFORM_APPLE = 2,
};
/// NOLINTEND(cppcoreguidelines-use-enum-class,readability-identifier-naming)
/// ABI1 public C enum: frozen interoperable names and values require this declaration form.
/// NOLINTBEGIN(cppcoreguidelines-use-enum-class,readability-identifier-naming)
enum RaspScopedKeyErrorDomainV1 {
  RASP_SK_ERROR_DOMAIN_NONE = 0,
  RASP_SK_ANDROID_KEYSTORE_ERROR = 1,
  RASP_SK_ANDROID_JCA_ERROR = 2,
  RASP_SK_ANDROID_BIOMETRIC_ERROR = 3,
  RASP_SK_APPLE_OSSTATUS_ERROR = 4,
  RASP_SK_APPLE_LA_ERROR = 5,
  RASP_SK_POSIX_ERROR = 6,
};
/// NOLINTEND(cppcoreguidelines-use-enum-class,readability-identifier-naming)

/// Opaque process-scoped lease/identity; all-zero is invalid and never authorization.
typedef struct RASP_SK_ALIGN8 RaspScopedKeyTokenV1 {
  uint8_t bytes[16];
} RaspScopedKeyTokenV1;
/// Immutable explicit namespace/profile; lengths are bounded, tails/reserved bytes must be zero.
typedef struct RASP_SK_ALIGN8 RaspScopedKeyNamespaceSpecV1 {
  uint32_t selector, backend_requirement, auth_requirement, lock_requirement;
  uint32_t gate_mode, namespace_length, purpose_length, gate_operation_length;
  uint8_t namespace_name[32], purpose[32], gate_operation[32], expected_policy_sha256[32];
  uint8_t reserved[16];
} RaspScopedKeyNamespaceSpecV1;
/// Worker-open configuration; explicit opt-in and up to four sorted unique namespaces.
typedef struct RASP_SK_ALIGN8 RaspScopedKeyClientSpecV1 {
  uint32_t abi_version, struct_size, signing_scope_length, namespace_count;
  uint8_t reserved[16], signing_scope[120];
  RaspScopedKeyNamespaceSpecV1 namespaces[4];
} RaspScopedKeyClientSpecV1;
/// Selector-to-session-handle mapping; the namespace handle expires with the client.
typedef struct RASP_SK_ALIGN8 RaspScopedKeyNamespaceEntryV1 {
  uint32_t selector, reserved;
  RaspScopedKeyTokenV1 namespace_handle;
} RaspScopedKeyNamespaceEntryV1;
/// Open outcome; inspect CALL status before OP status, and OP_OK before using handles.
typedef struct RASP_SK_ALIGN8 RaspScopedKeyClientOpenedV1 {
  uint32_t abi_version, struct_size, operation_status, namespace_count;
  RaspScopedKeyTokenV1 client;
  RaspScopedKeyNamespaceEntryV1 namespaces[4];
  uint8_t reserved[32];
} RaspScopedKeyClientOpenedV1;
/// Copied signing input; exact purpose plus audience/id/challenge/transaction binding.
typedef struct RASP_SK_ALIGN8 RaspScopedKeySignInputV1 {
  RaspScopedKeyTokenV1 key;
  uint32_t expected_purpose_length, audience_length, transaction_length, interaction;
  uint8_t expected_purpose[32], audience[128], transaction_id[16], challenge[32], transaction[4096];
} RaspScopedKeySignInputV1;
/// Only the selected operation member may be nonzero; all unused union bytes are mandatory zero.
typedef union RASP_SK_ALIGN8 RaspScopedKeyOperationInputV1 {
  RaspScopedKeySignInputV1 sign;
  RaspScopedKeyTokenV1 key_id;
  RaspScopedKeyTokenV1 key_handle;
  uint8_t raw[4336];
} RaspScopedKeyOperationInputV1;
/// Submit header and copied payload; TTL is1..60000ms and the whole4384-byte record stays off native stack.
typedef struct RASP_SK_ALIGN8 RaspScopedKeySubmitV1 {
  uint32_t abi_version, struct_size, operation, request_ttl_ms;
  RaspScopedKeyTokenV1 client, namespace_handle;
  RaspScopedKeyOperationInputV1 input;
} RaspScopedKeySubmitV1;
/// Admission is separate from completion and durable deletion; ACCEPTED owns one bounded slot.
typedef struct RASP_SK_ALIGN8 RaspScopedKeyAdmissionV1 {
  uint32_t abi_version, struct_size, admission_state, operation_status;
  RaspScopedKeyTokenV1 request;
  uint32_t durability;
  uint8_t reserved[28];
} RaspScopedKeyAdmissionV1;
/// Nonblocking cancel/release/close input; CLOSE requires a zero target.
typedef struct RASP_SK_ALIGN8 RaspScopedKeyControlV1 {
  uint32_t abi_version, struct_size, action, reserved0;
  RaspScopedKeyTokenV1 client, target;
  uint8_t reserved[16];
} RaspScopedKeyControlV1;
/// Control outcome and truthful retained ownership counts; DRAINING retains exclusive ownership.
typedef struct RASP_SK_ALIGN8 RaspScopedKeyControlResultV1 {
  uint32_t abi_version, struct_size, outcome, operation_status;
  uint32_t durability, retained_jobs, retained_requests, retained_callbacks;
  RaspScopedKeyTokenV1 client;
  uint8_t reserved[16];
} RaspScopedKeyControlResultV1;
/// Single-take request; both reserved words must be zero.
typedef struct RASP_SK_ALIGN8 RaspScopedKeyTakeRequestV1 {
  uint32_t abi_version, struct_size, reserved[2];
  RaspScopedKeyTokenV1 client, request;
} RaspScopedKeyTakeRequestV1;
/// Optional numeric OS error only; no localized message or borrowed OS object crosses the ABI.
typedef struct RASP_SK_ALIGN8 RaspScopedKeyPlatformErrorV1 {
  uint32_t platform, domain, numeric_code_present, reserved;
  int64_t numeric_code;
} RaspScopedKeyPlatformErrorV1;
/// Per-key measured facts; absent/unknown fields never imply hardware, authentication or attestation.
typedef struct RASP_SK_ALIGN8 RaspScopedKeyProvenanceV1 {
  uint32_t backend, security_level, source, key_origin, private_export;
  uint32_t auth_observed_present, auth_observed, auth_hardware_enforced_present, auth_hardware_enforced;
  uint32_t lock_observed_present, lock_observed, accessibility, backup, attestation;
  uint8_t reserved[8];
} RaspScopedKeyProvenanceV1;
/// Public immutable binding and point; KeyId does not itself authorize key use.
typedef struct RASP_SK_ALIGN8 RaspScopedKeyInfoV1 {
  RaspScopedKeyTokenV1 key_id;
  uint32_t algorithm, namespace_selector, backend_requirement, auth_requirement, lock_requirement, purpose_length;
  uint8_t purpose[32], profile_sha256[32], public_key_x963[65], reserved[7];
  RaspScopedKeyProvenanceV1 provenance;
} RaspScopedKeyInfoV1;
/// A finite key-handle lease plus verified public metadata; no private material.
typedef struct RASP_SK_ALIGN8 RaspScopedKeyValueKeyV1 {
  RaspScopedKeyTokenV1 key_handle;
  RaspScopedKeyInfoV1 info;
} RaspScopedKeyValueKeyV1;
/// Strict DER ECDSA over the exact internally encoded message; hash is public equality evidence.
typedef struct RASP_SK_ALIGN8 RaspScopedKeyValueSignatureV1 {
  RaspScopedKeyTokenV1 key_id;
  uint32_t algorithm, der_length;
  uint8_t message_sha256[32], der[72];
} RaspScopedKeyValueSignatureV1;
/// Exact captured cleanup target counts; failure/cancellation retains these diagnostics.
typedef struct RASP_SK_ALIGN8 RaspScopedKeyValueDeletionV1 {
  uint32_t requested, confirmed_absent, remaining, reserved;
} RaspScopedKeyValueDeletionV1;
/// Tagged completion value; unselected bytes are zero and unknown tags fail.
typedef union RASP_SK_ALIGN8 RaspScopedKeyValueV1 {
  RaspScopedKeyValueKeyV1 key;
  RaspScopedKeyInfoV1 info;
  RaspScopedKeyValueSignatureV1 signature;
  RaspScopedKeyValueDeletionV1 deletion;
  uint8_t raw[256];
} RaspScopedKeyValueV1;
/// Owned completion with independent OP/effect/durability/gate diagnostics; zero OP is failure.
typedef struct RASP_SK_ALIGN8 RaspScopedKeyCompletionV1 {
  uint32_t abi_version, struct_size, operation, operation_status;
  uint32_t effect, durability, platform_error_present, gate_present;
  RaspScopedKeyTokenV1 request;
  RaspScopedKeyPlatformErrorV1 platform_error;
  struct RaspLocalGateResultV1 gate;
  uint32_t value_tag, reserved0;
  RaspScopedKeyValueV1 value;
  uint8_t reserved[120];
} RaspScopedKeyCompletionV1;
/// Single transfer plus retained counts; caller owns the transferred copy.
typedef struct RASP_SK_ALIGN8 RaspScopedKeyTakeResultV1 {
  uint32_t abi_version, struct_size, take_state, durability, retained_requests, retained_jobs;
  RaspScopedKeyTokenV1 request;
  RaspScopedKeyCompletionV1 completion;
} RaspScopedKeyTakeResultV1;

/// Open on a worker; returns CALL status. OP_OK alone admits a client; absent attachment is NOT_READY.
/// Pointers must be nonnull,8-byte aligned, disjoint and exact-sized; unknown ABI returns a CALL error.
__attribute__((visibility("default"))) int32_t rasp_scoped_key_client_open_v1(const RaspScopedKeyClientSpecV1* input,
                                                                              uint32_t input_size,
                                                                              RaspScopedKeyClientOpenedV1* output,
                                                                              uint32_t output_size);
/// Copy validated input and reserve bounded ownership; ACCEPTED does not imply effect/durability.
/// Pointers must be nonnull,8-byte aligned, disjoint and exact-sized; unknown ABI returns a CALL error.
__attribute__((visibility("default"))) int32_t rasp_scoped_key_submit_v1(const RaspScopedKeySubmitV1* input,
                                                                         uint32_t input_size,
                                                                         RaspScopedKeyAdmissionV1* output,
                                                                         uint32_t output_size);
/// Transfer a completion once; every successful SIGN delivery requires a fresh actual local gate.
/// Pointers must be nonnull,8-byte aligned, disjoint and exact-sized; unknown ABI returns a CALL error.
__attribute__((visibility("default"))) int32_t rasp_scoped_key_take_v1(const RaspScopedKeyTakeRequestV1* input,
                                                                       uint32_t input_size,
                                                                       RaspScopedKeyTakeResultV1* output,
                                                                       uint32_t output_size);
/// Apply nonblocking cancellation/release/close; DRAINING retains all physical/callback/storage ownership.
/// Pointers must be nonnull,8-byte aligned, disjoint and exact-sized; unknown ABI returns a CALL error.
__attribute__((visibility("default"))) int32_t rasp_scoped_key_control_v1(const RaspScopedKeyControlV1* input,
                                                                          uint32_t input_size,
                                                                          RaspScopedKeyControlResultV1* output,
                                                                          uint32_t output_size);
#ifdef __cplusplus
}
#endif
#undef RASP_SK_ALIGN8
#endif
