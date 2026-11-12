/// ABI1 layouts checked against the approved independent design specimen.
#include <stddef.h>

#include "rasp/scoped_key.h"
#ifdef __cplusplus
#define CHECK static_assert
#define ALIGN alignof
#else
#define CHECK _Static_assert
#define ALIGN _Alignof
#endif
CHECK(sizeof(RaspScopedKeyTokenV1) == 16, "RaspScopedKeyTokenV1 size");
CHECK(ALIGN(RaspScopedKeyTokenV1) == 8, "RaspScopedKeyTokenV1 alignment");
CHECK(sizeof(RaspScopedKeyNamespaceSpecV1) == 176, "RaspScopedKeyNamespaceSpecV1 size");
CHECK(ALIGN(RaspScopedKeyNamespaceSpecV1) == 8, "RaspScopedKeyNamespaceSpecV1 alignment");
CHECK(sizeof(RaspScopedKeyClientSpecV1) == 856, "RaspScopedKeyClientSpecV1 size");
CHECK(ALIGN(RaspScopedKeyClientSpecV1) == 8, "RaspScopedKeyClientSpecV1 alignment");
CHECK(sizeof(RaspScopedKeyNamespaceEntryV1) == 24, "RaspScopedKeyNamespaceEntryV1 size");
CHECK(ALIGN(RaspScopedKeyNamespaceEntryV1) == 8, "RaspScopedKeyNamespaceEntryV1 alignment");
CHECK(sizeof(RaspScopedKeyClientOpenedV1) == 160, "RaspScopedKeyClientOpenedV1 size");
CHECK(ALIGN(RaspScopedKeyClientOpenedV1) == 8, "RaspScopedKeyClientOpenedV1 alignment");
CHECK(sizeof(RaspScopedKeySignInputV1) == 4336, "RaspScopedKeySignInputV1 size");
CHECK(ALIGN(RaspScopedKeySignInputV1) == 8, "RaspScopedKeySignInputV1 alignment");
CHECK(sizeof(RaspScopedKeyOperationInputV1) == 4336, "RaspScopedKeyOperationInputV1 size");
CHECK(ALIGN(RaspScopedKeyOperationInputV1) == 8, "RaspScopedKeyOperationInputV1 alignment");
CHECK(sizeof(RaspScopedKeySubmitV1) == 4384, "RaspScopedKeySubmitV1 size");
CHECK(ALIGN(RaspScopedKeySubmitV1) == 8, "RaspScopedKeySubmitV1 alignment");
CHECK(sizeof(RaspScopedKeyAdmissionV1) == 64, "RaspScopedKeyAdmissionV1 size");
CHECK(ALIGN(RaspScopedKeyAdmissionV1) == 8, "RaspScopedKeyAdmissionV1 alignment");
CHECK(sizeof(RaspScopedKeyControlV1) == 64, "RaspScopedKeyControlV1 size");
CHECK(ALIGN(RaspScopedKeyControlV1) == 8, "RaspScopedKeyControlV1 alignment");
CHECK(sizeof(RaspScopedKeyControlResultV1) == 64, "RaspScopedKeyControlResultV1 size");
CHECK(ALIGN(RaspScopedKeyControlResultV1) == 8, "RaspScopedKeyControlResultV1 alignment");
CHECK(sizeof(RaspScopedKeyTakeRequestV1) == 48, "RaspScopedKeyTakeRequestV1 size");
CHECK(ALIGN(RaspScopedKeyTakeRequestV1) == 8, "RaspScopedKeyTakeRequestV1 alignment");
CHECK(sizeof(RaspScopedKeyPlatformErrorV1) == 24, "RaspScopedKeyPlatformErrorV1 size");
CHECK(ALIGN(RaspScopedKeyPlatformErrorV1) == 8, "RaspScopedKeyPlatformErrorV1 alignment");
CHECK(sizeof(RaspScopedKeyProvenanceV1) == 64, "RaspScopedKeyProvenanceV1 size");
CHECK(ALIGN(RaspScopedKeyProvenanceV1) == 8, "RaspScopedKeyProvenanceV1 alignment");
CHECK(sizeof(RaspScopedKeyInfoV1) == 240, "RaspScopedKeyInfoV1 size");
CHECK(ALIGN(RaspScopedKeyInfoV1) == 8, "RaspScopedKeyInfoV1 alignment");
CHECK(sizeof(RaspScopedKeyValueKeyV1) == 256, "RaspScopedKeyValueKeyV1 size");
CHECK(ALIGN(RaspScopedKeyValueKeyV1) == 8, "RaspScopedKeyValueKeyV1 alignment");
CHECK(sizeof(RaspScopedKeyValueSignatureV1) == 128, "RaspScopedKeyValueSignatureV1 size");
CHECK(ALIGN(RaspScopedKeyValueSignatureV1) == 8, "RaspScopedKeyValueSignatureV1 alignment");
CHECK(sizeof(RaspScopedKeyValueDeletionV1) == 16, "RaspScopedKeyValueDeletionV1 size");
CHECK(ALIGN(RaspScopedKeyValueDeletionV1) == 8, "RaspScopedKeyValueDeletionV1 alignment");
CHECK(sizeof(RaspScopedKeyValueV1) == 256, "RaspScopedKeyValueV1 size");
CHECK(ALIGN(RaspScopedKeyValueV1) == 8, "RaspScopedKeyValueV1 alignment");
CHECK(sizeof(RaspScopedKeyCompletionV1) == 2560, "RaspScopedKeyCompletionV1 size");
CHECK(ALIGN(RaspScopedKeyCompletionV1) == 8, "RaspScopedKeyCompletionV1 alignment");
CHECK(sizeof(RaspScopedKeyTakeResultV1) == 2600, "RaspScopedKeyTakeResultV1 size");
CHECK(ALIGN(RaspScopedKeyTakeResultV1) == 8, "RaspScopedKeyTakeResultV1 alignment");
CHECK(offsetof(RaspScopedKeyClientSpecV1, namespaces) == 152, "RaspScopedKeyClientSpecV1.namespaces");
CHECK(offsetof(RaspScopedKeySubmitV1, input) == 48, "RaspScopedKeySubmitV1.input");
CHECK(offsetof(RaspScopedKeySignInputV1, transaction) == 240, "RaspScopedKeySignInputV1.transaction");
CHECK(offsetof(RaspScopedKeyInfoV1, public_key_x963) == 104, "RaspScopedKeyInfoV1.public_key_x963");
CHECK(offsetof(RaspScopedKeyInfoV1, provenance) == 176, "RaspScopedKeyInfoV1.provenance");
CHECK(offsetof(RaspScopedKeyCompletionV1, request) == 32, "RaspScopedKeyCompletionV1.request");
CHECK(offsetof(RaspScopedKeyCompletionV1, platform_error) == 48, "RaspScopedKeyCompletionV1.platform_error");
CHECK(offsetof(RaspScopedKeyCompletionV1, gate) == 72, "RaspScopedKeyCompletionV1.gate");
CHECK(offsetof(RaspScopedKeyCompletionV1, value_tag) == 2176, "RaspScopedKeyCompletionV1.value_tag");
CHECK(offsetof(RaspScopedKeyCompletionV1, value) == 2184, "RaspScopedKeyCompletionV1.value");
CHECK(offsetof(RaspScopedKeyCompletionV1, reserved) == 2440, "RaspScopedKeyCompletionV1.reserved");
CHECK(offsetof(RaspScopedKeyTakeResultV1, completion) == 40, "RaspScopedKeyTakeResultV1.completion");
CHECK(sizeof(struct RaspLocalGateResultV1) == 2104, "frozen gate projection");
CHECK(RASP_SK_CALL_OK == 0 && RASP_SK_OP_OK == 1 && RASP_SK_OP_UNAVAILABLE == 0, "separate call and operation status");

#undef CHECK
#undef ALIGN
