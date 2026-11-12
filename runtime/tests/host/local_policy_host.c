/// Real C/ObjC/C++/ObjC++ consumer of the installed primitive header and shipping library.
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#if defined(__APPLE__)
#include <RaspRuntime/local_policy_host.h>
#else
#include "rasp/local_policy_host.h"
#endif

#if defined(__cplusplus)
static_assert(sizeof(struct RaspLocalGateRequestV1) == 112);
static_assert(sizeof(struct RaspLocalGateResultV1) == 2104);
static_assert(sizeof(struct RaspLocalPolicyInfoV1) == 6532);
static_assert(offsetof(struct RaspLocalGateResultV1, sequence) == 72);
static_assert(offsetof(struct RaspLocalGateResultV1, details) == 472);
#else
_Static_assert(sizeof(struct RaspLocalGateRequestV1) == 112, "request layout");
_Static_assert(sizeof(struct RaspLocalGateResultV1) == 2104, "result layout");
_Static_assert(sizeof(struct RaspLocalPolicyInfoV1) == 6532, "info layout");
_Static_assert(offsetof(struct RaspLocalGateResultV1, sequence) == 72, "sequence alignment");
_Static_assert(offsetof(struct RaspLocalGateResultV1, details) == 472, "detail offset");
#endif

/// Caller-owned static primitive storage; no native allocation/destructor crosses ABI.
static struct RaspLocalPolicyInfoV1 policy_info;
static struct RaspLocalGateResultV1 decision;
/// Actual harmless adapted operation: return before modifying the book unless explicitly allowed.
int main(void) {
  struct RaspLocalGateRequestV1 request = {0};
  request.abi_version = 1;
  request.struct_size = sizeof(request);
  memcpy(request.operation, "append_demo_receipt", sizeof("append_demo_receipt"));
  /// Host expectation is built before packing; never copied from runtime policy_info.
  memcpy(request.expected_policy_sha256, "5685df69e0340b2a8472c2929cd9be01db0444191abb8c5fdf366a51b0262c81", 65);
  int receipts = 0;
  const int32_t status = rasp_local_policy_gate_v1(&request, sizeof(request), &decision, sizeof(decision));
  if (status == RASP_LOCAL_OK && decision.action == RASP_LOCAL_ALLOW) {
    ++receipts;
  }
  const int32_t info_status = rasp_local_policy_info_v1(&policy_info, sizeof(policy_info));
  return receipts == 0 && info_status == RASP_LOCAL_NOT_READY ? 0 : 1;
}
