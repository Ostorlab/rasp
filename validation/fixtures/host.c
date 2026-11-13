/// Harmless real production C ABI startup consumer; unavailable is never a security success.
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rasp/local_policy_host.h"

_Static_assert(sizeof(struct RaspLocalGateRequestV1) == 112, "request layout");
_Static_assert(sizeof(struct RaspLocalGateResultV1) == 2104, "decision layout");
_Static_assert(sizeof(struct RaspLocalPolicyInfoV1) == 6532, "info layout");
/// Run one fresh-process baseline, then gate immediately before a separate receipt append.
int main(int argc, char* argv[]) {
  if (argc != 2 || strlen(argv[1]) != 32 || strspn(argv[1], "0123456789abcdef") != 32) {
    return 2;
  }
  int baseline_receipts = 0;
  ++baseline_receipts;
  if (printf("{\"nonce\":\"%s\",\"phase\":\"baseline\",\"before\":0,\"after\":%d}\n", argv[1], baseline_receipts) < 0) {
    return 1;
  }
  struct RaspLocalPolicyInfoV1* const info = calloc(1, sizeof(struct RaspLocalPolicyInfoV1));
  if (info == NULL) {
    return 1;
  }
  const int32_t info_status = rasp_local_policy_info_v1(info, sizeof(*info));
  free(info);
  if (printf("{\"nonce\":\"%s\",\"phase\":\"setup\",\"info_status\":%d}\n", argv[1], info_status) < 0) {
    return 1;
  }
  struct RaspLocalGateRequestV1 request = {
      .abi_version = 1,
      .struct_size = sizeof(struct RaspLocalGateRequestV1),
      .operation = "append_demo_receipt",
      .expected_policy_sha256 = "0000000000000000000000000000000000000000000000000000000000000000",
      .reserved = {0},
  };
  struct RaspLocalGateResultV1 decision = {0};
  int receipts = 0;
  const int32_t status = rasp_local_policy_gate_v1(&request, sizeof(request), &decision, sizeof(decision));
  if (status == RASP_LOCAL_OK && decision.action == RASP_LOCAL_ALLOW) {
    ++receipts;
  }
  if (printf("{\"nonce\":\"%s\",\"phase\":\"execution\",\"api_status\":%d,\"action\":%u,"
             "\"info_status\":%d,\"before\":0,\"after\":%d}\n",
             argv[1], status, decision.action, info_status, receipts) < 0) {
    return 1;
  }
  return baseline_receipts == 1 && status == RASP_LOCAL_NOT_READY && decision.action == RASP_LOCAL_DENY &&
                 info_status == RASP_LOCAL_NOT_READY && receipts == 0
             ? 0
             : 1;
}
