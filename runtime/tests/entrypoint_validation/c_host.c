/// Actual C host effect boundary; no replacement gate or reusable permit.
#include "c_host.h"

#include <stddef.h>
#include <stdint.h>

#include "local_policy_host.h"
#include "rasp/entrypoint_validation.h"

int32_t entry_demo_open(const struct RaspEntryRuleV1* rule, const uint8_t* url, uint32_t length, uint32_t* receipts) {
  struct RaspEntryCheckV1 check = {0};
  if (receipts == NULL || *receipts == UINT32_MAX ||
      rasp_entry_classify_v1(rule, 1, sizeof(*rule), 1, 1, url, length, &check, sizeof(check)) != 0 ||
      check.route_id != 1 || (rule->dispatch_class != 1 && rule->dispatch_class != 3) || rule->caller_profile != 0) {
    return 0;
  }
  struct RaspLocalGateRequestV1 request = {0};
  struct RaspLocalGateResultV1 result = {0};
  request.abi_version = 1;
  request.struct_size = sizeof(request);
  for (size_t index = 0; index < sizeof(request.operation); ++index) {
    request.operation[index] = rule->operation[index];
  }
  for (size_t index = 0; index < sizeof(request.expected_policy_sha256); ++index) {
    request.expected_policy_sha256[index] = rule->expected_policy_sha256[index];
  }
  if (rasp_local_policy_gate_v1(&request, sizeof(request), &result, sizeof(result)) != 0 || result.abi_version != 1 ||
      result.struct_size != sizeof(result) || result.status != 0 || result.action != 2) {
    return 0;
  }
  ++*receipts;
  return 1;
}
