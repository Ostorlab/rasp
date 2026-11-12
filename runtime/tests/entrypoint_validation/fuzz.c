/// Synthetic bounded libFuzzer driver of the actual C classifier, never platform evidence.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "rasp/entrypoint_validation.h"

/// Mandatory external libFuzzer callback; its symbol and signature belong to the harness.
extern int LLVMFuzzerTestOneInput(const uint8_t* input, size_t size);

/// Assert finite deterministic classification and no input/table mutation.
int LLVMFuzzerTestOneInput(const uint8_t* input, size_t size) {
  if (size > 1025) {
    return 0;
  }
  struct RaspEntryRuleV1 rules[16] = {0};
  const uint32_t count = size > 0 ? (uint32_t)(input[0] % 16) + 1 : 1;
  for (uint32_t index = 0; index < count; ++index) {
    rules[index] = (struct RaspEntryRuleV1){
        .version = 1,
        .struct_size = sizeof(rules[index]),
        .route_id = index + 1,
        .delivery = 1,
        .method = 1,
        .dispatch_class = 1,
        .scheme = "https",
        .authority = "links.example.invalid",
        .path = "/open/help",
        .operation = "append_demo_receipt",
        .expected_policy_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    };
    if (index != 0) {
      rules[index].path[9] = (char)('a' + index - 1);
    }
  }
  struct RaspEntryCheckV1 first = {0};
  struct RaspEntryCheckV1 second = {0};
  const int32_t status =
      rasp_entry_classify_v1(rules, count, sizeof(*rules), 1, 1, input, (uint32_t)size, &first, sizeof(first));
  const int32_t again =
      rasp_entry_classify_v1(rules, count, sizeof(*rules), 1, 1, input, (uint32_t)size, &second, sizeof(second));
  if (status != again || memcmp(&first, &second, sizeof(first)) != 0 || (status != 0 && first.route_id != 0) ||
      first.caller_state != 0) {
    __builtin_trap();
  }
  if (status == 0 && (first.route_id < 1 || first.route_id > count || size < 30 ||
                      memcmp(input, "https://links.example.invalid/", 29) != 0)) {
    __builtin_trap();
  }
  return 0;
}
