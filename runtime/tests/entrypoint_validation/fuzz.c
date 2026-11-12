/// Synthetic bounded libFuzzer driver of the actual C classifier, never platform evidence.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "rasp/entrypoint_validation.h"

/// Assert finite deterministic classification and no input/table mutation.
int LLVMFuzzerTestOneInput(const uint8_t* input, size_t size) {
  if (size > 1025) return 0;
  struct RaspEntryRuleV1 rules[16];
  memset(rules, 0, sizeof(rules));
  const uint32_t count = size > 0 ? (uint32_t)(input[0] % 16) + 1 : 1;
  for (uint32_t index = 0; index < count; ++index) {
    rules[index].version = 1;
    rules[index].struct_size = sizeof(rules[index]);
    rules[index].route_id = index + 1;
    rules[index].delivery = 1;
    rules[index].method = 1;
    rules[index].dispatch_class = 1;
    memcpy(rules[index].scheme, "https", 5);
    memcpy(rules[index].authority, "links.example.invalid", 21);
    memcpy(rules[index].path, "/open/help", 10);
    if (index != 0) rules[index].path[9] = (char)('a' + index - 1);
    memcpy(rules[index].operation, "append_demo_receipt", 18);
    memset(rules[index].expected_policy_sha256, 'a', 64);
  }
  struct RaspEntryCheckV1 first = {0}, second = {0};
  const int32_t status =
      rasp_entry_classify_v1(rules, count, sizeof(*rules), 1, 1, input, (uint32_t)size, &first, sizeof(first));
  const int32_t again =
      rasp_entry_classify_v1(rules, count, sizeof(*rules), 1, 1, input, (uint32_t)size, &second, sizeof(second));
  if (status != again || memcmp(&first, &second, sizeof(first)) != 0 || (status != 0 && first.route_id != 0) ||
      first.caller_state != 0)
    __builtin_trap();
  if (status == 0 && (first.route_id < 1 || first.route_id > count || size < 30 ||
                      memcmp(input, "https://links.example.invalid/", 29) != 0))
    __builtin_trap();
  return 0;
}
