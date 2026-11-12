/// Primitive public consumer compiled as C, ObjC, C++ and ObjC++ against installed runtime artifacts.
#include <stdint.h>

#include "c_host.h"
#include "rasp/entrypoint_validation.h"

/// Link the actual host classifier/effect boundary and native gate, without executing a device.
int main(void) {
  struct RaspEntryRuleV1 rule = {
      .version = 1,
      .struct_size = sizeof(rule),
      .route_id = 1,
      .delivery = 1,
      .method = 1,
      .dispatch_class = 1,
      .caller_profile = 0,
      .reserved = 0,
      .scheme = "https",
      .authority = "links.example.invalid",
      .path = "/open/help",
      .operation = "append_demo_receipt",
      .expected_policy_sha256 = "5685df69e0340b2a8472c2929cd9be01db0444191abb8c5fdf366a51b0262c81",
      .reserved_tail = {0, 0},
  };
  const uint8_t url[] = "https://links.example.invalid/open/help";
  uint32_t receipts = 0;
  return entry_demo_open(&rule, url, sizeof(url) - 1, &receipts) == 1 ? 0 : 1;
}
