/// Primitive public consumer compiled as C, ObjC, C++ and ObjC++ against installed runtime artifacts.
#include <string.h>

#include "c_host.h"

/// Link the actual host classifier/effect boundary and native gate, without executing a device.
int main(void) {
  struct RaspEntryRuleV1 rule;
  memset(&rule, 0, sizeof(rule));
  rule.version = 1;
  rule.struct_size = sizeof(rule);
  rule.route_id = 1;
  rule.delivery = 1;
  rule.method = 1;
  rule.dispatch_class = 1;
  memcpy(rule.scheme, "https", 5);
  memcpy(rule.authority, "links.example.invalid", 21);
  memcpy(rule.path, "/open/help", 10);
  memcpy(rule.operation, "append_demo_receipt", 18);
  memcpy(rule.expected_policy_sha256, "5685df69e0340b2a8472c2929cd9be01db0444191abb8c5fdf366a51b0262c81", 64);
  const uint8_t url[] = "https://links.example.invalid/open/help";
  uint32_t receipts = 0;
  return entry_demo_open(&rule, url, sizeof(url) - 1, &receipts) == 1 ? 0 : 1;
}
