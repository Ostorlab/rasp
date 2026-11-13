/// Synthetic C API replacements linked only into the two controlled collector executables.
#include "support/interfaces.h"

#include <cstddef>
#include <gtest/gtest.h>
#include <ifaddrs.h>

extern "C" int rasp_test_getifaddrs(ifaddrs** list) {
  auto* const inventory = rasp::test::active_inventory();
  *list = nullptr;
  if (inventory == nullptr) {
    ADD_FAILURE() << "Unexpected interface API call outside a synthetic fixture";
    return -1;
  }
  ++inventory->reads;
  if (inventory->result != 0) {
    return inventory->result;
  }
  for (std::size_t index = 0; index < inventory->nodes.size(); ++index) {
    auto& node = inventory->nodes[index];
    node.entry.ifa_next = index + 1 == inventory->nodes.size() ? nullptr : &inventory->nodes[index + 1].entry;
    node.entry.ifa_name = node.null_name ? nullptr : node.name.data();
    node.entry.ifa_addr = node.null_address ? nullptr : &node.address;
  }
  if (!inventory->nodes.empty()) {
    *list = &inventory->nodes.front().entry;
  }
  return 0;
}

extern "C" void rasp_test_freeifaddrs(ifaddrs* list) {
  auto* const inventory = rasp::test::active_inventory();
  ASSERT_NE(inventory, nullptr);
  ASSERT_FALSE(inventory->nodes.empty());
  EXPECT_EQ(list, &inventory->nodes.front().entry);
  EXPECT_EQ(inventory->frees, 0U);
  ++inventory->frees;
  for (auto& node : inventory->nodes) {
    node.name.fill('?');
    node.entry = {};
  }
}
