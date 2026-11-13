/// Test-owned interface API state; no operation enumerates the host network.
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <gtest/gtest.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <string_view>
#include <sys/socket.h>
#include <vector>

namespace rasp::test {
/// One allocated synthetic API record with nullable name/address controls.
struct InterfaceNode {
  ifaddrs entry{};
  std::array<char, IFNAMSIZ> name{};
  sockaddr address{};
  bool null_name = false;
  bool null_address = false;
};
/// Plain external API data and invocation counts.
struct InterfaceInventory {
  std::vector<InterfaceNode> nodes;
  int result = 0;
  std::size_t reads = 0;
  std::size_t frees = 0;
};
/// Named options prevent confusing integer flags with an address family.
struct InterfaceOptions {
  unsigned int flags = IFF_UP;
  int family = AF_INET;
};
/// Returns test-thread state; unexpected calls fail instead of reaching the ambient API.
inline InterfaceInventory*& active_inventory() {
  static thread_local InterfaceInventory* inventory = nullptr;
  return inventory;
}
/// Owns the synthetic API allocation for one test.
class InterfaceList : public testing::Test {
 protected:
  /// Installs this fixture's data before collecting.
  void SetUp() override { active_inventory() = &inventory_; }
  /// Clears call-lifetime API state after the test.
  void TearDown() override {
    EXPECT_EQ(active_inventory(), &inventory_);
    active_inventory() = nullptr;
  }
  /// Exposes external fixture data, never collector internals.
  [[nodiscard]] InterfaceInventory& inventory() { return inventory_; }
  /// Adds one OS-shaped record without retaining the caller's string.
  void add_interface(std::string_view name, InterfaceOptions options = {}) {
    InterfaceNode node;
    std::ranges::copy(name.substr(0, node.name.size()), node.name.begin());
    node.entry.ifa_flags = options.flags;
    node.address.sa_family = static_cast<decltype(sockaddr::sa_family)>(options.family);
    inventory_.nodes.push_back(node);
  }

 private:
  InterfaceInventory inventory_;
};
}  // namespace rasp::test

/// Test C boundary, linked only to targets whose production collector calls are explicitly renamed.
extern "C" int rasp_test_getifaddrs(ifaddrs** list);
/// Releases/poisons the test-owned list instead of calling libc.
extern "C" void rasp_test_freeifaddrs(ifaddrs* list);
