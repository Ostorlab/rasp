/// Tests for the iOS network-interception checks: the tunnel probe that reports the tunnel interfaces that are up and
/// carry an IPv4 address.

#include "checks/mitm.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "rasp/observation.h"

namespace rasp::ios::checks {
namespace {

/// The address family of an IPv6 address, `AF_INET6` on Apple systems.
constexpr std::uint32_t kFamilyIPv6 = 30;
/// The address family of a link-layer address, `AF_LINK` on Apple systems.
constexpr std::uint32_t kFamilyLink = 18;
/// The bit of an interface's flags that marks it as a point-to-point link, `IFF_POINTOPOINT`.
constexpr std::uint32_t kInterfacePointToPoint = 0x10;
/// The flags of a tunnel interface that is up.
constexpr std::uint32_t kTunnelUp = kInterfaceUp | kInterfacePointToPoint;

/// The interface-name prefixes the tunnel probe matches.
constexpr auto kTunnelPrefixes = std::to_array<std::string_view>({"utun", "ipsec", "ppp", "tun", "tap"});

/// The entries of a stock device: its loopback, Wi-Fi and cellular interfaces with their addresses, and the `utun`
/// interfaces of the system's own services, which carry only an IPv6 link-local address.
[[nodiscard]] std::vector<InterfaceAddress> stock_entries() {
  return {
      {.name = "lo0", .flags = kInterfaceUp, .family = kFamilyIPv4},
      {.name = "lo0", .flags = kInterfaceUp, .family = kFamilyIPv6},
      {.name = "en0", .flags = kInterfaceUp, .family = kFamilyLink},
      {.name = "en0", .flags = kInterfaceUp, .family = kFamilyIPv4},
      {.name = "pdp_ip0", .flags = kTunnelUp, .family = kFamilyIPv4},
      {.name = "utun0", .flags = kTunnelUp, .family = kFamilyLink},
      {.name = "utun0", .flags = kTunnelUp, .family = kFamilyIPv6},
      {.name = "utun1", .flags = kTunnelUp, .family = kFamilyIPv6},
      {.name = "utun2", .flags = kTunnelUp, .family = kFamilyIPv6},
  };
}

/// Returns the stock entries with `added` appended.
///
/// @param added The entries to append.
/// @return The entries of stock_entries, then `added`.
[[nodiscard]] std::vector<InterfaceAddress> stock_entries_with(const std::vector<InterfaceAddress>& added) {
  std::vector<InterfaceAddress> entries = stock_entries();
  entries.insert(entries.end(), added.begin(), added.end());
  return entries;
}

/// Returns the mitm.tunnels observation that reports `names`.
///
/// @param names The interface names reported.
/// @return The observation, with status kOk.
[[nodiscard]] Observation tunnels(std::vector<std::string> names) {
  return {.signal = "mitm.tunnels", .source = "getifaddrs", .status = Status::kOk, .value = std::move(names)};
}

/// Whether `name` is one of the tunnel prefixes followed by a run of digits and nothing else.
///
/// @param name The interface name to look at.
/// @return Whether it has the form of a tunnel's name.
[[nodiscard]] bool has_tunnel_form(std::string_view name) {
  return std::ranges::any_of(kTunnelPrefixes, [name](std::string_view prefix) {
    return name.starts_with(prefix) && name.size() > prefix.size() &&
           std::ranges::all_of(name.substr(prefix.size()), [](char digit) { return digit >= '0' && digit <= '9'; });
  });
}

TEST(Mitm, observeTunnels_whenTheDeviceIsStock_reportsAnEmptyList) {
  EXPECT_EQ(observe_tunnels(stock_entries()), tunnels({}));
}

TEST(Mitm, observeTunnels_whenAUtunCarriesAnIPv4Address_reportsItsName) {
  EXPECT_EQ(observe_tunnels(stock_entries_with({{.name = "utun3", .flags = kTunnelUp, .family = kFamilyIPv4}})),
            tunnels({"utun3"}));
}

TEST(Mitm, observeTunnels_whenEveryTunnelKindCarriesAnIPv4Address_reportsTheirNamesSorted) {
  const std::vector<InterfaceAddress> added = {
      {.name = "utun4", .flags = kTunnelUp, .family = kFamilyIPv4},
      {.name = "ipsec0", .flags = kTunnelUp, .family = kFamilyIPv4},
      {.name = "ppp0", .flags = kTunnelUp, .family = kFamilyIPv4},
      {.name = "tun0", .flags = kTunnelUp, .family = kFamilyIPv4},
      {.name = "tap1", .flags = kTunnelUp, .family = kFamilyIPv4},
  };

  EXPECT_EQ(observe_tunnels(stock_entries_with(added)), tunnels({"ipsec0", "ppp0", "tap1", "tun0", "utun4"}));
}

TEST(Mitm, observeTunnels_whenATunnelCarriesOnlyIPv6Addresses_doesNotReportIt) {
  const std::vector<InterfaceAddress> added = {
      {.name = "utun5", .flags = kTunnelUp, .family = kFamilyLink},
      {.name = "utun5", .flags = kTunnelUp, .family = kFamilyIPv6},
      {.name = "utun5", .flags = kTunnelUp, .family = kFamilyIPv6},
  };

  EXPECT_EQ(observe_tunnels(stock_entries_with(added)), tunnels({}));
}

TEST(Mitm, observeTunnels_whenATunnelIsDown_doesNotReportIt) {
  EXPECT_EQ(
      observe_tunnels(stock_entries_with({{.name = "utun3", .flags = kInterfacePointToPoint, .family = kFamilyIPv4}})),
      tunnels({}));
}

TEST(Mitm, observeTunnels_whenAnEntryHasNoAddress_doesNotReportIt) {
  EXPECT_EQ(observe_tunnels(stock_entries_with({{.name = "utun3", .flags = kTunnelUp, .family = 0}})), tunnels({}));
}

TEST(Mitm, observeTunnels_whenANameOnlyStartsWithATunnelPrefix_doesNotReportIt) {
  const std::vector<InterfaceAddress> added = {
      {.name = "tunl0", .flags = kTunnelUp, .family = kFamilyIPv4},
      {.name = "utun", .flags = kTunnelUp, .family = kFamilyIPv4},
      {.name = "ipsec0a", .flags = kTunnelUp, .family = kFamilyIPv4},
      {.name = "xutun0", .flags = kTunnelUp, .family = kFamilyIPv4},
  };

  EXPECT_EQ(observe_tunnels(stock_entries_with(added)), tunnels({}));
}

TEST(Mitm, observeTunnels_whenATunnelHasSeveralIPv4Addresses_reportsItOnce) {
  const std::vector<InterfaceAddress> added = {
      {.name = "utun3", .flags = kTunnelUp, .family = kFamilyIPv4},
      {.name = "utun3", .flags = kTunnelUp, .family = kFamilyIPv6},
      {.name = "utun3", .flags = kTunnelUp, .family = kFamilyIPv4},
  };

  EXPECT_EQ(observe_tunnels(stock_entries_with(added)), tunnels({"utun3"}));
}

TEST(Mitm, observeTunnels_whenMoreThan100TunnelsMatch_reportsThe100Smallest) {
  constexpr std::size_t kTunnelCount = 120;
  std::vector<InterfaceAddress> entries;
  entries.reserve(kTunnelCount);
  for (std::size_t index = kTunnelCount; index > 0; --index) {
    entries.push_back({.name = "utun" + std::to_string(100 + index), .flags = kTunnelUp, .family = kFamilyIPv4});
  }

  std::vector<std::string> smallest;
  smallest.reserve(100);
  for (std::size_t index = 1; index <= 100; ++index) {
    smallest.push_back("utun" + std::to_string(100 + index));
  }
  EXPECT_EQ(observe_tunnels(entries), tunnels(smallest));
}

TEST(Mitm, observeInterfaces_whenGetifaddrsSucceeds_reportsOnlyTunnelNamesSortedOnce) {
  const Observation observation = observe_interfaces();
  ASSERT_EQ(observation.signal, "mitm.tunnels");
  ASSERT_EQ(observation.source, "getifaddrs");
  ASSERT_EQ(observation.status, Status::kOk);
  ASSERT_TRUE(std::holds_alternative<std::vector<std::string>>(observation.value));

  const auto& names = std::get<std::vector<std::string>>(observation.value);
  EXPECT_LE(names.size(), std::size_t{100});
  EXPECT_TRUE(std::ranges::all_of(names, has_tunnel_form));
  EXPECT_TRUE(std::ranges::is_sorted(names));
  EXPECT_EQ(std::ranges::adjacent_find(names), names.end());
}

TEST(Mitm, mitm_whenOffAPhysicalDevice_reportsUnsupported) {
  EXPECT_EQ(mitm(), (std::vector<Observation>{
                        {.signal = "mitm.tunnels", .source = "getifaddrs", .status = Status::kUnsupported, .value = {}},
                    }));
}

}  // namespace
}  // namespace rasp::ios::checks
