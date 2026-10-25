/// Tests for the iOS network-interception checks: the tunnel probe that reports the tunnel interfaces that are up and
/// carry an IPv4 address, and the proxy probe that reports the proxies of the system's proxy settings.

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

/// Returns the mitm.proxies observation that reports `proxies`.
///
/// @param proxies The proxies reported.
/// @return The observation, with status kOk.
[[nodiscard]] Observation proxies(std::vector<std::string> proxies) {
  return {
      .signal = "mitm.proxies",
      .source = "CFNetworkCopySystemProxySettings",
      .status = Status::kOk,
      .value = std::move(proxies),
  };
}

/// Returns proxy settings with only a manual HTTP proxy, and proxy auto-config disabled.
///
/// @param enabled Whether the HTTP proxy is enabled.
/// @param host The HTTP proxy's host, or empty for none.
/// @param port The HTTP proxy's port, or 0 for none.
/// @return The settings.
[[nodiscard]] ProxySettings http_proxy(bool enabled, std::string host, std::uint16_t port) {
  return {
      .http_enabled = enabled,
      .http_host = std::move(host),
      .http_port = port,
      .auto_config_enabled = false,
      .auto_config_url = "",
  };
}

/// Returns proxy settings with only proxy auto-config, and the manual HTTP proxy disabled.
///
/// @param enabled Whether proxy auto-config is enabled.
/// @param url The auto-config file's URL, or empty for none.
/// @return The settings.
[[nodiscard]] ProxySettings auto_config(bool enabled, std::string url) {
  return {
      .http_enabled = false,
      .http_host = "",
      .http_port = 0,
      .auto_config_enabled = enabled,
      .auto_config_url = std::move(url),
  };
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

TEST(Mitm, observeProxies_whenNoProxyIsEnabled_reportsAnEmptyList) {
  EXPECT_EQ(observe_proxies(http_proxy(false, "", 0)), proxies({}));
}

TEST(Mitm, observeProxies_whenTheHttpProxyIsEnabled_reportsItsHostAndPort) {
  EXPECT_EQ(observe_proxies(http_proxy(true, "192.168.1.10", 8080)), proxies({"http 192.168.1.10:8080"}));
}

TEST(Mitm, observeProxies_whenTheHttpProxyHasNoPort_reportsItsHostAlone) {
  EXPECT_EQ(observe_proxies(http_proxy(true, "proxy.example", 0)), proxies({"http proxy.example"}));
}

TEST(Mitm, observeProxies_whenTheHttpProxyHostIsAnIPv6Address_reportsItBetweenBrackets) {
  EXPECT_EQ(observe_proxies(http_proxy(true, "fd00::2", 8080)), proxies({"http [fd00::2]:8080"}));
}

TEST(Mitm, observeProxies_whenTheHttpProxyIsDisabled_doesNotReportIt) {
  EXPECT_EQ(observe_proxies(http_proxy(false, "192.168.1.10", 8080)), proxies({}));
}

TEST(Mitm, observeProxies_whenTheHttpProxyHasNoHost_doesNotReportIt) {
  EXPECT_EQ(observe_proxies(http_proxy(true, "", 8080)), proxies({}));
}

TEST(Mitm, observeProxies_whenAutoConfigIsEnabled_reportsItsUrl) {
  EXPECT_EQ(observe_proxies(auto_config(true, "http://wpad.example/proxy.pac")),
            proxies({"pac http://wpad.example/proxy.pac"}));
}

TEST(Mitm, observeProxies_whenAutoConfigIsEnabledWithNoUrl_reportsPacAlone) {
  EXPECT_EQ(observe_proxies(auto_config(true, "")), proxies({"pac"}));
}

TEST(Mitm, observeProxies_whenAutoConfigIsDisabled_doesNotReportIt) {
  EXPECT_EQ(observe_proxies(auto_config(false, "http://wpad.example/proxy.pac")), proxies({}));
}

TEST(Mitm, observeProxies_whenBothAreEnabled_reportsTheHttpProxyFirst) {
  const ProxySettings settings = {
      .http_enabled = true,
      .http_host = "10.0.0.2",
      .http_port = 3128,
      .auto_config_enabled = true,
      .auto_config_url = "http://wpad.example/proxy.pac",
  };

  EXPECT_EQ(observe_proxies(settings), proxies({"http 10.0.0.2:3128", "pac http://wpad.example/proxy.pac"}));
}

#ifdef __APPLE__
TEST(Mitm, observeSystemProxies_whenTheSettingsCanBeRead_reportsAtMostTwoProxies) {
  const Observation observation = observe_system_proxies();
  ASSERT_EQ(observation.signal, "mitm.proxies");
  ASSERT_EQ(observation.source, "CFNetworkCopySystemProxySettings");
  ASSERT_EQ(observation.status, Status::kOk);
  ASSERT_TRUE(std::holds_alternative<std::vector<std::string>>(observation.value));
  EXPECT_LE(std::get<std::vector<std::string>>(observation.value).size(), std::size_t{2});
}
#else
TEST(Mitm, observeSystemProxies_whenTheSystemHasNoCFNetwork_reportsUnsupported) {
  EXPECT_EQ(observe_system_proxies(), (Observation{.signal = "mitm.proxies",
                                                   .source = "CFNetworkCopySystemProxySettings",
                                                   .status = Status::kUnsupported,
                                                   .value = {}}));
}
#endif

TEST(Mitm, mitm_whenOffAPhysicalDevice_reportsEveryCheckAsUnsupported) {
  EXPECT_EQ(mitm(), (std::vector<Observation>{
                        {.signal = "mitm.tunnels", .source = "getifaddrs", .status = Status::kUnsupported, .value = {}},
                        {.signal = "mitm.proxies",
                         .source = "CFNetworkCopySystemProxySettings",
                         .status = Status::kUnsupported,
                         .value = {}},
                    }));
}

}  // namespace
}  // namespace rasp::ios::checks
