/// Tests for the iOS network-interception checks: the tunnel probe that reports the tunnel interfaces that are up and
/// carry an IPv4 address, the proxy probe that reports the proxies of the system's proxy settings, and the
/// user-authority probe that iOS doesn't support.

#include "checks/mitm.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <ifaddrs.h>
#include <memory>
#include <net/if.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <utility>
#include <variant>
#include <vector>

#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/cycle.h"
#include "rasp/decision.h"
#include "rasp/observation.h"
#include "rasp/plugin.h"
#include "support/interfaces.h"

namespace rasp::ios::checks {
namespace {

/// The address family of a link-layer address, `AF_LINK` on Apple systems.
constexpr std::uint32_t kFamilyLink = 18;
/// The bit of an interface's flags that marks it as a point-to-point link, `IFF_POINTOPOINT`.
constexpr std::uint32_t kInterfacePointToPoint = 0x10;
/// The flags of a tunnel interface that is up.
constexpr std::uint32_t kTunnelUp = kInterfaceUp | kInterfacePointToPoint;

/// The interface-name prefixes the tunnel probe matches.
constexpr auto kExpectedTunnelPrefixes = std::to_array<std::string_view>({"utun", "ipsec", "ppp", "tun", "tap"});

/// Synthetic ordinary/service-shaped entries, with no claim that they describe a measured stock device.
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
  return std::ranges::any_of(kExpectedTunnelPrefixes, [name](std::string_view prefix) {
    return name.starts_with(prefix) && name.size() > prefix.size() &&
           std::ranges::all_of(name.substr(prefix.size()), [](char digit) { return digit >= '0' && digit <= '9'; });
  });
}

TEST(Mitm, observeTunnels_whenSystemInterfacesIncludeIPv6_reportsNeutralCandidates) {
  EXPECT_EQ(observe_tunnels(stock_entries()), tunnels({"utun0", "utun1", "utun2"}));
}

TEST(Mitm, observeTunnels_whenAUtunCarriesAnIPv4Address_reportsItsName) {
  EXPECT_EQ(observe_tunnels(stock_entries_with({{.name = "utun3", .flags = kTunnelUp, .family = kFamilyIPv4}})),
            tunnels({"utun0", "utun1", "utun2", "utun3"}));
}

TEST(Mitm, observeTunnels_whenEveryTunnelKindCarriesAnIPv4Address_reportsTheirNamesSorted) {
  const std::vector<InterfaceAddress> added = {
      {.name = "utun4", .flags = kTunnelUp, .family = kFamilyIPv4},
      {.name = "ipsec0", .flags = kTunnelUp, .family = kFamilyIPv4},
      {.name = "ppp0", .flags = kTunnelUp, .family = kFamilyIPv4},
      {.name = "tun0", .flags = kTunnelUp, .family = kFamilyIPv4},
      {.name = "tap1", .flags = kTunnelUp, .family = kFamilyIPv4},
  };

  EXPECT_EQ(observe_tunnels(stock_entries_with(added)),
            tunnels({"ipsec0", "ppp0", "tap1", "tun0", "utun0", "utun1", "utun2", "utun4"}));
}

TEST(Mitm, observeTunnels_whenATunnelCarriesOnlyIPv6Addresses_reportsItOnce) {
  const std::vector<InterfaceAddress> added = {
      {.name = "utun5", .flags = kTunnelUp, .family = kFamilyLink},
      {.name = "utun5", .flags = kTunnelUp, .family = kFamilyIPv6},
      {.name = "utun5", .flags = kTunnelUp, .family = kFamilyIPv6},
  };

  EXPECT_EQ(observe_tunnels(stock_entries_with(added)), tunnels({"utun0", "utun1", "utun2", "utun5"}));
}

TEST(Mitm, observeTunnels_whenATunnelIsDown_doesNotReportIt) {
  EXPECT_EQ(
      observe_tunnels(stock_entries_with({{.name = "utun3", .flags = kInterfacePointToPoint, .family = kFamilyIPv4}})),
      tunnels({"utun0", "utun1", "utun2"}));
}

TEST(Mitm, observeTunnels_whenAnEntryHasNoAddress_doesNotReportIt) {
  EXPECT_EQ(observe_tunnels(stock_entries_with({{.name = "utun3", .flags = kTunnelUp, .family = 0}})),
            tunnels({"utun0", "utun1", "utun2"}));
}

TEST(Mitm, observeTunnels_whenANameOnlyStartsWithATunnelPrefix_doesNotReportIt) {
  const std::vector<InterfaceAddress> added = {
      {.name = "tunl0", .flags = kTunnelUp, .family = kFamilyIPv4},
      {.name = "utun", .flags = kTunnelUp, .family = kFamilyIPv4},
      {.name = "ipsec0a", .flags = kTunnelUp, .family = kFamilyIPv4},
      {.name = "xutun0", .flags = kTunnelUp, .family = kFamilyIPv4},
  };

  EXPECT_EQ(observe_tunnels(stock_entries_with(added)), tunnels({"utun0", "utun1", "utun2"}));
}

TEST(Mitm, observeTunnels_whenATunnelHasSeveralIPv4Addresses_reportsItOnce) {
  const std::vector<InterfaceAddress> added = {
      {.name = "utun3", .flags = kTunnelUp, .family = kFamilyIPv4},
      {.name = "utun3", .flags = kTunnelUp, .family = kFamilyIPv6},
      {.name = "utun3", .flags = kTunnelUp, .family = kFamilyIPv4},
  };

  EXPECT_EQ(observe_tunnels(stock_entries_with(added)), tunnels({"utun0", "utun1", "utun2", "utun3"}));
}

TEST(Mitm, observeTunnels_whenMoreThan64TunnelsMatch_reportsErrorWithoutPartialValue) {
  std::vector<InterfaceAddress> entries;
  entries.reserve(65);
  for (int index = 0; index < 65; ++index) {
    entries.push_back({.name = "utun" + std::to_string(index), .flags = kTunnelUp, .family = kFamilyIPv4});
  }
  EXPECT_EQ(observe_tunnels(entries), failed("mitm.tunnels", "getifaddrs"));
}

using IosInterfaces = rasp::test::InterfaceList;

TEST_F(IosInterfaces, observeInterfaces_whenOwnedInventorySucceeds_reportsOnlyTunnelNamesSortedOnce) {
  add_interface("utun3", {.flags = IFF_UP, .family = AF_INET6});
  add_interface("ppp1");
  add_interface("utun3");
  add_interface("en0");
  const Observation observation = observe_interfaces();
  ASSERT_EQ(observation.signal, "mitm.tunnels");
  ASSERT_EQ(observation.source, "getifaddrs");
  ASSERT_EQ(observation.status, Status::kOk);
  ASSERT_TRUE(std::holds_alternative<std::vector<std::string>>(observation.value));

  const auto& names = std::get<std::vector<std::string>>(observation.value);
  EXPECT_LE(names.size(), std::size_t{64});
  EXPECT_EQ(names, (std::vector<std::string>{"ppp1", "utun3"}));
  EXPECT_TRUE(std::ranges::all_of(names, has_tunnel_form));
  EXPECT_TRUE(std::ranges::is_sorted(names));
  EXPECT_EQ(std::ranges::adjacent_find(names), names.end());
  EXPECT_EQ(inventory().reads, 1U);
  EXPECT_EQ(inventory().frees, 1U);
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
  EXPECT_EQ(mitm(),
            (std::vector<Observation>{
                {.signal = "mitm.tunnels", .source = "getifaddrs", .status = Status::kUnsupported, .value = {}},
                {.signal = "mitm.proxies",
                 .source = "CFNetworkCopySystemProxySettings",
                 .status = Status::kUnsupported,
                 .value = {}},
                {.signal = "mitm.user_cas", .source = "trust_store", .status = Status::kUnsupported, .value = {}},
            }));
}

/// Actual production API path, reached with test-owned OS records only.
Observation collect_network() { return observe_interfaces(); }

TEST_F(IosInterfaces, collect_whenIPv6OnlyAndDualStack_reportsSortedOwnedNamesOnce) {
  add_interface("tun2", {.flags = IFF_UP, .family = AF_INET6});
  add_interface("tun0", {.flags = IFF_UP, .family = AF_INET});
  add_interface("tun2", {.flags = IFF_UP, .family = AF_INET});
  EXPECT_EQ(collect_network(), tunnels({"tun0", "tun2"}));
  EXPECT_EQ(inventory().reads, 1U);
  EXPECT_EQ(inventory().frees, 1U);
}
TEST_F(IosInterfaces, collect_whenOnlyIPv6Address_reportsCandidate) {
  add_interface("tun6", {.flags = IFF_UP, .family = AF_INET6});
  EXPECT_EQ(collect_network(), tunnels({"tun6"}));
  EXPECT_EQ(inventory().frees, 1U);
}
TEST_F(IosInterfaces, collect_whenSuccessHasNoList_reportsEmptyWithoutFree) {
  EXPECT_EQ(collect_network(), tunnels({}));
  EXPECT_EQ(inventory().reads, 1U);
  EXPECT_EQ(inventory().frees, 0U);
}
TEST_F(IosInterfaces, collect_whenApiFails_reportsErrorWithoutFree) {
  inventory().result = -1;
  EXPECT_EQ(collect_network(), failed("mitm.tunnels", "getifaddrs"));
  EXPECT_EQ(inventory().reads, 1U);
  EXPECT_EQ(inventory().frees, 0U);
}
TEST_F(IosInterfaces, collect_whenNameIsNull_reportsErrorAndFrees) {
  add_interface("tun0");
  inventory().nodes.front().null_name = true;
  EXPECT_EQ(collect_network(), failed("mitm.tunnels", "getifaddrs"));
  EXPECT_EQ(inventory().frees, 1U);
}
TEST_F(IosInterfaces, collect_whenNonmatchingNameIsEmpty_reportsErrorAndFrees) {
  add_interface("");
  EXPECT_EQ(collect_network(), failed("mitm.tunnels", "getifaddrs"));
  EXPECT_EQ(inventory().frees, 1U);
}
TEST_F(IosInterfaces, collect_when64CandidatesAndDuplicates_keepsCompleteSortedList) {
  std::vector<std::string> expected;
  for (int index = 63; index >= 0; --index) {
    const std::string name = "tun" + std::to_string(index);
    add_interface(name);
    add_interface(name, {.flags = IFF_UP, .family = AF_INET6});
    expected.push_back(name);
  }
  std::ranges::sort(expected);
  EXPECT_EQ(collect_network(), tunnels(expected));
  EXPECT_EQ(inventory().frees, 1U);
}
TEST_F(IosInterfaces, collect_whenMalformedRecordFollows64Candidates_doesNotStopAtOutputCeiling) {
  for (int index = 0; index < 64; ++index) {
    add_interface("tun" + std::to_string(index));
  }
  add_interface("");
  EXPECT_EQ(collect_network(), failed("mitm.tunnels", "getifaddrs"));
  EXPECT_EQ(inventory().frees, 1U);
}
TEST_F(IosInterfaces, collect_whenExactBudgetContainsNonmatchingAndNullAddressNodes_completesView) {
  constexpr std::size_t kRecords = 65536 / (sizeof(ifaddrs) + IFNAMSIZ);
  for (std::size_t index = 0; index < kRecords - 1; ++index) {
    add_interface("wlan0");
    inventory().nodes.back().null_address = true;
  }
  add_interface("tun0");
  EXPECT_EQ(collect_network(), tunnels({"tun0"}));
  EXPECT_EQ(inventory().frees, 1U);
}
TEST_F(IosInterfaces, collect_whenNonmatchingNodesExceedBudget_reportsErrorWithoutCandidate) {
  constexpr std::size_t kRecords = 65536 / (sizeof(ifaddrs) + IFNAMSIZ);
  for (std::size_t index = 0; index <= kRecords; ++index) {
    add_interface("wlan0");
    inventory().nodes.back().null_address = true;
  }
  EXPECT_EQ(collect_network(), failed("mitm.tunnels", "getifaddrs"));
  EXPECT_EQ(inventory().frees, 1U);
}
TEST_F(IosInterfaces, collect_whenOrdinaryAndUnusualNamesArePresent_reportsOnlyKnownForms) {
  for (const std::string_view name :
       {"pdp_ip0", "rmnet0", "wlan0", "en0", "awdl0", "llw0", "tunl0", "wg0", "corpmesh0"}) {
    add_interface(name, {.flags = IFF_UP, .family = AF_INET6});
  }
  EXPECT_EQ(collect_network(), tunnels({}));
}

TEST_F(IosInterfaces, collect_when65DistinctCandidates_reportsErrorAndFrees) {
  for (int index = 64; index >= 0; --index) {
    add_interface("tun" + std::to_string(index));
  }
  EXPECT_EQ(collect_network(), failed("mitm.tunnels", "getifaddrs"));
  EXPECT_EQ(inventory().frees, 1U);
}
TEST_F(IosInterfaces, collect_whenMalformedNonmatchingNameAfterCandidate_discardsPartialResult) {
  add_interface("tun0");
  add_interface(std::string(IFNAMSIZ, 'x'));
  EXPECT_EQ(collect_network(), failed("mitm.tunnels", "getifaddrs"));
  EXPECT_EQ(inventory().frees, 1U);
}
TEST_F(IosInterfaces, collect_whenWorkBudgetExceededByDuplicates_reportsErrorAndFrees) {
  constexpr std::size_t kRecords = 65536 / (sizeof(ifaddrs) + IFNAMSIZ);
  for (std::size_t index = 0; index <= kRecords; ++index) {
    add_interface("tun0");
  }
  EXPECT_EQ(collect_network(), failed("mitm.tunnels", "getifaddrs"));
  EXPECT_EQ(inventory().frees, 1U);
  RecordProperty("sizeof_ifaddrs", static_cast<int>(sizeof(ifaddrs)));
  RecordProperty("max_records", static_cast<int>(kRecords));
}

TEST_F(IosInterfaces, collect_whenNamedEntryHasNoAddress_preservesPlatformEligibility) {
  add_interface("tun0");
  inventory().nodes.front().null_address = true;
  EXPECT_EQ(collect_network(), tunnels({}));
  EXPECT_EQ(inventory().frees, 1U);
}
TEST_F(IosInterfaces, collect_whenNamedEntryIsDown_preservesPlatformEligibility) {
  add_interface("tun0", {.flags = 0, .family = AF_INET6});
  EXPECT_EQ(collect_network(), tunnels({}));
  EXPECT_EQ(inventory().frees, 1U);
}

/// Retains the exact immutable cycle published to the existing plugin callback.
constexpr rasp::plugins::Key<std::shared_ptr<const CycleSnapshot>> kNetworkSnapshot{"test.network.snapshot"};
/// Confirms the callback receives the same cycle owner and stores it beyond the dispatch call.
void retain_network_cycle(const std::shared_ptr<const CycleSnapshot>& snapshot, rasp::plugins::Context& context) {
  EXPECT_EQ(context.get(rasp::plugins::kCycleSnapshot), snapshot);
  context.put(kNetworkSnapshot, snapshot);
}
/// A plugin-supplied collision must never replace or rescue builtin network evidence.
std::vector<Observation> colliding_network_plugin(rasp::plugins::Context& /*unused*/) {
  return {observed("mitm.tunnels", "getifaddrs", std::vector<std::string>{"tun999"})};
}
/// Runs the actual bounded collector at the builtin boundary, keeping other platform sources explicitly unavailable.
std::vector<Observation> collect_network_cycle(const Config& /*selection*/, const void* /*unused*/) {
  return {
      collect_network(),
      unsupported("mitm.proxies", "CFNetworkCopySystemProxySettings"),
      unsupported("mitm.user_cas", "trust_store"),
  };
}
TEST_F(IosInterfaces, cycle_whenSourceChangesAndErrors_preservesIndependentOwnedSnapshots) {
  CycleMonitor monitor;
  rasp::plugins::Context context;
  constexpr std::array kNetworkChecks{colliding_network_plugin};
  const rasp::plugins::Plugin plugin{.init = nullptr, .checks = kNetworkChecks, .on_cycle = retain_network_cycle};
  const std::array plugins{&plugin};
  const Config config{.build_id = "network-test", .checks = std::vector<std::string>{"mitm"}};
  add_interface("tun6", {.flags = IFF_UP, .family = AF_INET6});
  const auto first = monitor.run(config, cycle_catalogue("ios"), plugins, context, collect_network_cycle, nullptr);
  EXPECT_EQ(context.get(kNetworkSnapshot), first);
  ASSERT_EQ(first->observations.front(), tunnels({"tun6"}));
  EXPECT_EQ(inventory().frees, 1U);
  const std::string rule_id = "native.ios.mitm.tunnels.getifaddrs";
  const auto decision = [&rule_id](const auto& snapshot) -> const LocalDecision& {
    const auto found = std::ranges::find(snapshot->local_decisions.rows, rule_id, &LocalDecision::rule_id);
    EXPECT_NE(found, snapshot->local_decisions.rows.end());
    return *found;
  };
  EXPECT_EQ(decision(first).verdict, LocalVerdict::kUnknown);
  EXPECT_EQ(decision(first).reason, LocalReason::kContextRequired);
  EXPECT_EQ(decision(first).severity, LocalSeverity::kInfo);
  EXPECT_EQ(decision(first).rule_version, 1U);
  ASSERT_EQ(decision(first).evidence, std::vector<std::size_t>{0});
  inventory() = {};
  inventory().result = -1;
  const auto second = monitor.run(config, cycle_catalogue("ios"), plugins, context, collect_network_cycle, nullptr);
  EXPECT_EQ(context.get(kNetworkSnapshot), second);
  EXPECT_NE(first, second);
  ASSERT_TRUE(first->metadata.sequence.has_value());
  EXPECT_EQ(second->metadata.sequence, *first->metadata.sequence + 1);
  EXPECT_EQ(second->observations.front(), failed("mitm.tunnels", "getifaddrs"));
  EXPECT_EQ(decision(second).verdict, LocalVerdict::kUnknown);
  EXPECT_EQ(decision(second).reason, LocalReason::kStatusUnavailable);
  EXPECT_FALSE(decision(second).predicate_evaluated);
  EXPECT_EQ(second->observations.back(), tunnels({"tun999"}));
  EXPECT_EQ(inventory().frees, 0U);
  inventory() = {};
  add_interface("tun7");
  const auto third = monitor.run(config, cycle_catalogue("ios"), plugins, context, collect_network_cycle, nullptr);
  EXPECT_EQ(context.get(kNetworkSnapshot), third);
  EXPECT_EQ(third->observations.front(), tunnels({"tun7"}));
  EXPECT_EQ(first->observations.front(), tunnels({"tun6"}));
  EXPECT_EQ(decision(first).reason, LocalReason::kContextRequired);
  EXPECT_EQ(second->observations.front(), failed("mitm.tunnels", "getifaddrs"));
  EXPECT_FALSE(context.get(rasp::plugins::kCycleSnapshot).has_value());
}
TEST_F(IosInterfaces, cycle_whenNoNamesMatch_limitsAbsenceToTheSourcePredicate) {
  CycleMonitor monitor;
  rasp::plugins::Context context;
  const auto snapshot = monitor.run({.build_id = "network-test", .checks = std::vector<std::string>{"mitm"}},
                                    cycle_catalogue("ios"), {}, context, collect_network_cycle, nullptr);
  const auto row =
      std::ranges::find(snapshot->local_decisions.rows, "native.ios.mitm.tunnels.getifaddrs", &LocalDecision::rule_id);
  ASSERT_NE(row, snapshot->local_decisions.rows.end());
  EXPECT_EQ(row->verdict, LocalVerdict::kBenign);
  EXPECT_EQ(row->reason, LocalReason::kIndicatorAbsent);
  EXPECT_EQ(row->evidence, std::vector<std::size_t>{0});
}

TEST_F(IosInterfaces, collect_whenCellularCallingShapedEntriesPresent_keepsPlatformScope) {
  add_interface("ipsec0", {.flags = IFF_UP, .family = AF_INET6});
  add_interface("utun0", {.flags = IFF_UP, .family = AF_INET6});
  add_interface("pdp_ip0", {.flags = IFF_UP, .family = AF_INET6});
  EXPECT_EQ(collect_network(), tunnels({"ipsec0", "utun0"}));
  EXPECT_EQ(inventory().frees, 1U);
}
TEST_F(IosInterfaces, collect_whenNameUsesLastTerminatorByte_validatesTheFullBound) {
  add_interface("tun" + std::string(IFNAMSIZ - 4, '1'));
  EXPECT_EQ(collect_network(), tunnels({"tun" + std::string(IFNAMSIZ - 4, '1')}));
  EXPECT_EQ(inventory().frees, 1U);
}
TEST(Mitm, observeTunnels_whenHelperNameContainsEmbeddedNull_reportsError) {
  const std::vector<InterfaceAddress> entries{
      {.name = std::string("utun0\0suffix", 12), .flags = kTunnelUp, .family = kFamilyIPv4},
  };
  EXPECT_EQ(observe_tunnels(entries), failed("mitm.tunnels", "getifaddrs"));
}

}  // namespace
}  // namespace rasp::ios::checks
