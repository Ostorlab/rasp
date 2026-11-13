/// Tests for the Android network-interception checks: the tunnel probe that reports tunnel interface names and the
/// KeyStore probe that reports user-installed certificate authorities.

#include "checks/mitm.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <gtest/gtest.h>
#include <ifaddrs.h>
#include <memory>
#include <net/if.h>
#include <string>
#include <sys/socket.h>
#include <utility>
#include <vector>

#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/cycle.h"
#include "rasp/decision.h"
#include "rasp/observation.h"
#include "rasp/plugin.h"
#include "support/interfaces.h"

namespace rasp::android::checks {
namespace {

/// A clean device's interface names: its physical interfaces and the loopback, no tunnel.
const std::vector<std::string> kCleanInterfaces = {"lo", "wlan0", "wlan0", "rmnet0"};

/// The mitm.tunnels observation that reports `names`.
[[nodiscard]] Observation tunnels(std::vector<std::string> names) {
  return {.signal = "mitm.tunnels", .source = "getifaddrs", .status = Status::kOk, .value = std::move(names)};
}

/// The mitm.user_cas observation that reports `names`.
[[nodiscard]] Observation user_cas(std::vector<std::string> names) {
  return {.signal = "mitm.user_cas", .source = "user_cacerts", .status = Status::kOk, .value = std::move(names)};
}

/// The three-digit-numbered tunnel name for `index`, so the names sort in the same order as the numbers.
[[nodiscard]] std::string numbered_tunnel(int index) {
  const std::string digits = std::to_string(index);
  return "tun" + std::string(3 - std::min<std::size_t>(3, digits.size()), '0') + digits;
}

TEST(Mitm, observeTunnels_whenNoTunnelInterfaces_reportsEmptyList) {
  EXPECT_EQ(observe_tunnels(kCleanInterfaces), tunnels({}));
}

TEST(Mitm, observeTunnels_whenATunInterfaceIsPresent_reportsItsName) {
  std::vector<std::string> names = kCleanInterfaces;
  names.emplace_back("tun0");

  EXPECT_EQ(observe_tunnels(names), tunnels({"tun0"}));
}

TEST(Mitm, observeTunnels_whenATapInterfaceIsPresent_reportsItsName) {
  std::vector<std::string> names = kCleanInterfaces;
  names.emplace_back("tap0");

  EXPECT_EQ(observe_tunnels(names), tunnels({"tap0"}));
}

TEST(Mitm, observeTunnels_whenAPppInterfaceIsPresent_doesNotReportIt) {
  std::vector<std::string> names = kCleanInterfaces;
  names.emplace_back("ppp0");

  EXPECT_EQ(observe_tunnels(names), tunnels({}));
}

TEST(Mitm, observeTunnels_whenAnIpipTunnelIsPresent_doesNotReportIt) {
  // tunl0 is the kernel's IPIP tunnel interface; it starts with `tun` but isn't a TUN/TAP device, so it must not match.
  std::vector<std::string> names = kCleanInterfaces;
  names.emplace_back("tunl0");

  EXPECT_EQ(observe_tunnels(names), tunnels({}));
}

TEST(Mitm, observeTunnels_whenATunnelAppearsTwice_reportsItOnce) {
  // getifaddrs lists an interface once per address it holds, so a tunnel with an IPv4 and an IPv6 address appears
  // twice.
  const std::vector<std::string> names = {"wlan0", "tun0", "tun0"};

  EXPECT_EQ(observe_tunnels(names), tunnels({"tun0"}));
}

TEST(Mitm, observeTunnels_whenMoreThan64Tunnels_reportsErrorWithoutPartialValue) {
  std::vector<std::string> names;
  names.reserve(65);
  for (int index = 0; index < 65; ++index) {
    names.push_back(numbered_tunnel(index));
  }
  EXPECT_EQ(observe_tunnels(names), failed("mitm.tunnels", "getifaddrs"));
}

/// The aliases of a device's `AndroidCAStore` KeyStore with no user authority: only system ones.
const std::vector<std::string> kSystemAliases = {"system:9a5ba575.0", "system:c8750f0d.0", "system:3c860d51.0"};

TEST(Mitm, observeUserCas_whenOnlySystemAuthoritiesAreTrusted_reportsEmptyList) {
  EXPECT_EQ(observe_user_cas(kSystemAliases), user_cas({}));
}

TEST(Mitm, observeUserCas_whenTheStoreIsEmpty_reportsEmptyList) { EXPECT_EQ(observe_user_cas({}), user_cas({})); }

TEST(Mitm, observeUserCas_whenAUserAuthorityIsInstalled_reportsItsFileName) {
  std::vector<std::string> aliases = kSystemAliases;
  aliases.emplace_back("user:9a5ba575.0");

  EXPECT_EQ(observe_user_cas(aliases), user_cas({"9a5ba575.0"}));
}

TEST(Mitm, observeUserCas_whenSeveralUserAuthoritiesAreInstalled_reportsThemSortedOnce) {
  const std::vector<std::string> aliases = {
      "user:c8750f0d.0",
      "system:1df5a75f.0",
      "user:3c860d51.0",
      "user:c8750f0d.0",
  };

  EXPECT_EQ(observe_user_cas(aliases), user_cas({"3c860d51.0", "c8750f0d.0"}));
}

TEST(Mitm, observeUserCas_whenAnAliasOnlyContainsUser_doesNotReportIt) {
  const std::vector<std::string> aliases = {"system:user:9a5ba575.0", "User:9a5ba575.0", "user"};

  EXPECT_EQ(observe_user_cas(aliases), user_cas({}));
}

/// The authority file name for `index`, with a three-digit number so the names sort in the same order as the numbers.
[[nodiscard]] std::string authority_name(int index) {
  const std::string digits = std::to_string(index);
  return "ca" + std::string(3 - std::min<std::size_t>(3, digits.size()), '0') + digits + ".0";
}

TEST(Mitm, observeUserCas_whenManyUserAuthoritiesAreInstalled_reportsThemAllSorted) {
  std::vector<std::string> aliases;
  std::vector<std::string> expected;
  aliases.reserve(110);
  expected.reserve(110);
  for (int index = 109; index >= 0; --index) {
    aliases.push_back("user:" + authority_name(index));
  }
  for (int index = 0; index < 110; ++index) {
    expected.push_back(authority_name(index));
  }

  EXPECT_EQ(observe_user_cas(aliases), user_cas(expected));
}

TEST(Mitm, mitm_whenOffAndroid_reportsEveryCheckAsUnsupported) {
  EXPECT_EQ(mitm(),
            (std::vector<Observation>{
                {.signal = "mitm.tunnels", .source = "getifaddrs", .status = Status::kUnsupported, .value = {}},
                {.signal = "mitm.user_cas", .source = "user_cacerts", .status = Status::kUnsupported, .value = {}},
            }));
}

/// Actual production API path, reached with test-owned OS records only.
Observation collect_network() { return observe_interfaces(); }
using AndroidInterfaces = rasp::test::InterfaceList;

TEST_F(AndroidInterfaces, collect_whenIPv6OnlyAndDualStack_reportsSortedOwnedNamesOnce) {
  add_interface("tun2", {.flags = IFF_UP, .family = AF_INET6});
  add_interface("tun0", {.flags = IFF_UP, .family = AF_INET});
  add_interface("tun2", {.flags = IFF_UP, .family = AF_INET});
  EXPECT_EQ(collect_network(), tunnels({"tun0", "tun2"}));
  EXPECT_EQ(inventory().reads, 1U);
  EXPECT_EQ(inventory().frees, 1U);
}
TEST_F(AndroidInterfaces, collect_whenOnlyIPv6Address_reportsCandidate) {
  add_interface("tun6", {.flags = IFF_UP, .family = AF_INET6});
  EXPECT_EQ(collect_network(), tunnels({"tun6"}));
  EXPECT_EQ(inventory().frees, 1U);
}
TEST_F(AndroidInterfaces, collect_whenSuccessHasNoList_reportsEmptyWithoutFree) {
  EXPECT_EQ(collect_network(), tunnels({}));
  EXPECT_EQ(inventory().reads, 1U);
  EXPECT_EQ(inventory().frees, 0U);
}
TEST_F(AndroidInterfaces, collect_whenApiFails_reportsErrorWithoutFree) {
  inventory().result = -1;
  EXPECT_EQ(collect_network(), failed("mitm.tunnels", "getifaddrs"));
  EXPECT_EQ(inventory().reads, 1U);
  EXPECT_EQ(inventory().frees, 0U);
}
TEST_F(AndroidInterfaces, collect_whenNameIsNull_reportsErrorAndFrees) {
  add_interface("tun0");
  inventory().nodes.front().null_name = true;
  EXPECT_EQ(collect_network(), failed("mitm.tunnels", "getifaddrs"));
  EXPECT_EQ(inventory().frees, 1U);
}
TEST_F(AndroidInterfaces, collect_whenNonmatchingNameIsEmpty_reportsErrorAndFrees) {
  add_interface("");
  EXPECT_EQ(collect_network(), failed("mitm.tunnels", "getifaddrs"));
  EXPECT_EQ(inventory().frees, 1U);
}
TEST_F(AndroidInterfaces, collect_when64CandidatesAndDuplicates_keepsCompleteSortedList) {
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
TEST_F(AndroidInterfaces, collect_whenMalformedRecordFollows64Candidates_doesNotStopAtOutputCeiling) {
  for (int index = 0; index < 64; ++index) {
    add_interface("tun" + std::to_string(index));
  }
  add_interface("");
  EXPECT_EQ(collect_network(), failed("mitm.tunnels", "getifaddrs"));
  EXPECT_EQ(inventory().frees, 1U);
}
TEST_F(AndroidInterfaces, collect_whenExactBudgetContainsNonmatchingAndNullAddressNodes_completesView) {
  constexpr std::size_t kRecords = 65536 / (sizeof(ifaddrs) + IFNAMSIZ);
  for (std::size_t index = 0; index < kRecords - 1; ++index) {
    add_interface("wlan0");
    inventory().nodes.back().null_address = true;
  }
  add_interface("tun0");
  EXPECT_EQ(collect_network(), tunnels({"tun0"}));
  EXPECT_EQ(inventory().frees, 1U);
}
TEST_F(AndroidInterfaces, collect_whenNonmatchingNodesExceedBudget_reportsErrorWithoutCandidate) {
  constexpr std::size_t kRecords = 65536 / (sizeof(ifaddrs) + IFNAMSIZ);
  for (std::size_t index = 0; index <= kRecords; ++index) {
    add_interface("wlan0");
    inventory().nodes.back().null_address = true;
  }
  EXPECT_EQ(collect_network(), failed("mitm.tunnels", "getifaddrs"));
  EXPECT_EQ(inventory().frees, 1U);
}
TEST_F(AndroidInterfaces, collect_whenOrdinaryAndUnusualNamesArePresent_reportsOnlyKnownForms) {
  for (const std::string_view name :
       {"pdp_ip0", "rmnet0", "wlan0", "en0", "awdl0", "llw0", "tunl0", "wg0", "corpmesh0"}) {
    add_interface(name, {.flags = IFF_UP, .family = AF_INET6});
  }
  EXPECT_EQ(collect_network(), tunnels({}));
}

TEST_F(AndroidInterfaces, collect_when65DistinctCandidates_reportsErrorAndFrees) {
  for (int index = 64; index >= 0; --index) {
    add_interface("tun" + std::to_string(index));
  }
  EXPECT_EQ(collect_network(), failed("mitm.tunnels", "getifaddrs"));
  EXPECT_EQ(inventory().frees, 1U);
}
TEST_F(AndroidInterfaces, collect_whenMalformedNonmatchingNameAfterCandidate_discardsPartialResult) {
  add_interface("tun0");
  add_interface(std::string(IFNAMSIZ, 'x'));
  EXPECT_EQ(collect_network(), failed("mitm.tunnels", "getifaddrs"));
  EXPECT_EQ(inventory().frees, 1U);
}
TEST_F(AndroidInterfaces, collect_whenWorkBudgetExceededByDuplicates_reportsErrorAndFrees) {
  constexpr std::size_t kRecords = 65536 / (sizeof(ifaddrs) + IFNAMSIZ);
  for (std::size_t index = 0; index <= kRecords; ++index) {
    add_interface("tun0");
  }
  EXPECT_EQ(collect_network(), failed("mitm.tunnels", "getifaddrs"));
  EXPECT_EQ(inventory().frees, 1U);
  RecordProperty("sizeof_ifaddrs", static_cast<int>(sizeof(ifaddrs)));
  RecordProperty("max_records", static_cast<int>(kRecords));
}

TEST_F(AndroidInterfaces, collect_whenNamedEntryHasNoAddress_preservesPlatformEligibility) {
  add_interface("tun0");
  inventory().nodes.front().null_address = true;
  EXPECT_EQ(collect_network(), tunnels({"tun0"}));
  EXPECT_EQ(inventory().frees, 1U);
}
TEST_F(AndroidInterfaces, collect_whenNamedEntryIsDown_preservesPlatformEligibility) {
  add_interface("tun0", {.flags = 0, .family = AF_INET6});
  EXPECT_EQ(collect_network(), tunnels({"tun0"}));
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
  return {collect_network(), unsupported("mitm.user_cas", "user_cacerts")};
}
TEST_F(AndroidInterfaces, cycle_whenSourceChangesAndErrors_preservesIndependentOwnedSnapshots) {
  CycleMonitor monitor;
  rasp::plugins::Context context;
  constexpr std::array kNetworkChecks{colliding_network_plugin};
  const rasp::plugins::Plugin plugin{.init = nullptr, .checks = kNetworkChecks, .on_cycle = retain_network_cycle};
  const std::array plugins{&plugin};
  const Config config{.build_id = "network-test", .checks = std::vector<std::string>{"mitm"}};
  add_interface("tun6", {.flags = IFF_UP, .family = AF_INET6});
  const auto first = monitor.run(config, cycle_catalogue("android"), plugins, context, collect_network_cycle, nullptr);
  EXPECT_EQ(context.get(kNetworkSnapshot), first);
  ASSERT_EQ(first->observations.front(), tunnels({"tun6"}));
  EXPECT_EQ(inventory().frees, 1U);
  const std::string rule_id = "native.android.mitm.tunnels.getifaddrs";
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
  const auto second = monitor.run(config, cycle_catalogue("android"), plugins, context, collect_network_cycle, nullptr);
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
  const auto third = monitor.run(config, cycle_catalogue("android"), plugins, context, collect_network_cycle, nullptr);
  EXPECT_EQ(context.get(kNetworkSnapshot), third);
  EXPECT_EQ(third->observations.front(), tunnels({"tun7"}));
  EXPECT_EQ(first->observations.front(), tunnels({"tun6"}));
  EXPECT_EQ(decision(first).reason, LocalReason::kContextRequired);
  EXPECT_EQ(second->observations.front(), failed("mitm.tunnels", "getifaddrs"));
  EXPECT_FALSE(context.get(rasp::plugins::kCycleSnapshot).has_value());
}
TEST_F(AndroidInterfaces, cycle_whenNoNamesMatch_limitsAbsenceToTheSourcePredicate) {
  CycleMonitor monitor;
  rasp::plugins::Context context;
  const auto snapshot = monitor.run({.build_id = "network-test", .checks = std::vector<std::string>{"mitm"}},
                                    cycle_catalogue("android"), {}, context, collect_network_cycle, nullptr);
  const auto row = std::ranges::find(snapshot->local_decisions.rows, "native.android.mitm.tunnels.getifaddrs",
                                     &LocalDecision::rule_id);
  ASSERT_NE(row, snapshot->local_decisions.rows.end());
  EXPECT_EQ(row->verdict, LocalVerdict::kBenign);
  EXPECT_EQ(row->reason, LocalReason::kIndicatorAbsent);
  EXPECT_EQ(row->evidence, std::vector<std::size_t>{0});
}

TEST_F(AndroidInterfaces, collect_whenCellularCallingShapedEntriesPresent_keepsPlatformScope) {
  add_interface("ipsec0", {.flags = IFF_UP, .family = AF_INET6});
  add_interface("utun0", {.flags = IFF_UP, .family = AF_INET6});
  add_interface("pdp_ip0", {.flags = IFF_UP, .family = AF_INET6});
  EXPECT_EQ(collect_network(), tunnels({}));
  EXPECT_EQ(inventory().frees, 1U);
}
TEST_F(AndroidInterfaces, collect_whenNameUsesLastTerminatorByte_validatesTheFullBound) {
  add_interface("tun" + std::string(IFNAMSIZ - 4, '1'));
  EXPECT_EQ(collect_network(), tunnels({"tun" + std::string(IFNAMSIZ - 4, '1')}));
  EXPECT_EQ(inventory().frees, 1U);
}
TEST(Mitm, observeTunnels_whenHelperNameContainsEmbeddedNull_reportsError) {
  EXPECT_EQ(observe_tunnels({std::string("tun0\0suffix", 11)}), failed("mitm.tunnels", "getifaddrs"));
}

}  // namespace
}  // namespace rasp::android::checks
