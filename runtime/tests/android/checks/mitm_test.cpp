/// Tests for the Android network-interception checks: the tunnel probe that reports tunnel interface names and the
/// KeyStore probe that reports user-installed certificate authorities.

#include "checks/mitm.h"

#include <algorithm>
#include <cstddef>
#include <gtest/gtest.h>
#include <string>
#include <utility>
#include <vector>

#include "rasp/observation.h"

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

TEST(Mitm, observeTunnels_whenMoreThan100Tunnels_reportsThe100Smallest) {
  std::vector<std::string> names;
  std::vector<std::string> expected;
  names.reserve(110);
  expected.reserve(100);
  // Add the names from the largest to the smallest, so a probe that kept the first 100 encountered rather than the 100
  // smallest would fail this test.
  for (int index = 109; index >= 0; --index) {
    names.push_back(numbered_tunnel(index));
  }
  for (int index = 0; index < 100; ++index) {
    expected.push_back(numbered_tunnel(index));
  }

  EXPECT_EQ(observe_tunnels(names), tunnels(expected));
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

}  // namespace
}  // namespace rasp::android::checks
