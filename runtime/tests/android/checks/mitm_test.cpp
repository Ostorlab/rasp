/// Tests for the Android network-interception checks: the tunnel probe that reports tunnel interface names and the
/// trust store probe that reports user-installed certificate authorities.

#include "checks/mitm.h"

#include <algorithm>
#include <cstddef>
#include <gtest/gtest.h>
#include <string>
#include <utility>
#include <vector>

#include "rasp/observation.h"
#include "support/files.h"

namespace rasp::android::checks {
namespace {

using test_support::TemporaryDirectory;
using test_support::write_file;

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

/// The observation of a trust store that couldn't be listed.
[[nodiscard]] Observation unreadable_cacerts() {
  return {.signal = "mitm.user_cas", .source = "user_cacerts", .status = Status::kError, .value = {}};
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

TEST(Mitm, observeUserCas_whenTheStoreIsEmpty_reportsEmptyList) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());

  EXPECT_EQ(observe_user_cas(directory.path()), user_cas({}));
}

TEST(Mitm, observeUserCas_whenAnAuthorityIsInstalled_reportsItsFileName) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  ASSERT_TRUE(write_file(directory.path() + "/9a5ba575.0", "certificate bytes"));

  EXPECT_EQ(observe_user_cas(directory.path()), user_cas({"9a5ba575.0"}));
}

TEST(Mitm, observeUserCas_whenSeveralAuthoritiesAreInstalled_reportsThemSorted) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  ASSERT_TRUE(write_file(directory.path() + "/c8750f0d.0", "one"));
  ASSERT_TRUE(write_file(directory.path() + "/3c860d51.0", "two"));

  EXPECT_EQ(observe_user_cas(directory.path()), user_cas({"3c860d51.0", "c8750f0d.0"}));
}

/// The authority file name for `index`, with a three-digit number so the names sort in the same order as the numbers.
[[nodiscard]] std::string authority_name(int index) {
  const std::string digits = std::to_string(index);
  return "ca" + std::string(3 - std::min<std::size_t>(3, digits.size()), '0') + digits + ".0";
}

TEST(Mitm, observeUserCas_whenManyAuthoritiesAreInstalled_reportsThemAllSorted) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  // Create the files from the largest name to the smallest, so a check that preserved creation order rather than
  // sorting would fail this test. Every authority is reported: the user decides which to trust.
  for (int index = 109; index >= 0; --index) {
    ASSERT_TRUE(write_file(directory.path() + "/" + authority_name(index), "cert"));
  }
  std::vector<std::string> expected;
  expected.reserve(110);
  for (int index = 0; index < 110; ++index) {
    expected.push_back(authority_name(index));
  }

  EXPECT_EQ(observe_user_cas(directory.path()), user_cas(expected));
}

TEST(Mitm, observeUserCas_whenTheDirectoryIsMissing_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());

  EXPECT_EQ(observe_user_cas(directory.path() + "/missing"), unreadable_cacerts());
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
