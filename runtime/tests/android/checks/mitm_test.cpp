/// Tests for the Android network-interception checks: the route probe that reports tunnel interfaces and the trust
/// store probe that reports user-installed certificate authorities.

#include "checks/mitm.h"

#include <algorithm>
#include <cstddef>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "rasp/observation.h"
#include "support/files.h"

namespace rasp::android::checks {
namespace {

using test_support::TemporaryDirectory;
using test_support::write_file;

/// The header line of a route table, which names no interface.
constexpr std::string_view kRouteHeader =
    "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n";

/// A clean device's route table: its physical interfaces only, no tunnel.
constexpr std::string_view kCleanRoutes =
    "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
    "wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n"
    "wlan0\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n";

/// The mitm.tunnels observation that reports `lines`.
[[nodiscard]] Observation tunnels(std::vector<std::string> lines) {
  return {.signal = "mitm.tunnels", .source = "proc_net_route", .status = Status::kOk, .value = std::move(lines)};
}

/// The mitm.user_cas observation that reports `names`.
[[nodiscard]] Observation user_cas(std::vector<std::string> names) {
  return {.signal = "mitm.user_cas", .source = "user_cacerts", .status = Status::kOk, .value = std::move(names)};
}

/// The observation of a route table that couldn't be read.
[[nodiscard]] Observation unreadable_route() {
  return {.signal = "mitm.tunnels", .source = "proc_net_route", .status = Status::kError, .value = {}};
}

/// The observation of a trust store that couldn't be listed.
[[nodiscard]] Observation unreadable_cacerts() {
  return {.signal = "mitm.user_cas", .source = "user_cacerts", .status = Status::kError, .value = {}};
}

/// Writes `content` to a route file in `directory` and returns its path.
[[nodiscard]] std::string write_route(const TemporaryDirectory& directory, std::string_view content) {
  const std::string path = directory.path() + "/route";
  return write_file(path, content) ? path : std::string();
}

TEST(Mitm, observeTunnels_whenNoTunnelRoutes_reportsEmptyList) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string path = write_route(directory, kCleanRoutes);
  ASSERT_FALSE(path.empty());

  EXPECT_EQ(observe_tunnels(path), tunnels({}));
}

TEST(Mitm, observeTunnels_whenATunnelInterfaceRoutes_reportsItsLine) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string line = "tun0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0";
  const std::string path = write_route(directory, std::string(kCleanRoutes) + line + "\n");
  ASSERT_FALSE(path.empty());

  EXPECT_EQ(observe_tunnels(path), tunnels({line}));
}

TEST(Mitm, observeTunnels_whenATapInterfaceRoutes_reportsItsLine) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string line = "tap0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0";
  const std::string path = write_route(directory, std::string(kRouteHeader) + line + "\n");
  ASSERT_FALSE(path.empty());

  EXPECT_EQ(observe_tunnels(path), tunnels({line}));
}

TEST(Mitm, observeTunnels_whenAPppInterfaceRoutes_doesNotReportIt) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string line = "ppp0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0";
  const std::string path = write_route(directory, std::string(kRouteHeader) + line + "\n");
  ASSERT_FALSE(path.empty());

  EXPECT_EQ(observe_tunnels(path), tunnels({}));
}

TEST(Mitm, observeTunnels_whenTheHeaderIsPresent_doesNotReportIt) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string path = write_route(directory, kRouteHeader);
  ASSERT_FALSE(path.empty());

  EXPECT_EQ(observe_tunnels(path), tunnels({}));
}

TEST(Mitm, observeTunnels_whenTheFileIsMissing_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());

  EXPECT_EQ(observe_tunnels(directory.path() + "/missing"), unreadable_route());
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

/// The authority file name for `index`, with a two-digit number so the names sort in the same order as the numbers.
[[nodiscard]] std::string authority_name(int index) {
  const std::string digits = std::to_string(index);
  return "ca" + std::string(2 - std::min<std::size_t>(2, digits.size()), '0') + digits + ".0";
}

TEST(Mitm, observeUserCas_whenMoreThan32AuthoritiesAreInstalled_reportsThe32Smallest) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  std::vector<std::string> expected;
  for (int index = 0; index < 40; ++index) {
    const std::string name = authority_name(index);
    ASSERT_TRUE(write_file(directory.path() + "/" + name, "cert"));
    if (index < 32) {
      expected.push_back(name);
    }
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
                {.signal = "mitm.tunnels", .source = "proc_net_route", .status = Status::kUnsupported, .value = {}},
                {.signal = "mitm.user_cas", .source = "user_cacerts", .status = Status::kUnsupported, .value = {}},
            }));
}

}  // namespace
}  // namespace rasp::android::checks
