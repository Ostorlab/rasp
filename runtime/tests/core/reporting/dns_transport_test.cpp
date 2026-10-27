/// Tests for the DNS transport layer.

#include "rasp/reporting/dns_transport.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "rasp/observation.h"
#include "rasp/reporting/dns_report.h"

namespace rasp::reporting {
namespace {

/// A build ref for testing.
constexpr std::array<std::uint8_t, 16> kTestBuildRef = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
};

/// An install id for testing.
constexpr std::array<std::uint8_t, 16> kTestInstallId = {
    0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x43, 0x33, 0x84, 0x44, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
};

const std::string kTestZone = "rsp.test";

/// Counts how many names the resolver was called with.
int g_resolve_count = 0;

/// The call index on which the resolver should fail (-1 = never fail).
int g_fail_on = -1;

bool fake_resolver(const std::string& /*name*/) {
  const int current = g_resolve_count;
  ++g_resolve_count;
  return current != g_fail_on;
}

ReportContext test_context() {
  return ReportContext{.build_ref = kTestBuildRef, .install_id = kTestInstallId, .zone = kTestZone};
}

TEST(DnsTransport, sendObservations_whenResolverSucceeds_resolvesAllNames) {
  g_resolve_count = 0;
  g_fail_on = -1;

  const std::vector<Observation> observations = {
      observed("jb.sandbox_escape", "open", true),
  };

  send_observations(observations, test_context(), &fake_resolver);

  EXPECT_EQ(g_resolve_count, 1);
}

TEST(DnsTransport, sendObservations_whenResolverFails_stopsEarly) {
  g_resolve_count = 0;
  g_fail_on = 1;

  std::vector<Observation> observations;
  observations.reserve(20);
  for (int i = 0; i < 20; ++i) {
    observations.push_back(
        observed("jb.fs_paths", "stat", std::vector<std::string>{"/Applications/Cydia.app", "/bin/sh", "/var/jb"}));
  }

  send_observations(observations, test_context(), &fake_resolver);

  EXPECT_EQ(g_resolve_count, 2);
}

}  // namespace
}  // namespace rasp::reporting
