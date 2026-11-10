/// Tests for the DNS report builder.

#include "dns_report.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "rasp/observation.h"

namespace rasp::plugins::dns_reporting {
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

ReportContext test_context() {
  return ReportContext{.build_ref = kTestBuildRef, .install_id = kTestInstallId, .zone = kTestZone};
}

TEST(DnsReport, buildReport_whenSmallObservations_returnsOneChunk) {
  const std::vector<rasp::Observation> observations = {
      rasp::observed("jb.sandbox_escape", "open", true),
  };

  const std::vector<std::string> names = build_report(observations, test_context());

  ASSERT_EQ(names.size(), static_cast<std::size_t>(1));
  EXPECT_GT(names[0].size(), kTestZone.size());
  EXPECT_EQ(names[0].substr(names[0].size() - kTestZone.size()), kTestZone);
}

TEST(DnsReport, buildReport_whenManyObservations_returnsMultipleChunks) {
  std::vector<rasp::Observation> observations;
  observations.reserve(20);
  for (int i = 0; i < 20; ++i) {
    observations.push_back(rasp::observed("jb.fs_paths", "stat",
                                          std::vector<std::string>{"/Applications/Cydia.app", "/bin/sh", "/var/jb"}));
  }

  const std::vector<std::string> names = build_report(observations, test_context());

  ASSERT_GT(names.size(), static_cast<std::size_t>(1));
  for (const std::string& name : names) {
    EXPECT_EQ(name.substr(name.size() - kTestZone.size()), kTestZone);
  }
}

TEST(DnsReport, buildReport_whenEmptyZone_returnsEmpty) {
  const ReportContext context = {.build_ref = kTestBuildRef, .install_id = kTestInstallId, .zone = ""};
  const std::vector<std::string> names = build_report({rasp::observed("s", "r", true)}, context);
  EXPECT_EQ(names.size(), static_cast<std::size_t>(0));
}

TEST(DnsReport, buildReport_whenEmptyObservations_returnsOneChunk) {
  const std::vector<std::string> names = build_report({}, test_context());
  ASSERT_EQ(names.size(), static_cast<std::size_t>(1));
}

}  // namespace
}  // namespace rasp::plugins::dns_reporting
