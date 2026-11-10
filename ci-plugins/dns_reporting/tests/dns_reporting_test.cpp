/// Tests for kPlugin, the DNS reporting plugin: verifies the plugin's init and on_observations wiring.

#include <array>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <vector>

#include "dns_frame.h"
#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/observation.h"
#include "rasp/plugin.h"
#include "reporting/undelivered_run.h"
#include "sender.h"

namespace rasp::plugins::dns_reporting {

extern const Plugin kPlugin;

namespace {

constexpr Key<std::array<std::uint8_t, kBuildRefBytes>> kBuildRefKey{"dns_reporting.build_ref"};

constexpr Key<std::array<std::uint8_t, kInstallIdBytes>> kInstallIdKey{"dns_reporting.install_id"};

constexpr Key<Sender*> kSenderKey{"dns_reporting.sender"};

/// The install id of the tests, as the runtime gives it.
constexpr const char* kInstallId = "0f8e5b8e-6c1a-4b7e-9d3a-2a4c5e6f7a8b";

/// The bytes of kInstallId.
constexpr std::array<std::uint8_t, kInstallIdBytes> kExpectedInstallIdBytes{
    0x0f, 0x8e, 0x5b, 0x8e, 0x6c, 0x1a, 0x4b, 0x7e, 0x9d, 0x3a, 0x2a, 0x4c, 0x5e, 0x6f, 0x7a, 0x8b,
};

/// Install ids that are not a UUID: empty, without hyphens, one digit short, one digit more, a misplaced hyphen and a
/// character that is not a hex digit.
constexpr std::array<const char*, 6> kMalformedInstallIds{
    "",
    "0f8e5b8e6c1a4b7e9d3a2a4c5e6f7a8b",
    "0f8e5b8e-6c1a-4b7e-9d3a-2a4c5e6f7a8",
    "0f8e5b8e-6c1a-4b7e-9d3a-2a4c5e6f7a8b0",
    "0f8e5b8e+6c1a-4b7e-9d3a-2a4c5e6f7a8b",
    "0f8e5b8e-6c1a-4b7e-9d3a-2a4c5e6f7a8g",
};

/// The install id init stores for a config.
///
/// @param config The runtime's config.
/// @return The install id in the context after init.
[[nodiscard]] std::optional<std::array<std::uint8_t, kInstallIdBytes>> stored_install_id(const Config& config) {
  Context context;
  kPlugin.init(config, context);
  return context.get(kInstallIdKey);
}

TEST(DnsReportingPlugin, kPlugin_whenDeclared_hasAnInitNoChecksAndAnOnObservations) {
  EXPECT_NE(kPlugin.init, nullptr);
  EXPECT_TRUE(kPlugin.checks.empty());
  EXPECT_NE(kPlugin.on_observations, nullptr);
}

TEST(DnsReportingPlugin, init_whenBuildIdIsValid_storesParsedBuildRef) {
  const Config config{.build_id = "0123456789abcdef0123456789abcdef"};
  Context context;

  kPlugin.init(config, context);

  const auto ref = context.get(kBuildRefKey);
  ASSERT_TRUE(ref.has_value());
  const std::array<std::uint8_t, kBuildRefBytes> expected{
      0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
  };
  EXPECT_EQ(*ref, expected);
}

TEST(DnsReportingPlugin, init_whenBuildIdIsTooShort_storesZeroedBuildRef) {
  const Config config{.build_id = "0123456789abcdef"};
  Context context;

  kPlugin.init(config, context);

  const auto ref = context.get(kBuildRefKey);
  ASSERT_TRUE(ref.has_value());
  EXPECT_EQ(*ref, (std::array<std::uint8_t, kBuildRefBytes>{}));
}

TEST(DnsReportingPlugin, init_whenBuildIdHasNonHexChars_storesZeroedBuildRef) {
  const Config config{.build_id = "0123456789abcdefGGGGGGGGGGGGGGGG"};
  Context context;

  kPlugin.init(config, context);

  const auto ref = context.get(kBuildRefKey);
  ASSERT_TRUE(ref.has_value());
  EXPECT_EQ(*ref, (std::array<std::uint8_t, kBuildRefBytes>{}));
}

TEST(DnsReportingPlugin, init_whenGivenAnInstallId_storesItsBytes) {
  const Config config{.build_id = "0123456789abcdef0123456789abcdef", .install_id = kInstallId};

  const std::optional<std::array<std::uint8_t, kInstallIdBytes>> install_id = stored_install_id(config);

  EXPECT_EQ(install_id, kExpectedInstallIdBytes);
}

TEST(DnsReportingPlugin, init_whenGivenAnUppercaseInstallId_storesItsBytes) {
  const Config config{
      .build_id = "0123456789abcdef0123456789abcdef",
      .install_id = "0F8E5B8E-6C1A-4B7E-9D3A-2A4C5E6F7A8B",
  };

  const std::optional<std::array<std::uint8_t, kInstallIdBytes>> install_id = stored_install_id(config);

  EXPECT_EQ(install_id, kExpectedInstallIdBytes);
}

TEST(DnsReportingPlugin, init_whenGivenNoInstallId_storesARandomIdForEachLaunch) {
  const Config config{.build_id = "0123456789abcdef0123456789abcdef"};

  const std::optional<std::array<std::uint8_t, kInstallIdBytes>> first = stored_install_id(config);
  const std::optional<std::array<std::uint8_t, kInstallIdBytes>> second = stored_install_id(config);

  ASSERT_TRUE(first.has_value());
  ASSERT_TRUE(second.has_value());
  EXPECT_NE(*first, *second);
}

TEST(DnsReportingPlugin, init_whenGivenAnInstallIdThatIsNotAUuid_storesARandomIdForEachLaunch) {
  for (const char* const malformed : kMalformedInstallIds) {
    const Config config{.build_id = "0123456789abcdef0123456789abcdef", .install_id = malformed};

    const std::optional<std::array<std::uint8_t, kInstallIdBytes>> first = stored_install_id(config);
    const std::optional<std::array<std::uint8_t, kInstallIdBytes>> second = stored_install_id(config);

    ASSERT_TRUE(first.has_value()) << malformed;
    ASSERT_TRUE(second.has_value()) << malformed;
    EXPECT_NE(*first, *second) << malformed;
  }
}

TEST(DnsReportingPlugin, onObservations_whenCalledAfterInit_doesNotCrash) {
  const Config config{.build_id = "0123456789abcdef0123456789abcdef"};
  Context context;
  kPlugin.init(config, context);

  const std::vector<Observation> observations{observed("jb.fork_ok", "fork", false)};
  kPlugin.on_observations(observations, context);
}

TEST(DnsReportingPlugin, onObservations_whenCalledWithoutInit_doesNotCrash) {
  Context context;

  const std::vector<Observation> observations{observed("jb.fork_ok", "fork", false)};
  kPlugin.on_observations(observations, context);
}

TEST(DnsReportingPlugin, onObservations_whenNoRunIsUndelivered_sendsNothing) {
  const Config config{.build_id = "0123456789abcdef0123456789abcdef"};
  Context context;
  kPlugin.init(config, context);
  const std::vector<Observation> observations{observed("jb.fork_ok", "fork", false)};

  kPlugin.on_observations(observations, context);

  EXPECT_FALSE(context.get(kSenderKey).has_value());
}

TEST(DnsReportingPlugin, onObservations_whenARunIsUndelivered_takesItAndStartsTheSender) {
  const Config config{.build_id = "0123456789abcdef0123456789abcdef"};
  Context context;
  kPlugin.init(config, context);
  context.put(reporting::kUndeliveredRun, std::vector<Observation>{observed("jb.fork_ok", "fork", true)});
  const std::vector<Observation> observations{observed("jb.fork_ok", "fork", false)};

  kPlugin.on_observations(observations, context);

  EXPECT_FALSE(context.get(reporting::kUndeliveredRun).has_value());
  EXPECT_TRUE(context.get(kSenderKey).has_value());
}

}  // namespace
}  // namespace rasp::plugins::dns_reporting
