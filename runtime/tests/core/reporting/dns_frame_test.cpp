/// Tests for the DNS frame encoder against the server's golden test vectors.

#include "rasp/reporting/dns_frame.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "rasp/observation.h"
#include "rasp/reporting/cbor.h"

namespace rasp::reporting {
namespace {

/// The server's golden BUILD_REF: 0x0123456789abcdef0123456789abcdef.
constexpr std::array<std::uint8_t, 16> kBuildRef = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
};

/// The server's golden INSTALL_ID: UUID "11111111-2222-4333-8444-555555555555".
constexpr std::array<std::uint8_t, 16> kInstallId = {
    0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x43, 0x33, 0x84, 0x44, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
};

/// The server's golden MSG_ID: 0x9a3c51e7.
constexpr std::array<std::uint8_t, 4> kMsgId = {0x9A, 0x3C, 0x51, 0xE7};

/// The server's golden HOUR.
constexpr std::uint16_t kHour = 123;

/// The server's golden ZONE.
const std::string kZone = "rsp.test";

/// Builds the golden payload from the small observation set.
std::vector<std::uint8_t> golden_payload() {
  const std::vector<Observation> observations = {
      observed("jb.sandbox_escape", "open", true),
      observed("jb.fs_paths", "access", std::vector<std::string>{"/Applications/Cydia.app"}),
  };
  const std::vector<std::uint8_t> cbor = encode_observations(observations);
  return write_payload(kBuildRef, kHour, kInstallId, cbor, kMsgId);
}

// --- hour_of tests ---

TEST(DnsFrame, hourOf_whenBeforeEpoch_returnsZero) {
  EXPECT_EQ(hour_of(0), 0);
  EXPECT_EQ(hour_of(1767225599), 0);
}

TEST(DnsFrame, hourOf_whenAtEpoch_returnsZero) { EXPECT_EQ(hour_of(1767225600), 0); }

TEST(DnsFrame, hourOf_whenOneHourAfter_returnsOne) { EXPECT_EQ(hour_of(1767225600 + 3600), 1); }

TEST(DnsFrame, hourOf_whenAtMaxHour_returnsMaxHour) {
  EXPECT_EQ(hour_of(1767225600 + (static_cast<std::int64_t>(65535) * 3600)), 65535);
}

TEST(DnsFrame, hourOf_whenBeyondMaxHour_clamps) {
  EXPECT_EQ(hour_of(1767225600 + (static_cast<std::int64_t>(65536) * 3600)), 65535);
}

// --- write_payload tests ---

TEST(DnsFrame, writePayload_whenValidInputs_startsWithVersion) {
  const std::vector<std::uint8_t> payload = golden_payload();

  ASSERT_EQ(payload.size(), static_cast<std::size_t>(112));
  EXPECT_EQ(payload[0], kPayloadVersion);
}

TEST(DnsFrame, writePayload_whenValidInputs_containsBuildRef) {
  const std::vector<std::uint8_t> payload = golden_payload();

  ASSERT_EQ(payload.size(), static_cast<std::size_t>(112));
  EXPECT_TRUE(std::equal(kBuildRef.begin(), kBuildRef.end(), payload.begin() + 1));
}

TEST(DnsFrame, writePayload_whenValidInputs_containsHourAndInstallId) {
  const std::vector<std::uint8_t> payload = golden_payload();

  ASSERT_EQ(payload.size(), static_cast<std::size_t>(112));
  EXPECT_EQ(payload[17], static_cast<std::uint8_t>(kHour >> 8U));
  EXPECT_EQ(payload[18], static_cast<std::uint8_t>(kHour & 0xFFU));
  EXPECT_TRUE(std::equal(kInstallId.begin(), kInstallId.end(), payload.begin() + 19));
}

TEST(DnsFrame, writePayload_whenValidInputs_matchesGoldenCrc) {
  const std::vector<std::uint8_t> payload = golden_payload();

  ASSERT_EQ(payload.size(), static_cast<std::size_t>(112));
  EXPECT_EQ(payload[108], 0x73);
  EXPECT_EQ(payload[109], 0xB3);
  EXPECT_EQ(payload[110], 0xE9);
  EXPECT_EQ(payload[111], 0x51);
}

// --- write_names tests ---

TEST(DnsFrame, writeNames_whenSingleChunk_matchesGoldenName) {
  const std::vector<std::uint8_t> payload = golden_payload();
  const std::vector<std::string> names = write_names(payload, kMsgId, kZone);

  ASSERT_EQ(names.size(), static_cast<std::size_t>(1));
  EXPECT_EQ(names[0],
            "040I6HB7H6LSRRO14D2MF2DBPNNG0UOH248H28H28CPO8H2LALALALALGA272QJ."
            "25PPM2RJ4C9NNGNR5EDHM2S35CHNN0PBE03QO8QRAC8N6CSQVE1GN8Q3JCPGM6O."
            "R5EDPG10BN5T0N0S3CD5HM2T39DTN76BQ3F5I6IO9EC5O70STJT58G."
            "06D3OKF7000N0."
            "rsp.test");
}

TEST(DnsFrame, writeNames_whenMultiChunk_matchesGoldenNames) {
  const std::vector<Observation> observations = {
      observed("jb.sandbox_escape", "open", true),
      observed("jb.fs_paths", "access", std::vector<std::string>{"/Applications/Cydia.app"}),
      observed("jb.fs_paths", "stat", std::vector<std::string>{"/Applications/Cydia.app", "/bin/sh", "/var/jb"}),
      observed("jb.fork_ok", "fork", true),
  };
  const std::vector<std::uint8_t> cbor = encode_observations(observations);
  const std::vector<std::uint8_t> payload = write_payload(kBuildRef, kHour, kInstallId, cbor, kMsgId);

  const std::vector<std::string> names = write_names(payload, kMsgId, kZone);

  ASSERT_EQ(names.size(), static_cast<std::size_t>(2));

  EXPECT_EQ(names[0],
            "040I6HB7H6LSRRO14D2MF2DBPNNG0UOH248H28H28CPO8H2LALALALALGI272QJ."
            "25PPM2RJ4C9NNGNR5EDHM2S35CHNN0PBE03QO8QRAC8N6CSQVE1GN8Q3JCPGM6O."
            "R5EDPG10BN5T0N0S3CD5HM2T39DTN76BQ3F5I6IO9EC5O7113BD9H2SPJJBTO62."
            "06D3OKF70017C."
            "rsp.test");

  EXPECT_EQ(names[1],
            "EHK76P3JEHGN8043ESNK2S3GDHKM6OBKD5NMSSPF8DSM8QB15PGN0S375TH6IRH."
            "FEDK6EBRMC5P2UQJ2GHL6KOHECPNN4QQVDTLM8PJFE9LG1TCMTTO2M."
            "06D3OKF70414I."
            "rsp.test");
}

TEST(DnsFrame, writeNames_whenEmptyPayload_returnsEmpty) {
  const std::vector<std::uint8_t> empty;
  const std::vector<std::string> names = write_names(empty, kMsgId, kZone);
  EXPECT_EQ(names.size(), static_cast<std::size_t>(0));
}

TEST(DnsFrame, writeNames_whenPayloadTooLarge_returnsEmpty) {
  const std::vector<std::uint8_t> huge((static_cast<std::size_t>(kChunkBytes) * kMaxChunks) + 1, 0x00);
  const std::vector<std::string> names = write_names(huge, kMsgId, kZone);
  EXPECT_EQ(names.size(), static_cast<std::size_t>(0));
}

TEST(DnsFrame, writeNames_whenEmptyZone_returnsEmpty) {
  const std::vector<std::uint8_t> payload = golden_payload();
  const std::vector<std::string> names = write_names(payload, kMsgId, "");
  EXPECT_EQ(names.size(), static_cast<std::size_t>(0));
}

TEST(DnsFrame, writeNames_whenZoneHasLeadingDot_returnsEmpty) {
  const std::vector<std::uint8_t> payload = golden_payload();
  const std::vector<std::string> names = write_names(payload, kMsgId, ".rsp.test");
  EXPECT_EQ(names.size(), static_cast<std::size_t>(0));
}

TEST(DnsFrame, writeNames_whenZoneHasTrailingDot_returnsEmpty) {
  const std::vector<std::uint8_t> payload = golden_payload();
  const std::vector<std::string> names = write_names(payload, kMsgId, "rsp.test.");
  EXPECT_EQ(names.size(), static_cast<std::size_t>(0));
}

TEST(DnsFrame, writeNames_whenZoneLabelTooLong_returnsEmpty) {
  const std::vector<std::uint8_t> payload = golden_payload();
  const std::string long_label(64, 'a');
  const std::vector<std::string> names = write_names(payload, kMsgId, long_label + ".test");
  EXPECT_EQ(names.size(), static_cast<std::size_t>(0));
}

TEST(DnsFrame, writeNames_whenZoneWireSizeTooLarge_returnsEmpty) {
  const std::vector<std::uint8_t> payload = golden_payload();
  // 9 labels of 5 chars each: wire size = 9 * (1 + 5) = 54 > kMaxZoneBytes (48).
  const std::vector<std::string> names =
      write_names(payload, kMsgId, "aaaaa.bbbbb.ccccc.ddddd.eeeee.fffff.ggggg.hhhhh.iiiii");
  EXPECT_EQ(names.size(), static_cast<std::size_t>(0));
}

}  // namespace
}  // namespace rasp::reporting
