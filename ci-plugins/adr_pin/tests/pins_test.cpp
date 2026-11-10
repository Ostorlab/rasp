/// Tests for observe and pin_of: every handshake outcome, the chain's order and cap, a certificate whose pin can't be
/// computed, and, on Apple platforms, the real SHA-256 against the pins openssl computes.

#include "pins.h"

#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "base64.h"
#include "fixture.h"
#include "handshake.h"
#include "rasp/observation.h"

namespace rasp::plugins::adr_pin {
namespace {

/// A stand-in for SHA-256: a digest whose 32 bytes are all the low byte of the input's size, so keys of different
/// sizes get different pins.
///
/// @param bytes The bytes.
/// @return The digest.
[[nodiscard]] std::optional<Digest> size_hash(std::span<const std::uint8_t> bytes) {
  Digest digest{};
  digest.fill(static_cast<std::uint8_t>(bytes.size()));
  return digest;
}

/// A SHA-256 that always fails.
///
/// @param bytes The bytes, unused.
/// @return Nothing.
[[nodiscard]] std::optional<Digest> failing_hash(std::span<const std::uint8_t> bytes) {
  static_cast<void>(bytes);
  return std::nullopt;
}

/// The pin size_hash gives to a key of `key_size` bytes.
///
/// @param key_size The size of the SubjectPublicKeyInfo.
/// @return The pin.
[[nodiscard]] std::string size_pin(std::size_t key_size) {
  Digest digest{};
  digest.fill(static_cast<std::uint8_t>(key_size));
  return "sha256/" + base64(digest);
}

/// A handshake that read `chain`.
///
/// @param chain The chain, leaf first.
/// @param trusted Whether the system trusted it.
/// @return The handshake.
[[nodiscard]] Handshake read(std::vector<std::vector<std::uint8_t>> chain, bool trusted) {
  return Handshake{.outcome = Outcome::kRead, .chain = std::move(chain), .trusted = trusted};
}

TEST(Pins, observe_whenChainWasRead_reportsEachPinLeafFirstAndTheTrust) {
  const std::vector<std::uint8_t> rsa = read_fixture("rsa.der");
  const std::vector<std::uint8_t> ec = read_fixture("ec.der");

  const std::vector<Observation> observations = observe(read({ec, rsa}, true), size_hash);

  const std::vector<std::string> pins{
      size_pin(read_fixture("ec.spki.der").size()),
      size_pin(read_fixture("rsa.spki.der").size()),
  };
  EXPECT_EQ(observations, (std::vector<Observation>{observed("mitm.adr_pin", "network_framework", pins),
                                                    observed("mitm.adr_trusted", "sec_trust", true)}));
}

TEST(Pins, observe_whenSystemDidNotTrustTheChain_reportsTheKeysAndFalse) {
  const std::vector<Observation> observations = observe(read({read_fixture("ec.der")}, false), size_hash);

  ASSERT_EQ(observations.size(), 2U);
  EXPECT_EQ(observations[0].status, Status::kOk);
  EXPECT_EQ(observations[1], observed("mitm.adr_trusted", "sec_trust", false));
}

TEST(Pins, observe_whenChainHoldsExactlyTheCap_reportsEveryPin) {
  const std::vector<std::vector<std::uint8_t>> chain(kMaxCertificates, read_fixture("ec.der"));

  const std::vector<Observation> observations = observe(read(chain, true), size_hash);

  ASSERT_EQ(observations[0].status, Status::kOk);
  EXPECT_EQ(std::get<std::vector<std::string>>(observations[0].value).size(), kMaxCertificates);
}

TEST(Pins, observe_whenChainIsLongerThanTheCap_reportsTheFirstCertificatesOnly) {
  std::vector<std::vector<std::uint8_t>> chain(kMaxCertificates, read_fixture("ec.der"));
  chain.push_back(read_fixture("rsa.der"));

  const std::vector<Observation> observations = observe(read(chain, true), size_hash);

  ASSERT_EQ(observations[0].status, Status::kOk);
  const auto& pins = std::get<std::vector<std::string>>(observations[0].value);
  ASSERT_EQ(pins.size(), kMaxCertificates);
  EXPECT_EQ(pins.back(), size_pin(read_fixture("ec.spki.der").size()));
}

TEST(Pins, observe_whenACertificateIsNotACertificate_reportsThePinsAsAnErrorAndStillTheTrust) {
  const std::vector<Observation> observations = observe(read({read_fixture("ec.der"), {0x30, 0x00}}, true), size_hash);

  EXPECT_EQ(observations, (std::vector<Observation>{failed("mitm.adr_pin", "network_framework"),
                                                    observed("mitm.adr_trusted", "sec_trust", true)}));
}

TEST(Pins, observe_whenACertificateIsEmpty_reportsThePinsAsAnError) {
  const std::vector<Observation> observations = observe(read({read_fixture("ec.der"), {}}, true), size_hash);

  EXPECT_EQ(observations[0], failed("mitm.adr_pin", "network_framework"));
}

TEST(Pins, observe_whenTheHashFails_reportsThePinsAsAnError) {
  const std::vector<Observation> observations = observe(read({read_fixture("ec.der")}, true), failing_hash);

  EXPECT_EQ(observations[0], failed("mitm.adr_pin", "network_framework"));
}

TEST(Pins, observe_whenChainIsEmpty_reportsThePinsAsAnError) {
  const std::vector<Observation> observations = observe(read({}, true), size_hash);

  EXPECT_EQ(observations[0], failed("mitm.adr_pin", "network_framework"));
}

TEST(Pins, observe_whenHandshakeTimedOut_reportsTwoTimeouts) {
  const std::vector<Observation> observations =
      observe(Handshake{.outcome = Outcome::kTimeout, .chain = {}, .trusted = false}, size_hash);

  EXPECT_EQ(
      observations,
      (std::vector<Observation>{
          Observation{.signal = "mitm.adr_pin", .source = "network_framework", .status = Status::kTimeout, .value = {}},
          Observation{.signal = "mitm.adr_trusted", .source = "sec_trust", .status = Status::kTimeout, .value = {}}}));
}

TEST(Pins, observe_whenHandshakeFailed_reportsTwoErrors) {
  const std::vector<Observation> observations =
      observe(Handshake{.outcome = Outcome::kFailed, .chain = {}, .trusted = false}, size_hash);

  EXPECT_EQ(observations, (std::vector<Observation>{failed("mitm.adr_pin", "network_framework"),
                                                    failed("mitm.adr_trusted", "sec_trust")}));
}

TEST(Pins, observe_whenHandshakeCannotRunHere_reportsTwoUnsupported) {
  const std::vector<Observation> observations =
      observe(Handshake{.outcome = Outcome::kUnsupported, .chain = {}, .trusted = false}, size_hash);

  EXPECT_EQ(observations, (std::vector<Observation>{unsupported("mitm.adr_pin", "network_framework"),
                                                    unsupported("mitm.adr_trusted", "sec_trust")}));
}

TEST(Pins, pinOf_whenNotACertificate_returnsNothing) {
  const std::vector<std::uint8_t> bytes{0x01, 0x02, 0x03};

  EXPECT_FALSE(pin_of(bytes, size_hash).has_value());
}

#ifdef __APPLE__
TEST(Pins, sha256_whenAbc_returnsTheFips180Digest) {
  const std::vector<std::uint8_t> abc{'a', 'b', 'c'};

  const std::optional<Digest> digest = sha256(abc);

  ASSERT_TRUE(digest.has_value());
  EXPECT_EQ(base64(*digest), "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=");
}

TEST(Pins, pinOf_whenRealCertificates_matchesThePinsOpensslComputes) {
  EXPECT_EQ(pin_of(read_fixture("rsa.der"), sha256), "sha256/8pzafNBHOcmmxO1FVhZefwpKgM6rvFEF/15v6TzdmyU=");
  EXPECT_EQ(pin_of(read_fixture("ec.der"), sha256), "sha256/ADmIk0UJHzSCbrga0xEnzkwbrsKM2t0ptysA8P6yFWU=");
}
#else
TEST(Pins, sha256_whenNotOnAnApplePlatform_returnsNothing) {
  const std::vector<std::uint8_t> abc{'a', 'b', 'c'};

  EXPECT_FALSE(sha256(abc).has_value());
}
#endif

}  // namespace
}  // namespace rasp::plugins::adr_pin
