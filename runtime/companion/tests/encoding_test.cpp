/// Frozen independent vectors and adversarial byte encodings, not implementation-derived expectations.
#include "encoding.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <gtest/gtest.h>
#include <memory>
#include <psa/crypto.h>
#include <span>

#include "golden.h"
#include "platform.h"
#include "rasp/scoped_key.h"
#include "support.h"

namespace {
TEST(ScopedEncoding, encode_whenFrozenPublicInputs_matchEveryIndependentGoldenByte) {
  ASSERT_EQ(psa_crypto_init(), PSA_SUCCESS);
  auto client = fixture::config();
  auto& space = client.namespaces[0];
  std::memcpy(std::span(space.namespace_name).data(), "receipts", 8);
  space.backend_requirement = 2;
  space.auth_requirement = 2;
  space.lock_requirement = 2;
  for (std::size_t index = 0; index < 32; ++index) {
    std::span(space.expected_policy_sha256)[index] = static_cast<std::uint8_t>(index);
  }
  rasp::keys::Application application{};
  application.length = 19;
  std::memcpy(application.name.data(), "co.ostorlab.fixture", 19);
  auto scratch = std::make_unique<std::array<std::uint8_t, 8192>>();
  const auto size = rasp::keys::profile_bytes(application, client, space, *scratch);
  EXPECT_EQ(size, 184U);
  const auto expected = fixture::unhex(fixture::kProfileHex);
  EXPECT_TRUE(std::ranges::equal(std::span(*scratch).first(size), expected));
  RaspScopedKeyInfoV1 key{};
  ASSERT_TRUE(rasp::keys::digest(std::span(*scratch).first(size), key.profile_sha256));
  EXPECT_TRUE(std::ranges::equal(key.profile_sha256, fixture::unhex(fixture::kProfileSha256)));
  const auto point = fixture::unhex(
      "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315e"
      "cecbb6406837bf51f5");
  std::ranges::copy(point, std::span(key.public_key_x963).begin());
  auto sign = std::make_unique<RaspScopedKeySignInputV1>();
  for (std::size_t index = 0; index < 16; ++index) {
    std::span(key.key_id.bytes)[index] = static_cast<std::uint8_t>(index + 16);
    std::span(sign->transaction_id)[index] = static_cast<std::uint8_t>(index + 32);
  }
  for (std::size_t index = 0; index < 32; ++index) {
    std::span(sign->challenge)[index] = static_cast<std::uint8_t>(index + 160);
  }
  sign->audience_length = 16;
  std::memcpy(std::span(sign->audience).data(), "receipts.example", 16);
  constexpr std::string_view kTransaction = R"({"amount_minor":1234,"currency":"USD"})";
  sign->transaction_length = static_cast<std::uint32_t>(kTransaction.size());
  std::memcpy(std::span(sign->transaction).data(), kTransaction.data(), kTransaction.size());
  const auto message_size = rasp::keys::message_bytes(application, client, space, key, *sign, *scratch);
  EXPECT_EQ(message_size, 391U);
  EXPECT_TRUE(std::ranges::equal(std::span(*scratch).first(message_size), fixture::unhex(fixture::kMessageHex)));
  std::array<std::uint8_t, 32> digest{};
  ASSERT_TRUE(rasp::keys::digest(std::span(*scratch).first(message_size), digest));
  EXPECT_TRUE(std::ranges::equal(digest, fixture::unhex(fixture::kMessageSha256)));
  EXPECT_EQ(rasp::keys::message_bytes(application, client, space, key, *sign, std::span(*scratch).first(390)), 0U);
}
TEST(ScopedEncoding, validate_whenUnknownEnumsOrNonzeroTails_rejectsRatherThanDowngrades) {
  const auto valid = fixture::config();
  ASSERT_TRUE(rasp::keys::valid_spec(valid));
  for (const auto value : {0U, 4U, UINT32_MAX}) {
    auto changed = valid;
    changed.namespaces[0].backend_requirement = value;
    EXPECT_FALSE(rasp::keys::valid_spec(changed));
  }
  auto changed = valid;
  changed.namespaces[1].selector = 1;
  EXPECT_FALSE(rasp::keys::valid_spec(changed));
  changed = valid;
  changed.namespaces[0].reserved[0] = 1;
  EXPECT_FALSE(rasp::keys::valid_spec(changed));
  changed = valid;
  changed.signing_scope[119] = 1;
  EXPECT_FALSE(rasp::keys::valid_spec(changed));
  changed = valid;
  changed.namespaces[0].gate_mode = 0;
  EXPECT_FALSE(rasp::keys::valid_spec(changed));
}
TEST(ScopedEncoding, utf8_whenOverlongSurrogateOrControl_isNeverNormalizedIntoAnIdentifier) {
  for (const auto* const value : {"00", "1f", "7f", "c080", "eda080", "f4908080", "c280", "e08080", "f0808080"}) {
    EXPECT_FALSE(rasp::keys::utf8(fixture::unhex(value)));
  }
  EXPECT_TRUE(rasp::keys::utf8(fixture::unhex("c3a9")));
}
TEST(ScopedEncoding, signature_whenNonminimalNegativeZeroOrOrder_rejectsInvalidDer) {
  for (const auto* const value : {
           "3006020100020101",
           "300702020001020101",
           "3006020180020101",
           "3006020101020100",
           "308106020101020101",
           "300602010102010100",
       }) {
    EXPECT_FALSE(rasp::keys::valid_signature(fixture::unhex(value)));
  }
  EXPECT_TRUE(rasp::keys::valid_signature(fixture::unhex("3006020101020101")));
}
}  // namespace
namespace {
TEST(ScopedEncoding, point_whenCanonicalGeneratorOrMutatedCoordinates_checksActualCurveAndFieldBounds) {
  const auto bytes = fixture::unhex(
      "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315e"
      "cecbb6406837bf51f5");
  std::array<std::uint8_t, 65> original{};
  std::ranges::copy(bytes, original.begin());
  ASSERT_TRUE(rasp::keys::valid_point(original));
  for (std::size_t i = 0; i < original.size(); ++i) {
    auto changed = original;
    std::span(changed)[i] ^= std::uint8_t{1};
    EXPECT_FALSE(rasp::keys::valid_point(changed)) << i;
  }
  auto noncanonical = original;
  const auto prime = fixture::unhex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
  std::ranges::copy(prime, std::span(noncanonical).subspan(1).begin());
  EXPECT_FALSE(rasp::keys::valid_point(noncanonical));
  noncanonical = {};
  noncanonical[0] = 4;
  EXPECT_FALSE(rasp::keys::valid_point(noncanonical));
}
TEST(ScopedEncoding, diagnostic_whenClosedFieldsAreInvalid_neverTreatsThemAsAnActualOsCode) {
  rasp::keys::PlatformDiagnostic diagnostic;
  EXPECT_TRUE(rasp::keys::valid_diagnostic(diagnostic));
  diagnostic.error.numeric_code = 1;
  EXPECT_FALSE(rasp::keys::valid_diagnostic(diagnostic));
  diagnostic = {};
  diagnostic.present = 1;
  diagnostic.error.platform = RASP_SK_PLATFORM_ANDROID;
  diagnostic.error.domain = RASP_SK_ANDROID_JCA_ERROR;
  EXPECT_TRUE(rasp::keys::valid_diagnostic(diagnostic));
  diagnostic.error.numeric_code = -1;
  EXPECT_FALSE(rasp::keys::valid_diagnostic(diagnostic));
  diagnostic.error.numeric_code_present = 1;
  EXPECT_TRUE(rasp::keys::valid_diagnostic(diagnostic));
  diagnostic.error.reserved = 1;
  EXPECT_FALSE(rasp::keys::valid_diagnostic(diagnostic));
}
}  // namespace
