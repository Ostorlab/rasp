/// Tests for spki_of: the public keys of real RSA and EC certificates, a version 1 certificate, and every way the DER
/// can be cut short or malformed.

#include "der.h"

#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <span>
#include <vector>

#include "fixture.h"

namespace rasp::plugins::adr_pin {
namespace {

/// The tag of a SEQUENCE.
constexpr std::uint8_t kSequence = 0x30;
/// The tag of an INTEGER.
constexpr std::uint8_t kInteger = 0x02;

/// A placeholder content for the fields the walk skips.
const std::vector<std::uint8_t> kFiller{0x01, 0x02};

/// A key element, distinct from the fields around it.
const std::vector<std::uint8_t> kKey = element(kSequence, std::vector<std::uint8_t>{0xaa, 0xbb, 0xcc});

/// A certificate built by hand around `tbs_fields`, the content of its tbsCertificate.
///
/// @param tbs_fields The tbsCertificate's fields.
/// @return The certificate's DER, with a signature algorithm and a signature after the tbsCertificate.
[[nodiscard]] std::vector<std::uint8_t> certificate(const std::vector<std::uint8_t>& tbs_fields) {
  return element(kSequence,
                 join({element(kSequence, tbs_fields), element(kSequence, kFiller), element(0x03, kFiller)}));
}

/// The fields of a version 3 tbsCertificate, with `key` as its SubjectPublicKeyInfo.
///
/// @param key The SubjectPublicKeyInfo element.
/// @return The fields.
[[nodiscard]] std::vector<std::uint8_t> v3_fields(const std::vector<std::uint8_t>& key) {
  return join({
      element(0xa0, element(kInteger, std::vector<std::uint8_t>{0x02})),
      element(kInteger, kFiller),
      element(kSequence, kFiller),
      element(kSequence, kFiller),
      element(kSequence, kFiller),
      element(kSequence, kFiller),
      key,
      element(0xa3, kFiller),
  });
}

/// Whether `found` holds exactly the bytes of `expected`.
///
/// @param found What spki_of returned.
/// @param expected The expected bytes.
/// @return `true` when they are equal.
[[nodiscard]] bool same(const std::optional<std::span<const std::uint8_t>>& found,
                        const std::vector<std::uint8_t>& expected) {
  return found.has_value() && std::vector<std::uint8_t>(found->begin(), found->end()) == expected;
}

TEST(Der, spkiOf_whenRsaCertificate_returnsTheKeyOpensslExtracts) {
  const std::vector<std::uint8_t> der = read_fixture("rsa.der");
  ASSERT_FALSE(der.empty());

  EXPECT_TRUE(same(spki_of(der), read_fixture("rsa.spki.der")));
}

TEST(Der, spkiOf_whenEcCertificate_returnsTheKeyOpensslExtracts) {
  const std::vector<std::uint8_t> der = read_fixture("ec.der");
  ASSERT_FALSE(der.empty());

  EXPECT_TRUE(same(spki_of(der), read_fixture("ec.spki.der")));
}

TEST(Der, spkiOf_whenVersion3CertificateBuiltByHand_returnsTheKey) {
  EXPECT_TRUE(same(spki_of(certificate(v3_fields(kKey))), kKey));
}

TEST(Der, spkiOf_whenVersion1CertificateWithoutTheVersionField_returnsTheKey) {
  const std::vector<std::uint8_t> fields = join({
      element(kInteger, kFiller),
      element(kSequence, kFiller),
      element(kSequence, kFiller),
      element(kSequence, kFiller),
      element(kSequence, kFiller),
      kKey,
  });

  EXPECT_TRUE(same(spki_of(certificate(fields)), kKey));
}

TEST(Der, spkiOf_whenCertificateIsCutAtAnyByte_returnsNothing) {
  const std::vector<std::uint8_t> der = read_fixture("rsa.der");
  ASSERT_FALSE(der.empty());

  for (std::size_t size = 0; size < der.size(); ++size) {
    EXPECT_FALSE(spki_of(std::span(der).first(size)).has_value()) << "cut at " << size;
  }
}

TEST(Der, spkiOf_whenBytesFollowTheCertificate_returnsNothing) {
  std::vector<std::uint8_t> der = read_fixture("ec.der");
  der.push_back(0x00);

  EXPECT_FALSE(spki_of(der).has_value());
}

TEST(Der, spkiOf_whenInputIsEmpty_returnsNothing) { EXPECT_FALSE(spki_of({}).has_value()); }

TEST(Der, spkiOf_whenFirstElementIsNotASequence_returnsNothing) {
  std::vector<std::uint8_t> der = certificate(v3_fields(kKey));
  der[0] = 0x31;

  EXPECT_FALSE(spki_of(der).has_value());
}

TEST(Der, spkiOf_whenLengthIsIndefinite_returnsNothing) {
  const std::vector<std::uint8_t> der{kSequence, 0x80, kSequence, 0x00, 0x00, 0x00};

  EXPECT_FALSE(spki_of(der).has_value());
}

TEST(Der, spkiOf_whenLengthTakesFiveBytes_returnsNothing) {
  const std::vector<std::uint8_t> der{kSequence, 0x85, 0x00, 0x00, 0x00, 0x00, 0x02, kSequence, 0x00};

  EXPECT_FALSE(spki_of(der).has_value());
}

TEST(Der, spkiOf_whenLengthGoesPastTheEnd_returnsNothing) {
  const std::vector<std::uint8_t> der{kSequence, 0x84, 0xff, 0xff, 0xff, 0xff, kSequence, 0x00};

  EXPECT_FALSE(spki_of(der).has_value());
}

TEST(Der, spkiOf_whenTagTakesSeveralBytes_returnsNothing) {
  const std::vector<std::uint8_t> der{0x3f, 0x81, 0x00};

  EXPECT_FALSE(spki_of(der).has_value());
}

TEST(Der, spkiOf_whenSerialNumberIsNotAnInteger_returnsNothing) {
  const std::vector<std::uint8_t> fields = join({
      element(kSequence, kFiller),
      element(kSequence, kFiller),
      element(kSequence, kFiller),
      element(kSequence, kFiller),
      element(kSequence, kFiller),
      kKey,
  });

  EXPECT_FALSE(spki_of(certificate(fields)).has_value());
}

TEST(Der, spkiOf_whenTheKeyIsMissing_returnsNothing) {
  const std::vector<std::uint8_t> fields = join({
      element(kInteger, kFiller),
      element(kSequence, kFiller),
      element(kSequence, kFiller),
      element(kSequence, kFiller),
      element(kSequence, kFiller),
  });

  EXPECT_FALSE(spki_of(certificate(fields)).has_value());
}

TEST(Der, spkiOf_whenTheKeyIsNotASequence_returnsNothing) {
  const std::vector<std::uint8_t> key = element(0x03, kFiller);

  EXPECT_FALSE(spki_of(certificate(v3_fields(key))).has_value());
}

}  // namespace
}  // namespace rasp::plugins::adr_pin
