/// Tests for the APK reader: the stored-entry reader and the signing-certificate reader over the APK Signing Block.

#include "apk/archive.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#include "rasp/util/read_file.h"
#include "support/files.h"
#include "support/zip.h"
#include "util/signing_certificates.h"

namespace rasp::android::apk {
namespace {

using test_support::TemporaryDirectory;
using test_support::write_file;
using test_support::zip_with_stored_entry;
using test_support::zip_detail::append_le;
using test_support::zip_detail::Field;

/// The id of the APK Signature Scheme v2 block.
constexpr std::uint32_t kV2 = 0x7109871aU;
/// The id of the APK Signature Scheme v3.1 block.
constexpr std::uint32_t kV31 = 0x1b93ad61U;
/// The id of the APK Signature Scheme v3 block.
constexpr std::uint32_t kV3 = 0xf05368c0U;
/// The id of the verity padding block apksigner adds, which the reader skips.
constexpr std::uint32_t kPadding = 0x42726577U;
/// The size of the End Of Central Directory record the zip builder writes.
constexpr std::size_t kEndSize = 22;
/// The offset of the central directory's offset in the End Of Central Directory record.
constexpr std::size_t kDirectoryOffsetField = 16;
/// The highest API level a v3 signer can name, which apksigner writes for "every later version".
constexpr std::uint32_t kAnyLaterLevel = 0x7fffffffU;
/// The API level of Android 12, the runtime's minimum.
constexpr std::uint32_t kAndroid12 = 31;
/// The API level of Android 16.
constexpr std::uint32_t kAndroid16 = 36;

/// `value` after its 32-bit little-endian length.
[[nodiscard]] std::string prefixed(std::string_view value) {
  std::string out;
  append_le(out, Field{.value = value.size(), .width = 4});
  out.append(value);
  return out;
}

/// A v3 or v3.1 signer: its certificate and the range of API levels it applies to.
struct V3Signer {
  /// The signer's only certificate.
  std::string_view certificate;
  /// The lowest API level the signer applies to.
  std::uint32_t min_level = 0;
  /// The highest API level the signer applies to.
  std::uint32_t max_level = kAnyLaterLevel;
};

/// The signed data of a signer whose only certificate is `certificate`.
[[nodiscard]] std::string signed_data(std::string_view certificate) {
  return prefixed("digests") + prefixed(prefixed(certificate)) + prefixed("attributes");
}

/// The value of a v2 block with one signer whose only certificate is `certificate`.
[[nodiscard]] std::string v2_scheme(std::string_view certificate) {
  return prefixed(prefixed(prefixed(signed_data(certificate)) + prefixed("signatures") + prefixed("public key")));
}

/// The value of a v3 or v3.1 block holding `signers`, in order.
[[nodiscard]] std::string v3_scheme(std::initializer_list<V3Signer> signers) {
  std::string all;
  for (const V3Signer& signer : signers) {
    std::string range;
    append_le(range, Field{.value = signer.min_level, .width = 4});
    append_le(range, Field{.value = signer.max_level, .width = 4});
    all +=
        prefixed(prefixed(signed_data(signer.certificate)) + range + prefixed("signatures") + prefixed("public key"));
  }
  return prefixed(all);
}

/// One id-value pair of an APK Signing Block.
[[nodiscard]] std::string pair(std::uint32_t id, std::string_view value) {
  std::string out;
  append_le(out, Field{.value = 4 + value.size(), .width = 8});
  append_le(out, Field{.value = id, .width = 4});
  out.append(value);
  return out;
}

/// An APK Signing Block holding `pairs`, with its size before the pairs set to `header_size` when given.
[[nodiscard]] std::string signing_block(std::string_view pairs, std::optional<std::uint64_t> header_size = {},
                                        std::string_view magic = "APK Sig Block 42") {
  const std::uint64_t size = pairs.size() + 24;
  std::string out;
  append_le(out, Field{.value = header_size.value_or(size), .width = 8});
  out.append(pairs);
  append_le(out, Field{.value = size, .width = 8});
  out.append(magic);
  return out;
}

/// An APK with one stored entry, and `block` between its entries and its central directory, as apksigner writes it.
[[nodiscard]] std::string signed_apk(std::string_view block) {
  std::string apk = zip_with_stored_entry("classes.dex", "dex");
  const std::size_t field = apk.size() - kEndSize + kDirectoryOffsetField;
  std::uint32_t directory_offset = 0;
  for (std::size_t index = 0; index < 4; ++index) {
    directory_offset |= static_cast<std::uint32_t>(static_cast<std::uint8_t>(apk[field + index])) << (8U * index);
  }
  apk.insert(directory_offset, block);
  std::string moved;
  append_le(moved, Field{.value = directory_offset + block.size(), .width = 4});
  apk.replace(field + block.size(), 4, moved);
  return apk;
}

/// `text` as bytes.
[[nodiscard]] std::vector<std::uint8_t> bytes_of(std::string_view text) { return {text.begin(), text.end()}; }

/// The certificate find_signing_certificate finds in `apk` for a device at `api_level`.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> certificate_of(std::string_view apk,
                                                                      std::uint32_t api_level = kAndroid16) {
  return find_signing_certificate(bytes_of(apk), api_level);
}

TEST(Archive, findSigningCertificate_whenSignedWithV2_returnsTheSignersCertificate) {
  const std::string apk = signed_apk(signing_block(pair(kV2, v2_scheme("v2 certificate"))));

  EXPECT_EQ(certificate_of(apk), bytes_of("v2 certificate"));
}

TEST(Archive, findSigningCertificate_whenSignedWithV2AndV3_returnsTheV3Certificate) {
  const std::string apk = signed_apk(signing_block(pair(kV2, v2_scheme("v2 certificate")) +
                                                   pair(kV3, v3_scheme({{.certificate = "v3 certificate"}}))));

  EXPECT_EQ(certificate_of(apk), bytes_of("v3 certificate"));
}

TEST(Archive, findSigningCertificate_whenTheKeyWasRotated_returnsTheNewKeyWhereV31Applies) {
  const std::string apk =
      signed_apk(signing_block(pair(kV3, v3_scheme({{.certificate = "old key", .min_level = 24, .max_level = 32}})) +
                               pair(kV31, v3_scheme({{.certificate = "new key", .min_level = 33}}))));

  EXPECT_EQ(certificate_of(apk, kAndroid16), bytes_of("new key"));
}

TEST(Archive, findSigningCertificate_whenTheKeyWasRotated_returnsTheOldKeyBelowWhereV31Applies) {
  const std::string apk =
      signed_apk(signing_block(pair(kV3, v3_scheme({{.certificate = "old key", .min_level = 24, .max_level = 32}})) +
                               pair(kV31, v3_scheme({{.certificate = "new key", .min_level = 33}}))));

  EXPECT_EQ(certificate_of(apk, kAndroid12), bytes_of("old key"));
}

TEST(Archive, findSigningCertificate_whenV31CoversADeviceBelowAndroid13_usesTheV3Certificate) {
  // The v3.1 signer's range reaches below Android 13 (API 33), but the platform honors the v3.1 block only from there.
  const std::string apk = signed_apk(signing_block(pair(kV3, v3_scheme({{.certificate = "v3 key"}})) +
                                                   pair(kV31, v3_scheme({{.certificate = "v31 key"}}))));

  EXPECT_EQ(certificate_of(apk, kAndroid12), bytes_of("v3 key"));
  EXPECT_EQ(certificate_of(apk, 33), bytes_of("v31 key"));
}

TEST(Archive, findSigningCertificate_whenV3HasSignersForSeveralRanges_returnsTheOneForTheDevice) {
  const std::string apk =
      signed_apk(signing_block(pair(kV3, v3_scheme({
                                             {.certificate = "older", .min_level = 24, .max_level = 30},
                                             {.certificate = "current", .min_level = 31},
                                         }))));

  EXPECT_EQ(certificate_of(apk, kAndroid12), bytes_of("current"));
}

TEST(Archive, findSigningCertificate_whenNoV3SignerAppliesToTheDevice_returnsTheV2Certificate) {
  const std::string apk = signed_apk(
      signing_block(pair(kV2, v2_scheme("v2 certificate")) +
                    pair(kV3, v3_scheme({{.certificate = "v3 certificate", .min_level = 24, .max_level = 30}}))));

  EXPECT_EQ(certificate_of(apk, kAndroid12), bytes_of("v2 certificate"));
}

TEST(Archive, findSigningCertificate_whenAV3SignerHasNoLevelRange_returnsNothing) {
  const std::string apk =
      signed_apk(signing_block(pair(kV3, prefixed(prefixed(prefixed(signed_data("v3 certificate")))))));

  EXPECT_EQ(certificate_of(apk), std::nullopt);
}

TEST(Archive, findSigningCertificate_whenTheBlockHasOtherPairs_skipsThem) {
  const std::string apk =
      signed_apk(signing_block(pair(kPadding, std::string(16, '\0')) + pair(kV2, v2_scheme("v2 certificate"))));

  EXPECT_EQ(certificate_of(apk), bytes_of("v2 certificate"));
}

TEST(Archive, findSigningCertificate_whenTheApkHasNoSigningBlock_returnsNothing) {
  EXPECT_EQ(certificate_of(zip_with_stored_entry("classes.dex", "dex")), std::nullopt);
}

TEST(Archive, findSigningCertificate_whenTheBlockHasNeitherV2NorV3_returnsNothing) {
  const std::string apk = signed_apk(signing_block(pair(kPadding, std::string(16, '\0'))));

  EXPECT_EQ(certificate_of(apk), std::nullopt);
}

TEST(Archive, findSigningCertificate_whenTheMagicIsWrong_returnsNothing) {
  const std::string apk = signed_apk(signing_block(pair(kV2, v2_scheme("v2 certificate")), {}, "APK Sig Block 41"));

  EXPECT_EQ(certificate_of(apk), std::nullopt);
}

TEST(Archive, findSigningCertificate_whenTheTwoSizesDiffer_returnsNothing) {
  const std::string pairs = pair(kV2, v2_scheme("v2 certificate"));
  const std::string apk = signed_apk(signing_block(pairs, pairs.size() + 23));

  EXPECT_EQ(certificate_of(apk), std::nullopt);
}

TEST(Archive, findSigningCertificate_whenACertificateLengthRunsPastItsList_returnsNothing) {
  std::string certificates;
  append_le(certificates, Field{.value = 1000, .width = 4});
  certificates.append("short");
  const std::string signed_data = prefixed("digests") + prefixed(certificates);
  const std::string apk = signed_apk(signing_block(pair(kV2, prefixed(prefixed(prefixed(signed_data))))));

  EXPECT_EQ(certificate_of(apk), std::nullopt);
}

TEST(Archive, findSigningCertificate_whenACertificateIsEmpty_returnsNothing) {
  const std::string apk = signed_apk(signing_block(pair(kV2, v2_scheme(""))));

  EXPECT_EQ(certificate_of(apk), std::nullopt);
}

TEST(Archive, findSigningCertificate_whenAValidPairIsFollowedByAMalformedPair_returnsNothing) {
  std::string pairs = pair(kV2, v2_scheme("v2 certificate"));
  append_le(pairs, Field{.value = 1000, .width = 8});
  append_le(pairs, Field{.value = kV3, .width = 4});
  const std::string apk = signed_apk(signing_block(pairs));

  EXPECT_EQ(certificate_of(apk), std::nullopt);
}

TEST(Archive, findSigningCertificate_whenThePairLengthRunsPastTheBlock_returnsNothing) {
  std::string pairs;
  append_le(pairs, Field{.value = 1000, .width = 8});
  append_le(pairs, Field{.value = kV2, .width = 4});
  const std::string apk = signed_apk(signing_block(pairs));

  EXPECT_EQ(certificate_of(apk), std::nullopt);
}

TEST(Archive, readSigningCertificate_whenGivenASignedApkFile_returnsTheCertificate) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string path = directory.path() + "/base.apk";
  ASSERT_TRUE(write_file(path, signed_apk(signing_block(pair(kV3, v3_scheme({{.certificate = "v3 certificate"}}))))));

  EXPECT_EQ(read_signing_certificate(path, kAndroid16), bytes_of("v3 certificate"));
}

TEST(Archive, readSigningCertificate_whenTheFileIsMissing_returnsNothing) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());

  EXPECT_EQ(read_signing_certificate(directory.path() + "/missing.apk", kAndroid16), std::nullopt);
}

TEST(Archive, readStoredEntry_whenTheApkIsSigned_stillReadsTheEntry) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string path = directory.path() + "/base.apk";
  ASSERT_TRUE(write_file(path, signed_apk(signing_block(pair(kV2, v2_scheme("v2 certificate"))))));

  EXPECT_EQ(read_stored_entry(path, "classes.dex"), bytes_of("dex"));
}

/// Reads a public DER fixture used only for parser and digest tests; private keys are not shipped in this repository.
[[nodiscard]] std::string der_fixture(std::string_view filename) {
  return rasp::util::read_file(std::string(RASP_TEST_CERTIFICATE_DIR) + "/" + std::string(filename), 65536)
      .value_or("");
}

/// Structurally complete digest/signature algorithm record; its dummy signature is intentionally never verified.
[[nodiscard]] std::string algorithm_record() {
  std::string record;
  append_le(record, Field{.value = 0x0201, .width = 4});
  return prefixed(record + prefixed("unverified"));
}

/// Explicit fixture targeting parameters, separate from certificate-chain contents.
struct SignerFixture {
  bool v3 = false;
  std::uint32_t minimum = 31;
  std::uint32_t maximum = kAnyLaterLevel;
  std::string_view attributes;
};

/// Encodes a certificate chain and optional SDK targeting in a complete signer record.
[[nodiscard]] std::string complete_signer(std::initializer_list<std::string_view> chain, SignerFixture options = {}) {
  std::string certificates;
  for (const auto certificate : chain) {
    certificates += prefixed(certificate);
  }
  std::string range;
  if (options.v3) {
    append_le(range, Field{.value = options.minimum, .width = 4});
    append_le(range, Field{.value = options.maximum, .width = 4});
  }
  const std::string data = prefixed(algorithm_record()) + prefixed(certificates) + range + prefixed(options.attributes);
  return prefixed(prefixed(data) + range + prefixed(algorithm_record()) + prefixed("unverified public key"));
}

/// Parses the new complete-set API independently of the legacy first-certificate helper.
[[nodiscard]] SignerCertificates complete_certificates(std::string_view pairs, std::uint32_t api = 34) {
  return find_signing_certificates(bytes_of(signed_apk(signing_block(pairs))), api);
}

TEST(Archive, findSigningCertificates_whenV2HasParallelSigners_returnsEveryLeafAndPreservesLegacyFirst) {
  const auto first = der_fixture("signer_a.der");
  const auto second = der_fixture("signer_b.der");
  ASSERT_FALSE(first.empty());
  ASSERT_FALSE(second.empty());
  const auto pairs = pair(kV2, prefixed(complete_signer({first}) + complete_signer({second})));
  const auto found = complete_certificates(pairs);
  ASSERT_TRUE(found.has_value());
  EXPECT_EQ(*found, (util::Certificates{bytes_of(first), bytes_of(second)}));
  EXPECT_EQ(certificate_of(signed_apk(signing_block(pairs))), bytes_of(first));
}

TEST(Archive, findSigningCertificates_whenSignerHasAChain_returnsOnlyItsLeaf) {
  const auto leaf = der_fixture("signer_a.der");
  const auto issuer = der_fixture("signer_b.der");
  const auto found = complete_certificates(pair(kV2, prefixed(complete_signer({leaf, issuer}))));
  ASSERT_TRUE(found.has_value());
  EXPECT_EQ(*found, (util::Certificates{bytes_of(leaf)}));
}

TEST(Archive, findSigningCertificates_whenSchemesDiffer_usesExactlyThePlatformScheme) {
  const auto old_key = der_fixture("signer_a.der");
  const auto new_key = der_fixture("signer_b.der");
  const auto pairs =
      pair(kV2, prefixed(complete_signer({new_key}))) +
      pair(kV3, prefixed(complete_signer({old_key}, {.v3 = true, .minimum = 31, .maximum = 33, .attributes = ""}))) +
      pair(kV31, prefixed(complete_signer({new_key}, {.v3 = true, .minimum = 34, .attributes = ""})));
  for (const auto api : {31U, 32U, 33U, 34U}) {
    const auto found = complete_certificates(pairs, api);
    ASSERT_TRUE(found.has_value()) << api;
    EXPECT_EQ(*found, (util::Certificates{bytes_of(api == 34 ? new_key : old_key)}));
  }
}

TEST(Archive, findSigningCertificates_whenV3HasDisjointRanges_returnsTheApplicableLeaf) {
  const auto old_key = der_fixture("signer_a.der");
  const auto new_key = der_fixture("signer_b.der");
  const auto pairs =
      pair(kV3, prefixed(complete_signer({old_key}, {.v3 = true, .minimum = 28, .maximum = 30, .attributes = ""}) +
                         complete_signer({new_key}, {.v3 = true, .minimum = 31, .attributes = ""})));
  const auto found = complete_certificates(pairs, 31);
  ASSERT_TRUE(found.has_value());
  EXPECT_EQ(*found, (util::Certificates{bytes_of(new_key)}));
}

TEST(Archive, findSigningCertificates_whenV3HasNoApplicableOrMultipleApplicableSigners_refusesFallback) {
  const auto certificate = der_fixture("signer_a.der");
  const auto v2 = pair(kV2, prefixed(complete_signer({certificate})));
  EXPECT_FALSE(complete_certificates(
      v2 + pair(kV3,
                prefixed(complete_signer({certificate}, {.v3 = true, .minimum = 28, .maximum = 30, .attributes = ""}))),
      31));
  EXPECT_FALSE(
      complete_certificates(v2 + pair(kV3, prefixed(complete_signer({certificate}, {.v3 = true, .attributes = ""}) +
                                                    complete_signer({certificate}, {.v3 = true, .attributes = ""})))));
}

TEST(Archive, findSigningCertificates_whenV2HasTenOrElevenSigners_enforcesPlatformLimit) {
  const auto certificate = der_fixture("signer_a.der");
  std::string signers;
  for (std::size_t count = 0; count < 10; ++count) {
    signers += complete_signer({certificate});
  }
  const auto ten = complete_certificates(pair(kV2, prefixed(signers)));
  ASSERT_TRUE(ten.has_value());
  EXPECT_EQ(ten->size(), 10U);
  EXPECT_FALSE(complete_certificates(pair(kV2, prefixed(signers + complete_signer({certificate})))));
}

TEST(Archive, findSigningCertificates_whenLaterSignerOrChainEntryIsMalformed_refusesPartialSet) {
  const auto certificate = der_fixture("signer_a.der");
  EXPECT_FALSE(complete_certificates(pair(kV2, prefixed(complete_signer({certificate}) + prefixed("short")))));
  EXPECT_FALSE(complete_certificates(pair(kV2, prefixed(complete_signer({certificate, "bad DER"})))));
  EXPECT_FALSE(
      complete_certificates(pair(kV2, prefixed(complete_signer({certificate.substr(0, certificate.size() - 1)})))));
  EXPECT_FALSE(complete_certificates(pair(kV2, prefixed(complete_signer({""})))));
  EXPECT_FALSE(complete_certificates(pair(kV2, prefixed(complete_signer({std::string(65537, 'x')})))));
}

TEST(Archive, findSigningCertificates_whenChainCountExceedsLimit_refusesTheSigner) {
  const auto certificate = der_fixture("signer_a.der");
  std::string chain;
  for (std::size_t count = 0; count < 33; ++count) {
    chain += prefixed(certificate);
  }
  const auto data = prefixed(algorithm_record()) + prefixed(chain) + prefixed("");
  EXPECT_FALSE(complete_certificates(
      pair(kV2, prefixed(prefixed(prefixed(data) + prefixed(algorithm_record()) + prefixed("key"))))));
}

TEST(Archive, findSigningCertificates_whenDuplicateSchemeOrTrailingPairIsMalformed_refusesAll) {
  const auto certificate = der_fixture("signer_a.der");
  const auto scheme = pair(kV2, prefixed(complete_signer({certificate})));
  EXPECT_FALSE(complete_certificates(scheme + scheme));
  EXPECT_FALSE(complete_certificates(scheme + "bad"));
  EXPECT_FALSE(complete_certificates(scheme + pair(kPadding, std::string(1048576, 'x'))));
}

TEST(Archive, findSigningCertificates_whenDevelopmentRotationIsPresent_reportsUnsupported) {
  const auto certificate = der_fixture("signer_a.der");
  std::string attribute;
  append_le(attribute, Field{.value = 0xc2a6b3baU, .width = 4});
  const auto pairs =
      pair(kV3, prefixed(complete_signer({certificate}, {.v3 = true, .attributes = ""}))) +
      pair(kV31, prefixed(complete_signer(
                     {certificate},
                     {.v3 = true, .minimum = 33, .maximum = kAnyLaterLevel, .attributes = prefixed(attribute)})));
  const auto found = complete_certificates(pairs, 33);
  ASSERT_FALSE(found.has_value());
  EXPECT_EQ(found.error(), SignerReadError::kUnsupported);
  EXPECT_TRUE(complete_certificates(pairs, 31).has_value());
}

TEST(Archive, findSigningCertificates_whenRotationMinimumIsStrippedOrInconsistent_reportsError) {
  const auto certificate = der_fixture("signer_a.der");
  std::string attribute;
  append_le(attribute, Field{.value = 0x559f8b02U, .width = 4});
  append_le(attribute, Field{.value = 34, .width = 4});
  const auto v3 =
      pair(kV3, prefixed(complete_signer(
                    {certificate}, {.v3 = true, .minimum = 31, .maximum = 33, .attributes = prefixed(attribute)})));
  EXPECT_FALSE(complete_certificates(v3, 33));
  EXPECT_TRUE(complete_certificates(v3, 31));
  EXPECT_TRUE(complete_certificates(
      v3 + pair(kV31, prefixed(complete_signer({certificate}, {.v3 = true, .minimum = 34, .attributes = ""}))), 33));
  EXPECT_FALSE(complete_certificates(
      v3 + pair(kV31, prefixed(complete_signer({certificate}, {.v3 = true, .minimum = 35, .attributes = ""}))), 33));
}

TEST(Archive, readSigningCertificates_whenArchiveIsValidOrTruncated_matchesBoundedParser) {
  const TemporaryDirectory directory;
  const auto certificate = der_fixture("signer_a.der");
  const auto apk = signed_apk(signing_block(pair(kV2, prefixed(complete_signer({certificate})))));
  const auto path = directory.path() + "/base.apk";
  ASSERT_TRUE(write_file(path, apk));
  const auto found = read_signing_certificates(path, 34);
  ASSERT_TRUE(found.has_value());
  EXPECT_EQ(*found, (util::Certificates{bytes_of(certificate)}));
  ASSERT_TRUE(write_file(path, apk.substr(0, apk.size() - 1)));
  EXPECT_FALSE(read_signing_certificates(path, 34));
}

TEST(Archive, findSigningCertificates_whenEveryArchivePrefixIsTruncated_reportsError) {
  const auto certificate = der_fixture("signer_a.der");
  const auto apk = signed_apk(signing_block(pair(kV2, prefixed(complete_signer({certificate})))));
  for (std::size_t length = 0; length < apk.size(); ++length) {
    EXPECT_FALSE(find_signing_certificates(bytes_of(apk.substr(0, length)), 34));
  }
}

TEST(Archive, readSigningCertificates_whenFifoHasNoWriter_returnsPromptErrorWithoutAReaderThread) {
  const TemporaryDirectory directory;
  const auto path = directory.path() + "/fifo.apk";
  ASSERT_EQ(mkfifo(path.c_str(), 0600), 0);
  const auto start = std::chrono::steady_clock::now();
  const auto result = read_signing_certificates(path, 34);
  const auto elapsed = std::chrono::steady_clock::now() - start;
  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), SignerReadError::kError);
  EXPECT_LT(elapsed, std::chrono::milliseconds(500));
}

TEST(Archive, readSigningCertificates_whenMissingDirectoryOrCharacterDevice_reportsError) {
  const TemporaryDirectory directory;
  EXPECT_FALSE(read_signing_certificates(directory.path() + "/missing", 34));
  EXPECT_FALSE(read_signing_certificates(directory.path(), 34));
  EXPECT_FALSE(read_signing_certificates("/dev/null", 34));
}

/// Large structurally valid DER envelope for bounds tests, deliberately without X.509 semantic or signature validity.
[[nodiscard]] std::string large_envelope() {
  std::string encoded(60018, '\0');
  const std::vector<std::uint8_t> prefix{
      0x30, 0x82, 0xea, 0x6e, 0x30, 3, 2, 1, 1, 0x30, 3, 6, 1, 42, 3, 0x82, 0xea, 0x60,
  };
  for (std::size_t index = 0; index < prefix.size(); ++index) {
    encoded[index] = static_cast<char>(prefix[index]);
  }
  return encoded;
}

TEST(Archive, findSigningCertificates_whenAggregateChainBytesExceedLimit_refusesTheCompleteSet) {
  const auto large = large_envelope();
  ASSERT_TRUE(util::certificate_envelope(bytes_of(large)));
  EXPECT_TRUE(complete_certificates(pair(kV2, prefixed(complete_signer({large, large, large, large})))));
  EXPECT_FALSE(complete_certificates(pair(kV2, prefixed(complete_signer({large, large, large, large, large})))));
}

TEST(Archive, findSigningCertificates_whenDerLengthIsIndefiniteOrNoncanonical_reportsError) {
  auto der = der_fixture("signer_a.der");
  ASSERT_GT(der.size(), 4U);
  der[1] = static_cast<char>(0x80);
  EXPECT_FALSE(complete_certificates(pair(kV2, prefixed(complete_signer({der})))));
  der[1] = static_cast<char>(0x82);
  der[2] = 0;
  EXPECT_FALSE(complete_certificates(pair(kV2, prefixed(complete_signer({der})))));
}

TEST(Archive, readSigningCertificates_whenArchiveIsOverLimit_reportsErrorWithoutReadingItsContents) {
  const TemporaryDirectory directory;
  const auto path = directory.path() + "/oversized.apk";
  ASSERT_TRUE(write_file(path, "sparse"));
  ASSERT_EQ(truncate(path.c_str(), static_cast<off_t>(2147483648ULL)), 0);
  EXPECT_FALSE(read_signing_certificates(path, 34));
}

TEST(Archive, findSigningCertificates_whenSdkIsOutsideSignedPlatformRange_neverReturnsAnEmptySuccessfulSet) {
  const auto certificate = der_fixture("signer_a.der");
  const auto result = complete_certificates(pair(kV2, prefixed(complete_signer({certificate}))), 0xffffffffU);
  EXPECT_FALSE(result.has_value());
}

TEST(Archive, findSigningCertificates_whenApiIsBelowMinimum_reportsUnsupported) {
  const auto found = find_signing_certificates({}, 30);
  ASSERT_FALSE(found.has_value());
  EXPECT_EQ(found.error(), SignerReadError::kUnsupported);
}

}  // namespace
}  // namespace rasp::android::apk
