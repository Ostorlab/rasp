/// Tests for the APK reader: the stored-entry reader and the signing-certificate reader over the APK Signing Block.

#include "apk/archive.h"

#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "support/files.h"
#include "support/zip.h"

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

}  // namespace
}  // namespace rasp::android::apk
