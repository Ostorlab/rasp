/// Tests for the APK reader: the stored-entry reader and the signing-certificate reader over the APK Signing Block.

#include "apk/archive.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <initializer_list>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "checks/integrity.h"
#include "support/files.h"
#include "support/zip.h"

namespace rasp::android::apk {
namespace {

using test_support::StoredEntry;
using test_support::TemporaryDirectory;
using test_support::write_file;
using test_support::zip_with_stored_entries;
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

/// The SHA-256 of `bytes`, or no bytes when the hash fails.
[[nodiscard]] std::vector<std::uint8_t> sha256_of(std::string_view bytes) {
  const std::optional<std::array<std::uint8_t, checks::kDigestSize>> digest = checks::sha256(bytes_of(bytes));
  if (!digest.has_value()) {
    return {};
  }
  return {digest->begin(), digest->end()};
}

/// The little-endian 16-bit number at `at` in `data`.
[[nodiscard]] std::uint16_t u16_at(std::string_view data, std::size_t at) {
  return static_cast<std::uint16_t>(static_cast<std::uint32_t>(static_cast<std::uint8_t>(data[at])) |
                                    (static_cast<std::uint32_t>(static_cast<std::uint8_t>(data[at + 1])) << 8U));
}

/// The little-endian 32-bit number at `at` in `data`.
[[nodiscard]] std::uint32_t u32_at(std::string_view data, std::size_t at) {
  return static_cast<std::uint32_t>(u16_at(data, at)) | (static_cast<std::uint32_t>(u16_at(data, at + 2)) << 16U);
}

/// `data` with `field` written over its bytes at `at`, little-endian.
[[nodiscard]] std::string with_field(std::string data, std::size_t at, Field field) {
  std::string bytes;
  append_le(bytes, field);
  data.replace(at, bytes.size(), bytes);
  return data;
}

/// The size of a central-directory file header before its name, in the test zips, which carry no extra field and no
/// comment.
constexpr std::size_t kCentralHeaderSize = 46;
/// The offsets, in a central-directory file header, of the entry's compression method and of its name's length.
constexpr std::size_t kCentralMethodField = 10;
constexpr std::size_t kCentralNameLengthField = 28;
/// The compression method of a deflated entry.
constexpr std::uint64_t kDeflated = 8;

/// `zip` with the entry named `name` marked as deflated in its central directory. The readers take an entry's method
/// from there only, so the entry reads as compressed without holding deflated data.
[[nodiscard]] std::string with_deflated_entry(std::string zip, std::string_view name) {
  const std::size_t end = zip.size() - kEndSize;
  std::size_t at = u32_at(zip, end + kDirectoryOffsetField);
  while (at < end) {
    const std::size_t name_length = u16_at(zip, at + kCentralNameLengthField);
    if (std::string_view(zip).substr(at + kCentralHeaderSize, name_length) == name) {
      return with_field(std::move(zip), at + kCentralMethodField, Field{.value = kDeflated, .width = 2});
    }
    at += kCentralHeaderSize + name_length;
  }
  return zip;
}

/// The path of a file named `base.apk` in `directory` holding `apk`, or an empty path, after a test failure, when the
/// file can't be written.
[[nodiscard]] std::string apk_file(const TemporaryDirectory& directory, std::string_view apk) {
  std::string path = directory.path() + "/base.apk";
  if (!write_file(path, apk)) {
    ADD_FAILURE() << "could not write " << path;
    return {};
  }
  return path;
}

/// A string attribute of a test manifest's `<manifest>` element: its name and its value, both in UTF-8.
struct StringAttribute {
  /// The attribute's name.
  std::string_view name;
  /// The attribute's value.
  std::string_view value;
};

/// The UTF-16 units of the well-formed UTF-8 text `text`.
[[nodiscard]] std::vector<std::uint16_t> utf16_of(std::string_view text) {
  std::vector<std::uint16_t> units;
  std::size_t at = 0;
  while (at < text.size()) {
    const auto lead = static_cast<std::uint8_t>(text[at]);
    std::size_t length = 1;
    std::uint32_t code_point = lead;
    if (lead >= 0xF0U) {
      length = 4;
      code_point = lead & 0x07U;
    } else if (lead >= 0xE0U) {
      length = 3;
      code_point = lead & 0x0FU;
    } else if (lead >= 0xC0U) {
      length = 2;
      code_point = lead & 0x1FU;
    }
    for (std::size_t index = 1; index < length; ++index) {
      code_point = (code_point << 6U) | (static_cast<std::uint8_t>(text[at + index]) & 0x3FU);
    }
    at += length;
    if (code_point >= 0x10000U) {
      code_point -= 0x10000U;
      units.push_back(static_cast<std::uint16_t>(0xD800U + (code_point >> 10U)));
      units.push_back(static_cast<std::uint16_t>(0xDC00U + (code_point & 0x3FFU)));
    } else {
      units.push_back(static_cast<std::uint16_t>(code_point));
    }
  }
  return units;
}

/// One string of a UTF-8 string pool: its length in UTF-16 units, then in bytes, each in the one-byte form that holds
/// lengths below 128, then the bytes and a null.
[[nodiscard]] std::string utf8_record(std::string_view text) {
  std::string record;
  append_le(record, Field{.value = utf16_of(text).size(), .width = 1});
  append_le(record, Field{.value = text.size(), .width = 1});
  record.append(text);
  record.push_back('\0');
  return record;
}

/// One string of a UTF-16 string pool: its length in units, in the one-unit form, then the units and a null unit.
[[nodiscard]] std::string utf16_record(std::string_view text) {
  const std::vector<std::uint16_t> units = utf16_of(text);
  std::string record;
  append_le(record, Field{.value = units.size(), .width = 2});
  for (const std::uint16_t unit : units) {
    append_le(record, Field{.value = unit, .width = 2});
  }
  append_le(record, Field{.value = 0, .width = 2});
  return record;
}

/// Where a binary manifest's string pool starts: after the eight-byte XML file header.
constexpr std::size_t kPoolStart = 8;
/// The size of the string pool chunk's own header, before its offsets table.
constexpr std::size_t kPoolHeaderSize = 28;
/// The offsets, in the string pool chunk's header, of the chunk's size and of where its strings start.
constexpr std::size_t kPoolChunkSizeField = 4;
constexpr std::size_t kPoolStringsStartField = 20;
/// The index, in binary_manifest's pool, of the first attribute's value.
constexpr std::size_t kFirstValueString = 2;

/// A binary AndroidManifest.xml with one `<manifest>` element carrying `attributes`, each a string, its strings in a
/// UTF-8 pool when `utf8` and in a UTF-16 pool otherwise. String 0 is the element's name; for attribute i, string
/// 1 + 2i is its name and string 2 + 2i its value.
[[nodiscard]] std::string binary_manifest(std::span<const StringAttribute> attributes, bool utf8) {
  std::vector<std::string_view> strings{"manifest"};
  for (const StringAttribute& attribute : attributes) {
    strings.push_back(attribute.name);
    strings.push_back(attribute.value);
  }
  std::string offsets;
  std::string data;
  for (const std::string_view text : strings) {
    append_le(offsets, Field{.value = data.size(), .width = 4});
    data += utf8 ? utf8_record(text) : utf16_record(text);
  }
  std::string pool;
  append_le(pool, Field{.value = 0x0001, .width = 2});                                          // type: string pool
  append_le(pool, Field{.value = kPoolHeaderSize, .width = 2});                                 // header size
  append_le(pool, Field{.value = kPoolHeaderSize + offsets.size() + data.size(), .width = 4});  // chunk size
  append_le(pool, Field{.value = strings.size(), .width = 4});                                  // string count
  append_le(pool, Field{.value = 0, .width = 4});                                               // style count
  append_le(pool, Field{.value = utf8 ? 0x100U : 0U, .width = 4});                              // flags: UTF-8
  append_le(pool, Field{.value = kPoolHeaderSize + offsets.size(), .width = 4});                // strings start
  append_le(pool, Field{.value = 0, .width = 4});                                               // styles start
  pool += offsets;
  pool += data;

  std::string element;
  append_le(element, Field{.value = 0x0102, .width = 2});                         // type: start element
  append_le(element, Field{.value = 16, .width = 2});                             // header size
  append_le(element, Field{.value = 36 + (20 * attributes.size()), .width = 4});  // chunk size
  append_le(element, Field{.value = 1, .width = 4});                              // line number
  append_le(element, Field{.value = 0xFFFFFFFFU, .width = 4});                    // comment: none
  append_le(element, Field{.value = 0xFFFFFFFFU, .width = 4});                    // namespace: none
  append_le(element, Field{.value = 0, .width = 4});                              // name: string 0
  append_le(element, Field{.value = 20, .width = 2});                             // attributes start
  append_le(element, Field{.value = 20, .width = 2});                             // attribute size
  append_le(element, Field{.value = attributes.size(), .width = 2});              // attribute count
  append_le(element, Field{.value = 0, .width = 6});                              // id, class and style indices
  for (std::size_t index = 0; index < attributes.size(); ++index) {
    append_le(element, Field{.value = 0xFFFFFFFFU, .width = 4});      // namespace: none
    append_le(element, Field{.value = 1 + (2 * index), .width = 4});  // name
    append_le(element, Field{.value = 2 + (2 * index), .width = 4});  // raw value: the string
    append_le(element, Field{.value = 8, .width = 2});                // typed value's size
    append_le(element, Field{.value = 0, .width = 1});                // reserved
    append_le(element, Field{.value = 0x03, .width = 1});             // type: string
    append_le(element, Field{.value = 2 + (2 * index), .width = 4});  // data: the string
  }

  std::string document;
  append_le(document, Field{.value = 0x0003, .width = 2});  // type: XML
  append_le(document, Field{.value = 8, .width = 2});       // header size
  append_le(document, Field{.value = kPoolStart + pool.size() + element.size(), .width = 4});
  return document + pool + element;
}

/// Where the offset of string `index` sits in a binary manifest's offsets table.
[[nodiscard]] std::size_t offset_position(std::size_t index) { return kPoolStart + kPoolHeaderSize + (4 * index); }

/// Where string `index` of a binary manifest's pool starts, in the manifest's bytes.
[[nodiscard]] std::size_t string_position(std::string_view manifest, std::size_t index) {
  return kPoolStart + u32_at(manifest, kPoolStart + kPoolStringsStartField) + u32_at(manifest, offset_position(index));
}

/// The semantic digest of a `<manifest>` element carrying `attributes`, from the canonical form the packer hashes,
/// without the reader: for each attribute, the element's name, a null, its name, a null, `str`, its value's UTF-8
/// bytes and a null, sorted and hashed together.
[[nodiscard]] std::vector<std::uint8_t> expected_semantics(std::span<const StringAttribute> attributes) {
  std::vector<std::string> entries;
  for (const StringAttribute& attribute : attributes) {
    std::string entry("manifest");
    entry.push_back('\0');
    entry.append(attribute.name);
    entry.push_back('\0');
    entry.append("str");
    entry.append(attribute.value);
    entry.push_back('\0');
    entries.push_back(std::move(entry));
  }
  std::ranges::sort(entries);
  std::string all;
  for (const std::string& entry : entries) {
    all += entry;
  }
  return sha256_of(all);
}

/// The semantic digest read_manifest_semantics reads from an APK in `directory` that holds `manifest`.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> semantics_of(const TemporaryDirectory& directory,
                                                                    std::string_view manifest) {
  return read_manifest_semantics(apk_file(directory, zip_with_stored_entry("AndroidManifest.xml", manifest)));
}

/// Attribute values beyond ASCII: a Latin-1 letter, Arabic letters, and a character above U+FFFF, which UTF-16 holds
/// as a surrogate pair.
constexpr std::array<StringAttribute, 3> kNonAsciiAttributes{
    {
        {.name = "label", .value = "Caf\xC3\xA9"},
        {.name = "package", .value = "\xD8\xA7\xD9\x84\xD9\x83\xD9\x87\xD9\x81"},
        {.name = "process", .value = "app\xF0\x9F\x93\x96"},
    },
};

/// One ASCII attribute, for the tests that corrupt a manifest.
constexpr std::array<StringAttribute, 1> kOneAttribute{{{.name = "label", .value = "value"}}};

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

TEST(Archive, readStubEntry_whenTheApkHasSeveralClassDexes_returnsTheHighestNumberedOne) {
  // classes10.dex sorts before classes2.dex as text, so the reader has to compare the numbers.
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::vector<StoredEntry> entries{
      {.name = "classes.dex", .content = "app dex"},
      {.name = "classes10.dex", .content = "stub dex"},
      {.name = "classes2.dex", .content = "second dex"},
  };

  EXPECT_EQ(read_stub_entry(apk_file(directory, zip_with_stored_entries(entries))), bytes_of("stub dex"));
}

TEST(Archive, readStubEntry_whenTheHighestNumberedClassDexIsCompressed_returnsNothing) {
  // Taking the next stored dex down instead would hand back the app's own dex as if it were the stub.
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::vector<StoredEntry> entries{
      {.name = "classes.dex", .content = "app dex"},
      {.name = "classes2.dex", .content = "stub dex"},
  };
  const std::string apk = with_deflated_entry(zip_with_stored_entries(entries), "classes2.dex");

  EXPECT_EQ(read_stub_entry(apk_file(directory, apk)), std::nullopt);
}

TEST(Archive, readStubEntry_whenTheApkHoldsNoClassDex_returnsNothing) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());

  EXPECT_EQ(read_stub_entry(apk_file(directory, zip_with_stored_entry("assets/data.bin", "data"))), std::nullopt);
}

TEST(Archive, readApkDigest_whenAnEntryChanges_changes) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::vector<StoredEntry> clean{
      {.name = "classes.dex", .content = "dex"},
      {.name = "res/a.xml", .content = "a"},
  };
  const std::vector<StoredEntry> edited{
      {.name = "classes.dex", .content = "dex"},
      {.name = "res/a.xml", .content = "b"},
  };

  const std::optional<std::vector<std::uint8_t>> clean_digest =
      read_apk_digest(apk_file(directory, zip_with_stored_entries(clean)));
  const std::optional<std::vector<std::uint8_t>> edited_digest =
      read_apk_digest(apk_file(directory, zip_with_stored_entries(edited)));

  ASSERT_TRUE(clean_digest.has_value());
  ASSERT_TRUE(edited_digest.has_value());
  EXPECT_EQ(clean_digest->size(), checks::kDigestSize);
  EXPECT_NE(*clean_digest, *edited_digest);
}

TEST(Archive, readApkDigest_whenAnEntryIsAdded_changes) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::vector<StoredEntry> clean{{.name = "classes.dex", .content = "dex"}};
  const std::vector<StoredEntry> grown{
      {.name = "classes.dex", .content = "dex"},
      {.name = "lib/arm64-v8a/libextra.so", .content = "extra"},
  };

  const std::optional<std::vector<std::uint8_t>> clean_digest =
      read_apk_digest(apk_file(directory, zip_with_stored_entries(clean)));
  const std::optional<std::vector<std::uint8_t>> grown_digest =
      read_apk_digest(apk_file(directory, zip_with_stored_entries(grown)));

  ASSERT_TRUE(clean_digest.has_value());
  ASSERT_TRUE(grown_digest.has_value());
  EXPECT_NE(*clean_digest, *grown_digest);
}

TEST(Archive, readApkDigest_whenAnEntryIsDeflatedInstead_changes) {
  // The method is bound, and a deflated entry adds its metadata but not its bytes.
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::vector<StoredEntry> entries{
      {.name = "classes.dex", .content = "dex"},
      {.name = "res/a.xml", .content = "a"},
  };
  const std::string stored = zip_with_stored_entries(entries);

  const std::optional<std::vector<std::uint8_t>> stored_digest = read_apk_digest(apk_file(directory, stored));
  const std::optional<std::vector<std::uint8_t>> deflated_digest =
      read_apk_digest(apk_file(directory, with_deflated_entry(stored, "res/a.xml")));

  ASSERT_TRUE(stored_digest.has_value());
  ASSERT_TRUE(deflated_digest.has_value());
  EXPECT_NE(*stored_digest, *deflated_digest);
}

TEST(Archive, readApkDigest_whenOnlyEntriesItLeavesOutChange_staysTheSame) {
  // The signing step's META-INF/ entries, the fold's own outputs under assets/rasp/ and assets/business/, and the
  // runtime's own library are left out. The test binary is no shared object, so the library's legacy name applies.
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::vector<StoredEntry> before{
      {.name = "classes.dex", .content = "dex"},
      {.name = "META-INF/CERT.SF", .content = "one"},
      {.name = "assets/rasp/s.bin", .content = "one"},
      {.name = "assets/business/0.dex", .content = "one"},
      {.name = "lib/arm64-v8a/librasp.so", .content = "one"},
  };
  const std::vector<StoredEntry> after{
      {.name = "classes.dex", .content = "dex"},
      {.name = "META-INF/CERT.SF", .content = "two"},
      {.name = "assets/rasp/s.bin", .content = "two"},
      {.name = "assets/business/0.dex", .content = "two"},
      {.name = "lib/arm64-v8a/librasp.so", .content = "two"},
  };

  const std::optional<std::vector<std::uint8_t>> before_digest =
      read_apk_digest(apk_file(directory, zip_with_stored_entries(before)));
  const std::optional<std::vector<std::uint8_t>> after_digest =
      read_apk_digest(apk_file(directory, zip_with_stored_entries(after)));

  ASSERT_TRUE(before_digest.has_value());
  EXPECT_EQ(before_digest, after_digest);
}

TEST(Archive, readApkDigest_whenTheFileIsNotAZip_returnsNothing) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());

  EXPECT_EQ(read_apk_digest(apk_file(directory, "not a zip")), std::nullopt);
}

TEST(Archive, readSignerDigest_whenSignedWithV3_hashesTheSignersCertificate) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string apk = signed_apk(signing_block(pair(kV3, v3_scheme({{.certificate = "v3 certificate"}}))));

  EXPECT_EQ(read_signer_digest(apk_file(directory, apk)), sha256_of("v3 certificate"));
}

TEST(Archive, readSignerDigest_whenAPairLengthWouldWrapPastTheBlock_returnsNothing) {
  // A pair length near 2^64 wraps a sum back to a small value. The reader must stop at the pair, not read past the
  // block or step onto the same pair again and again.
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  std::string pairs;
  append_le(pairs, Field{.value = 0xFFFFFFFFFFFFFFF8ULL, .width = 8});
  append_le(pairs, Field{.value = kPadding, .width = 4});
  pairs.append("padding");

  EXPECT_EQ(read_signer_digest(apk_file(directory, signed_apk(signing_block(pairs)))), std::nullopt);
}

TEST(Archive, readManifestSemantics_whenTheStringsAreUtf16_hashesTheirUtf8Bytes) {
  // The packer hashes each manifest string in UTF-8, so a UTF-16 pool has to decode to the same bytes, beyond ASCII
  // too. Keeping only each unit's low byte would give a genuine app with such a string a different digest.
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());

  EXPECT_EQ(semantics_of(directory, binary_manifest(kNonAsciiAttributes, false)),
            expected_semantics(kNonAsciiAttributes));
}

TEST(Archive, readManifestSemantics_whenTheStringsAreUtf8_hashesTheirBytes) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());

  EXPECT_EQ(semantics_of(directory, binary_manifest(kNonAsciiAttributes, true)),
            expected_semantics(kNonAsciiAttributes));
}

TEST(Archive, readManifestSemantics_whenAUtf16StringHoldsALoneSurrogate_returnsNothing) {
  // No string the packer wrote decodes to a surrogate without its pair, so the manifest is refused.
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string manifest = binary_manifest(kOneAttribute, false);
  ASSERT_EQ(semantics_of(directory, manifest), expected_semantics(kOneAttribute));
  // The value's first unit, after its length unit, becomes a high surrogate followed by an ordinary letter.
  const std::size_t first_unit = string_position(manifest, kFirstValueString) + 2;
  const std::string broken = with_field(manifest, first_unit, Field{.value = 0xD800U, .width = 2});

  EXPECT_EQ(semantics_of(directory, broken), std::nullopt);
}

TEST(Archive, readManifestSemantics_whenAStringOffsetWrapsPast32Bits_returnsNothing) {
  // The strings' start and a string's offset are both 32-bit. Their sum taken in 32 bits wraps back to a small value
  // inside the pool, while the address formed from the two lies 4 GiB past it.
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string manifest = binary_manifest(kOneAttribute, true);
  ASSERT_EQ(semantics_of(directory, manifest), expected_semantics(kOneAttribute));
  const std::uint64_t strings_start = u32_at(manifest, kPoolStart + kPoolStringsStartField);
  const std::string broken = with_field(manifest, offset_position(kFirstValueString),
                                        Field{.value = (std::uint64_t{1} << 32U) - strings_start, .width = 4});

  EXPECT_EQ(semantics_of(directory, broken), std::nullopt);
}

TEST(Archive, readManifestSemantics_whenAStringStartsPastThePool_returnsNothing) {
  // An offset reaching past the pool's own chunk lands in the element after it: here on the manifest's last two
  // bytes, which read as a UTF-8 string with two-byte lengths would send the reader past the manifest's end.
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string manifest = binary_manifest(kOneAttribute, true);
  ASSERT_EQ(semantics_of(directory, manifest), expected_semantics(kOneAttribute));
  const std::size_t last_two = manifest.size() - 2;
  const std::uint64_t strings_start = u32_at(manifest, kPoolStart + kPoolStringsStartField);
  const std::string broken =
      with_field(with_field(manifest, last_two, Field{.value = 0x8080U, .width = 2}),
                 offset_position(kFirstValueString), Field{.value = last_two - kPoolStart - strings_start, .width = 4});

  EXPECT_EQ(semantics_of(directory, broken), std::nullopt);
}

TEST(Archive, readManifestSemantics_whenThePoolsStringsStartPastItsChunk_returnsNothing) {
  // The strings start inside the pool's own chunk. A start past it would read the element after the pool as strings,
  // and the offsets table could run past the manifest's end.
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string manifest = binary_manifest(kOneAttribute, true);
  ASSERT_EQ(semantics_of(directory, manifest), expected_semantics(kOneAttribute));
  const std::uint64_t chunk_size = u32_at(manifest, kPoolStart + kPoolChunkSizeField);
  const std::string broken =
      with_field(manifest, kPoolStart + kPoolStringsStartField, Field{.value = chunk_size + 4, .width = 4});

  EXPECT_EQ(semantics_of(directory, broken), std::nullopt);
}

}  // namespace
}  // namespace rasp::android::apk
