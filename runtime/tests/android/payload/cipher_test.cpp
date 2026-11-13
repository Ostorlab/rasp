/// Tests for decrypt, against a frame the packer's cipher made and a Project Wycheproof test vector.

#include "payload/cipher.h"

#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace rasp::android::payload {
namespace {

/// The value of the lowercase hex digit `c`.
[[nodiscard]] std::uint32_t nibble(char c) {
  if (c >= '0' && c <= '9') {
    return static_cast<std::uint32_t>(c - '0');
  }
  return static_cast<std::uint32_t>(c - 'a' + 10);
}

/// The bytes that the lowercase hex digits in `hex` stand for, two digits per byte.
[[nodiscard]] std::vector<std::uint8_t> from_hex(std::string_view hex) {
  std::vector<std::uint8_t> bytes;
  bytes.reserve(hex.size() / 2);
  for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
    bytes.push_back(static_cast<std::uint8_t>((nibble(hex[i]) << 4U) | nibble(hex[i + 1])));
  }
  return bytes;
}

/// The key the packer's cipher used to make kFrame and kEmptyFrame.
constexpr std::string_view kKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

/// A frame the packer's cipher (rasp_packer.android.cipher) made from kPlaintext under kKey, with the nonce
/// 00 01 ... 0b. The packer's tests check that it makes these exact bytes.
constexpr std::string_view kFrame =
    "000102030405060708090a0bfd936d205b62cb34deee5ad3ec787d17e916c0863c1197998af841a210b2864884e142d3"
    "8970d4b801065bba1ce0ea033decc83795498aab32dab568f324b2f60a179cb98d710c82a16f3ec86a19bd9cfaad3753"
    "0119d04a7938d06cb41261d43e94d233cbe6e8bfc182b89601363c917a";

/// The text in kFrame. It is longer than 64 bytes, so its keystream takes more than one ChaCha20 block.
constexpr std::string_view kPlaintext =
    "the runtime test frame: longer than one 64-byte ChaCha20 block, so the keystream spans two blocks";

/// A frame the packer's cipher made from no bytes at all under kKey, with the same nonce: the nonce and the tag.
constexpr std::string_view kEmptyFrame = "000102030405060708090a0b295a498b8841a1c5f55d4d606f731159";

/// Test case 74 of Project Wycheproof's chacha20_poly1305_test.json, which has no associated data, written as a frame:
/// its nonce, its ciphertext and its tag. The packer's tests check the same vector.
constexpr std::string_view kWycheproofKey = "fe6e55bdaed1f7284ca5fc0f8c5f2b8df56dc0f49e8ca66a41995e783351f901";

/// The frame of the Wycheproof test case.
constexpr std::string_view kWycheproofFrame =
    "17c86a8abbb7e003acde2799"
    "d0102f6c258bf49742cec34cf2d0fedf23d105fb4c84cf98515e1bc9a64f8ad5be8f0721bde50645d00083c3a263a3"
    "1053b760245f52ae2866a5ec83b19f61be1d30d5c5d9fecc4cbbe08fd385813a2aa39a00ff9c10f7f23702add1e4b2"
    "ffa31c"
    "41865fc71de12b19612127ce49993bb0";

/// The plaintext of the Wycheproof test case.
constexpr std::string_view kWycheproofPlaintext =
    "b429eb80fb8fe8baeda0c85b9c333458e7c2992e558475069d12d45c22217564121588032297eff56783742a5fc22d74"
    "10ffb29d66098661d76f126c3c27689e43b37267cac5a3a6d3ab49e391da29cd3054a5692e2807e4c3ea46c8761d50f5"
    "92";

TEST(AndroidCipher, decrypt_whenGivenAFrameFromThePacker_returnsItsPlaintext) {
  const std::optional<std::vector<std::uint8_t>> plaintext = decrypt(from_hex(kKey), from_hex(kFrame));

  ASSERT_TRUE(plaintext.has_value());
  EXPECT_EQ(std::string(plaintext->begin(), plaintext->end()), std::string(kPlaintext));
}

TEST(AndroidCipher, decrypt_whenGivenTheWycheproofVector_returnsItsPlaintext) {
  const std::optional<std::vector<std::uint8_t>> plaintext =
      decrypt(from_hex(kWycheproofKey), from_hex(kWycheproofFrame));

  ASSERT_TRUE(plaintext.has_value());
  EXPECT_EQ(*plaintext, from_hex(kWycheproofPlaintext));
}

TEST(AndroidCipher, decrypt_whenTheFrameHoldsNoBytes_returnsNoBytes) {
  const std::optional<std::vector<std::uint8_t>> plaintext = decrypt(from_hex(kKey), from_hex(kEmptyFrame));

  ASSERT_TRUE(plaintext.has_value());
  EXPECT_TRUE(plaintext->empty());
}

TEST(AndroidCipher, decrypt_whenTheTagIsTampered_returnsNothing) {
  std::vector<std::uint8_t> frame = from_hex(kFrame);
  frame.back() = static_cast<std::uint8_t>(frame.back() ^ 0x01U);

  EXPECT_FALSE(decrypt(from_hex(kKey), frame).has_value());
}

TEST(AndroidCipher, decrypt_whenTheCiphertextIsTampered_returnsNothing) {
  constexpr std::size_t kCiphertextOffset = 20;
  std::vector<std::uint8_t> frame = from_hex(kFrame);
  frame[kCiphertextOffset] = static_cast<std::uint8_t>(frame[kCiphertextOffset] ^ 0x01U);

  EXPECT_FALSE(decrypt(from_hex(kKey), frame).has_value());
}

TEST(AndroidCipher, decrypt_whenTheNonceIsTampered_returnsNothing) {
  std::vector<std::uint8_t> frame = from_hex(kFrame);
  frame.front() = static_cast<std::uint8_t>(frame.front() ^ 0x01U);

  EXPECT_FALSE(decrypt(from_hex(kKey), frame).has_value());
}

TEST(AndroidCipher, decrypt_whenTheKeyIsWrong_returnsNothing) {
  std::vector<std::uint8_t> key = from_hex(kKey);
  key.front() = static_cast<std::uint8_t>(key.front() ^ 0x01U);

  EXPECT_FALSE(decrypt(key, from_hex(kFrame)).has_value());
}

TEST(AndroidCipher, decrypt_whenTheKeyHasTheWrongSize_returnsNothing) {
  std::vector<std::uint8_t> key = from_hex(kKey);
  key.pop_back();

  EXPECT_FALSE(decrypt(key, from_hex(kFrame)).has_value());
}

TEST(AndroidCipher, decrypt_whenTheFrameIsShorterThanANonceAndATag_returnsNothing) {
  std::vector<std::uint8_t> frame = from_hex(kEmptyFrame);
  frame.pop_back();

  EXPECT_FALSE(decrypt(from_hex(kKey), frame).has_value());
}

}  // namespace
}  // namespace rasp::android::payload
