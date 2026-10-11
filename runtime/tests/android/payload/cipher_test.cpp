/// Tests for decrypt, against a frame the packer's cipher made.

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

/// The key the packer's cipher used to make kFrame.
constexpr std::string_view kKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

/// A frame the packer's cipher (rasp_packer.android.cipher) made from kPlaintext under kKey, with a fixed nonce.
constexpr std::string_view kFrame =
    "5241535001030a11181f262d343b424950575e656cab21cc37b32446acdeec3ae869314c9ee169c315ce769e6962b44"
    "da4093e8588b1477f32113078d9adeb59c6a3a22ecd88084c8689c2a90626064f64f8a36055b9c69e32f81374e59c79"
    "47af9628844400d03ad4f2918f5c24224d2ed921fe08948e8e7d09bc1436b37b7f3717";

/// The text in kFrame. It is longer than 32 bytes, so it takes more than one keystream block.
constexpr std::string_view kPlaintext = "hello rasp payload, spanning > 32 bytes to cross a keystream block boundary!!";

TEST(AndroidCipher, decrypt_whenGivenAFrameFromThePacker_returnsItsPlaintext) {
  const std::optional<std::vector<std::uint8_t>> plaintext = decrypt(from_hex(kKey), from_hex(kFrame));

  ASSERT_TRUE(plaintext.has_value());
  EXPECT_EQ(std::string(plaintext->begin(), plaintext->end()), std::string(kPlaintext));
}

TEST(AndroidCipher, decrypt_whenTheFrameIsTampered_returnsNothing) {
  std::vector<std::uint8_t> frame = from_hex(kFrame);
  frame.back() = static_cast<std::uint8_t>(frame.back() ^ 0x01U);

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

TEST(AndroidCipher, decrypt_whenTheFrameIsTooShort_returnsNothing) {
  const std::vector<std::uint8_t> frame = {0x52, 0x41, 0x53, 0x50, 0x01};

  EXPECT_FALSE(decrypt(from_hex(kKey), frame).has_value());
}

TEST(AndroidCipher, decrypt_whenTheFrameStartsWithOtherBytes_returnsNothing) {
  std::vector<std::uint8_t> frame = from_hex(kFrame);
  frame.front() = 0x00;

  EXPECT_FALSE(decrypt(from_hex(kKey), frame).has_value());
}

TEST(AndroidCipher, decrypt_whenTheFrameHasAnotherVersion_returnsNothing) {
  constexpr std::size_t kVersionOffset = 4;
  std::vector<std::uint8_t> frame = from_hex(kFrame);
  frame[kVersionOffset] = 0x02;

  EXPECT_FALSE(decrypt(from_hex(kKey), frame).has_value());
}

}  // namespace
}  // namespace rasp::android::payload
