/// Tests for base64: the test vectors of RFC 4648 section 10, every padding length, and every alphabet character.

#include "base64.h"

#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <vector>

namespace rasp::plugins::adr_pin {
namespace {

/// The base64 of the bytes of `text`.
///
/// @param text The bytes.
/// @return Their base64.
[[nodiscard]] std::string encode(std::string_view text) {
  const std::vector<std::uint8_t> bytes(text.begin(), text.end());
  return base64(bytes);
}

TEST(Base64, base64_whenRfc4648Vectors_matchesTheRfc) {
  EXPECT_EQ(encode(""), "");
  EXPECT_EQ(encode("f"), "Zg==");
  EXPECT_EQ(encode("fo"), "Zm8=");
  EXPECT_EQ(encode("foo"), "Zm9v");
  EXPECT_EQ(encode("foob"), "Zm9vYg==");
  EXPECT_EQ(encode("fooba"), "Zm9vYmE=");
  EXPECT_EQ(encode("foobar"), "Zm9vYmFy");
}

TEST(Base64, base64_whenBytesCoverEverySixBitValue_usesTheWholeAlphabet) {
  std::vector<std::uint8_t> bytes;
  // Three bytes hold four 6-bit values; 0x00 0x10 0x83 holds 0, 1, 2 and 3, and each next group adds 4 to each.
  for (std::uint32_t value = 0; value < 64; value += 4) {
    const std::uint32_t group = (value << 18U) | ((value + 1) << 12U) | ((value + 2) << 6U) | (value + 3);
    bytes.push_back(static_cast<std::uint8_t>(group >> 16U));
    bytes.push_back(static_cast<std::uint8_t>(group >> 8U));
    bytes.push_back(static_cast<std::uint8_t>(group));
  }

  EXPECT_EQ(base64(bytes), "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
}

TEST(Base64, base64_whenSha256SizedDigest_returns44CharactersWithOnePad) {
  const std::vector<std::uint8_t> digest(32, 0xff);

  EXPECT_EQ(base64(digest), "//////////////////////////////////////////8=");
}

}  // namespace
}  // namespace rasp::plugins::adr_pin
