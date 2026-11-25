/// Tests for the iOS at-rest ChaCha20, against the RFC 8439 test vector so it matches the packer's cipher byte for
/// byte, and against the Android bootstrap's cipher (the same vector), so the packer can encrypt once and either
/// platform decrypt.

#include "selfdecrypt/chacha20.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <string_view>
#include <vector>

namespace rasp::ios::selfdecrypt {
namespace {

/// The value of the hexadecimal digit `c`.
[[nodiscard]] std::uint8_t nibble(char c) {
  if (c >= '0' && c <= '9') {
    return static_cast<std::uint8_t>(c - '0');
  }
  return static_cast<std::uint8_t>((c - 'a') + 10);
}

/// The bytes a hexadecimal string spells.
[[nodiscard]] std::vector<std::uint8_t> from_hex(std::string_view hex) {
  std::vector<std::uint8_t> bytes;
  bytes.reserve(hex.size() / 2);
  for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index): i is bounded by hex.size().
    bytes.push_back(static_cast<std::uint8_t>((nibble(hex[i]) << 4U) | nibble(hex[i + 1])));
  }
  return bytes;
}

/// The key of the vector: the bytes 00 to 1f.
[[nodiscard]] std::array<std::uint8_t, kKeySize> vector_key() {
  std::array<std::uint8_t, kKeySize> key{};
  for (std::size_t i = 0; i < key.size(); ++i) {
    key[i] = static_cast<std::uint8_t>(i);
  }
  return key;
}

/// The plaintext of RFC 8439's section 2.4.2 example, 114 bytes, so its keystream takes two blocks.
constexpr std::string_view kRfcPlaintext =
    "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be "
    "it.";

/// RFC 8439's block counter 1 and nonce, as the 16 bytes the cipher takes.
constexpr std::string_view kRfcCounterAndNonce = "01000000000000000000004a00000000";

/// RFC 8439's ciphertext for kRfcPlaintext.
constexpr std::string_view kRfcCiphertext =
    "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e651"
    "52ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2"
    "785e42874d";

TEST(ChaCha20, xor_whenGivenTheRfc8439Example_makesItsCiphertext) {
  std::vector<std::uint8_t> data(kRfcPlaintext.begin(), kRfcPlaintext.end());
  const std::array<std::uint8_t, kKeySize> key = vector_key();
  const std::vector<std::uint8_t> nonce = from_hex(kRfcCounterAndNonce);

  chacha20_xor(data.data(), data.size(), key.data(), nonce.data());

  EXPECT_EQ(data, from_hex(kRfcCiphertext));
}

TEST(ChaCha20, xor_whenRunTwice_givesBackThePlaintext) {
  const std::vector<std::uint8_t> plaintext(kRfcPlaintext.begin(), kRfcPlaintext.end());
  std::vector<std::uint8_t> data = plaintext;
  const std::array<std::uint8_t, kKeySize> key = vector_key();
  const std::vector<std::uint8_t> nonce = from_hex(kRfcCounterAndNonce);

  chacha20_xor(data.data(), data.size(), key.data(), nonce.data());
  chacha20_xor(data.data(), data.size(), key.data(), nonce.data());

  EXPECT_EQ(data, plaintext);
}

TEST(ChaCha20, xor_whenTheKeyDiffersByOneBit_makesDifferentCiphertext) {
  const std::vector<std::uint8_t> plaintext(kRfcPlaintext.begin(), kRfcPlaintext.end());
  std::array<std::uint8_t, kKeySize> key = vector_key();
  const std::vector<std::uint8_t> nonce = from_hex(kRfcCounterAndNonce);

  std::vector<std::uint8_t> with_key = plaintext;
  chacha20_xor(with_key.data(), with_key.size(), key.data(), nonce.data());

  key[0] ^= 0x01U;
  std::vector<std::uint8_t> with_flipped_key = plaintext;
  chacha20_xor(with_flipped_key.data(), with_flipped_key.size(), key.data(), nonce.data());

  EXPECT_NE(with_key, with_flipped_key);
}

}  // namespace
}  // namespace rasp::ios::selfdecrypt
