/// Tests for the bootstrap's ChaCha20, against the RFC 8439 test vector and a vector the packer's `cryptography`
/// ChaCha20 made with the 16-byte counter and nonce the packer uses.

#include "selfdecrypt/chacha20.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <string_view>
#include <vector>

namespace rasp::android::selfdecrypt {
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

/// The key of both vectors: the bytes 00 to 1f.
[[nodiscard]] std::array<std::uint8_t, 32> vector_key() {
  std::array<std::uint8_t, 32> key{};
  for (std::size_t i = 0; i < key.size(); ++i) {
    key[i] = static_cast<std::uint8_t>(i);
  }
  return key;
}

/// The plaintext of RFC 8439's section 2.4.2 example, 114 bytes, so its keystream takes two blocks.
constexpr std::string_view kRfcPlaintext =
    "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be "
    "it.";

/// The RFC's block counter 1 and nonce 00 00 00 00 00 00 00 4a 00 00 00 00, as the 16 bytes the bootstrap takes.
constexpr std::string_view kRfcCounterAndNonce = "01000000000000000000004a00000000";

/// The RFC's ciphertext for kRfcPlaintext.
constexpr std::string_view kRfcCiphertext =
    "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e651"
    "52ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2"
    "785e42874d";

/// A counter of 0 and a 12-byte nonce, the shape of the counter and nonce the packer writes for each region.
constexpr std::string_view kPackerCounterAndNonce = "00000000a1a2a3a4a5a6a7a8a9aaabac";

/// What the packer's `cryptography` ChaCha20 makes of packer_plaintext() under vector_key() and
/// kPackerCounterAndNonce: 300 bytes, four whole blocks and a part of a fifth.
constexpr std::string_view kPackerCiphertext =
    "39b2e153ff272f3f4a76aa889a5ab23c54ca09071b80a4ccb72dbab67b83c6f697d301acf1afe7475a215e9c3ceb26ff97c170e2ad24c9"
    "565836227f2de7888aca12a066ddd097b8603c4a3e7013487112a69dc0b2bf1f7a2df5fa5aae040dc28a7003cca4964b6a0f26ee777f07"
    "658044bdb02cedd505ad926c4f2d0a746cc7fc93b1a537fb981a63cd7c4c102d88a5cdd479b3517b8b935c0fe44905637cbd96df52259f"
    "f5d6a0e6bcbd689eae6bbf319e6691d866a2da1fc9288b8e47abbc057052a02d7bcfc6983c664057570e78ca25582c5bbf400a3373255e"
    "126acd71d9ea7fb341a52a5fb656d8969431b2d8efe52b49881c45ceaf040bf44b3ba6d30ef9d16b821f9844e465bd158582cef443f96d"
    "ec015e402037d628b5b02e3cc7eec20215597f6bd006b6370c";

/// The plaintext of the packer vector: byte i is (7 * i + 3) mod 256, for 300 bytes.
[[nodiscard]] std::vector<std::uint8_t> packer_plaintext() {
  std::vector<std::uint8_t> bytes(300);
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    bytes[i] = static_cast<std::uint8_t>(((i * 7) + 3) & 0xFFU);
  }
  return bytes;
}

TEST(ChaCha20, xor_whenGivenTheRfc8439Example_makesItsCiphertext) {
  std::vector<std::uint8_t> data(kRfcPlaintext.begin(), kRfcPlaintext.end());
  const std::array<std::uint8_t, 32> key = vector_key();
  const std::vector<std::uint8_t> nonce = from_hex(kRfcCounterAndNonce);

  chacha20_xor(data.data(), data.size(), key.data(), nonce.data());

  EXPECT_EQ(data, from_hex(kRfcCiphertext));
}

TEST(ChaCha20, xor_whenGivenThePackersCounterAndNonce_makesWhatThePackerMakes) {
  std::vector<std::uint8_t> data = packer_plaintext();
  const std::array<std::uint8_t, 32> key = vector_key();
  const std::vector<std::uint8_t> nonce = from_hex(kPackerCounterAndNonce);

  chacha20_xor(data.data(), data.size(), key.data(), nonce.data());

  EXPECT_EQ(data, from_hex(kPackerCiphertext));
}

TEST(ChaCha20, xor_whenRunTwice_givesBackThePlaintext) {
  std::vector<std::uint8_t> data = packer_plaintext();
  const std::array<std::uint8_t, 32> key = vector_key();
  const std::vector<std::uint8_t> nonce = from_hex(kPackerCounterAndNonce);

  chacha20_xor(data.data(), data.size(), key.data(), nonce.data());
  chacha20_xor(data.data(), data.size(), key.data(), nonce.data());

  EXPECT_EQ(data, packer_plaintext());
}

TEST(ChaCha20, xor_whenTheLengthIsZero_writesNothing) {
  std::array<std::uint8_t, 4> data{1, 2, 3, 4};
  const std::array<std::uint8_t, 32> key = vector_key();
  const std::vector<std::uint8_t> nonce = from_hex(kPackerCounterAndNonce);

  chacha20_xor(data.data(), 0, key.data(), nonce.data());

  EXPECT_EQ(data, (std::array<std::uint8_t, 4>{1, 2, 3, 4}));
}

}  // namespace
}  // namespace rasp::android::selfdecrypt
