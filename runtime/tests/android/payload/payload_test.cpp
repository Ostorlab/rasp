/// Tests for unpack, against a payload the packer made and against payloads sealed here the same way.

#include "payload/payload.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "rasp/util/sha256.h"

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

/// The text that `data` holds.
[[nodiscard]] std::string text_of(const std::vector<std::uint8_t>& data) { return {data.begin(), data.end()}; }

/// The bytes of `text`.
[[nodiscard]] std::vector<std::uint8_t> bytes_of(std::string_view text) { return {text.begin(), text.end()}; }

/// The key the packer used to make kPayload.
constexpr std::string_view kKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

/// A packer-built payload under kKey: classes.dex holds `DEX-primary-001`, classes2.dex holds `DEX-secondary-22`.
constexpr std::string_view kPayload =
    "5241535001030a11181f262d343b424950575e656cc344a059dc0434c6cef07beb7b2d53dfe4689735bd06f04349850e"
    "b35b69c8daf11e307b55640bf9d9881ac9b0be2edbdb5b428989c3da7254736a4c80ec7f5fb9c2d034f61463accf397d"
    "70609d2f405b435a7a7909287d92e71bbc8f10a83662518e8c86dec252cfc2";

/// Encrypts `plaintext` under kKey into a frame, the way the packer's cipher does, with a nonce of zeros.
[[nodiscard]] std::vector<std::uint8_t> seal(std::span<const std::uint8_t> plaintext) {
  const std::vector<std::uint8_t> key = from_hex(kKey);
  constexpr std::size_t kNonceSize = 16;
  const std::array<std::uint8_t, kNonceSize> nonce{};
  std::vector<std::uint8_t> frame = {0x52, 0x41, 0x53, 0x50, 0x01};
  frame.insert(frame.end(), nonce.begin(), nonce.end());

  const Sha256Digest encrypt_key = hmac_sha256(key, bytes_of("rasp/android/encrypt/v1"));
  std::vector<std::uint8_t> body(plaintext.begin(), plaintext.end());
  for (std::size_t offset = 0; offset < body.size(); offset += kSha256Size) {
    std::vector<std::uint8_t> counter_input(nonce.begin(), nonce.end());
    const std::uint64_t counter = offset / kSha256Size;
    for (std::size_t index = 0; index < 8; ++index) {
      counter_input.push_back(static_cast<std::uint8_t>(counter >> (56U - (8U * index))));
    }
    const Sha256Digest keystream = hmac_sha256(encrypt_key, counter_input);
    for (auto [byte, keystream_byte] : std::views::zip(std::span(body).subspan(offset), keystream)) {
      byte = static_cast<std::uint8_t>(byte ^ keystream_byte);
    }
  }
  frame.insert(frame.end(), body.begin(), body.end());

  const Sha256Digest authenticate_key = hmac_sha256(key, bytes_of("rasp/android/authenticate/v1"));
  const Sha256Digest tag = hmac_sha256(authenticate_key, frame);
  frame.insert(frame.end(), tag.begin(), tag.end());
  return frame;
}

TEST(AndroidPayload, unpack_whenGivenAPayloadFromThePacker_returnsTheDexFilesInOrder) {
  const std::optional<std::vector<Dex>> dexes = unpack(from_hex(kKey), from_hex(kPayload));

  ASSERT_TRUE(dexes.has_value());
  const std::vector<Dex>& files = *dexes;
  ASSERT_EQ(files.size(), 2U);
  EXPECT_EQ(files[0].name, "classes.dex");
  EXPECT_EQ(text_of(files[0].data), "DEX-primary-001");
  EXPECT_EQ(files[1].name, "classes2.dex");
  EXPECT_EQ(text_of(files[1].data), "DEX-secondary-22");
}

TEST(AndroidPayload, unpack_whenThePayloadIsTampered_returnsNothing) {
  std::vector<std::uint8_t> payload = from_hex(kPayload);
  payload.back() = static_cast<std::uint8_t>(payload.back() ^ 0x01U);

  EXPECT_FALSE(unpack(from_hex(kKey), payload).has_value());
}

TEST(AndroidPayload, unpack_whenThePayloadHoldsNoDexFile_returnsNoDexFile) {
  const std::optional<std::vector<Dex>> dexes = unpack(from_hex(kKey), seal(std::vector<std::uint8_t>{0, 0, 0, 0}));

  ASSERT_TRUE(dexes.has_value());
  EXPECT_TRUE(dexes->empty());
}

TEST(AndroidPayload, unpack_whenBytesFollowTheLastDexFile_ignoresThem) {
  const std::vector<std::uint8_t> container = {0, 0, 0, 1, 0, 0, 0, 1, 'a', 0, 0, 0, 2, 'b', 'c', 'x', 'y'};

  const std::optional<std::vector<Dex>> dexes = unpack(from_hex(kKey), seal(container));

  ASSERT_TRUE(dexes.has_value());
  EXPECT_EQ(*dexes, (std::vector<Dex>{Dex{.name = "a", .data = bytes_of("bc")}}));
}

TEST(AndroidPayload, unpack_whenTheCountIsLargerThanTheDexFiles_returnsNothing) {
  const std::vector<std::uint8_t> container = {0xff, 0xff, 0xff, 0xff, 0, 0, 0, 1, 'a', 0, 0, 0, 1, 'b'};

  EXPECT_FALSE(unpack(from_hex(kKey), seal(container)).has_value());
}

TEST(AndroidPayload, unpack_whenADexLengthGoesPastTheEnd_returnsNothing) {
  const std::vector<std::uint8_t> container = {0, 0, 0, 1, 0, 0, 0, 1, 'a', 0, 0, 0, 9, 'b', 'c'};

  EXPECT_FALSE(unpack(from_hex(kKey), seal(container)).has_value());
}

TEST(AndroidPayload, unpack_whenTheCountIsCutShort_returnsNothing) {
  EXPECT_FALSE(unpack(from_hex(kKey), seal(std::vector<std::uint8_t>{0, 0, 0})).has_value());
}

}  // namespace
}  // namespace rasp::android::payload
