/// Tests for unpack, against a payload the packer made and against payloads sealed here the same way.

#include "payload/payload.h"

#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <psa/crypto.h>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "payload/cipher.h"

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

/// A payload the packer built under kKey, with the nonce 00 01 ... 0b: classes.dex holds `DEX-primary-001`, and
/// classes2.dex holds `DEX-secondary-22`. The packer's tests check that it reads it back.
constexpr std::string_view kPayload =
    "000102030405060708090a0b89fb08022917a54bd4ef5e80eb787d4dad15cae75174a2fda3cf02b507a9cb5d9ef901c3"
    "d62fb198373e15b404e7fc460db687109850b89b12a89d42c862edb31a17d2a9846655c4f624e056ce59e1b5f8c08278"
    "cb9333815322";

/// Encrypts `plaintext` under kKey into a frame the way the packer's cipher does: ChaCha20-Poly1305, with a nonce of
/// zeros in front. It gives an empty frame when TF-PSA-Crypto refuses, which makes the test that uses it fail.
[[nodiscard]] std::vector<std::uint8_t> seal(std::span<const std::uint8_t> plaintext) {
  constexpr std::size_t kNonceSize = 12;
  constexpr std::size_t kTagSize = 16;
  if (psa_crypto_init() != PSA_SUCCESS) {
    return {};
  }
  const std::vector<std::uint8_t> key = from_hex(kKey);
  psa_key_attributes_t attributes = psa_key_attributes_init();
  psa_set_key_type(&attributes, PSA_KEY_TYPE_CHACHA20);
  psa_set_key_bits(&attributes, PSA_BYTES_TO_BITS(kKeySize));
  psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
  psa_set_key_algorithm(&attributes, PSA_ALG_CHACHA20_POLY1305);
  psa_key_id_t key_id = PSA_KEY_ID_NULL;
  if (psa_import_key(&attributes, key.data(), key.size(), &key_id) != PSA_SUCCESS) {
    return {};
  }

  std::vector<std::uint8_t> frame(kNonceSize + plaintext.size() + kTagSize);
  const std::span<std::uint8_t> nonce = std::span(frame).first(kNonceSize);
  const std::span<std::uint8_t> sealed = std::span(frame).subspan(kNonceSize);
  std::size_t written = 0;
  const psa_status_t status =
      psa_aead_encrypt(key_id, PSA_ALG_CHACHA20_POLY1305, nonce.data(), nonce.size(), nullptr, 0, plaintext.data(),
                       plaintext.size(), sealed.data(), sealed.size(), &written);
  psa_destroy_key(key_id);
  if (status != PSA_SUCCESS || written != sealed.size()) {
    return {};
  }
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

/// A decrypted payload of `count` dex files, each with an empty name and no bytes.
[[nodiscard]] std::vector<std::uint8_t> empty_dex_files(std::uint32_t count) {
  std::vector<std::uint8_t> container = {
      static_cast<std::uint8_t>(count >> 24U),
      static_cast<std::uint8_t>(count >> 16U),
      static_cast<std::uint8_t>(count >> 8U),
      static_cast<std::uint8_t>(count),
  };
  container.resize(container.size() + (std::size_t{count} * 8U));
  return container;
}

TEST(AndroidPayload, unpack_whenThePayloadHoldsTheMostDexFiles_returnsThemAll) {
  const std::optional<std::vector<Dex>> dexes = unpack(from_hex(kKey), seal(empty_dex_files(kMaxDexFiles)));

  ASSERT_TRUE(dexes.has_value());
  EXPECT_EQ(dexes->size(), kMaxDexFiles);
}

TEST(AndroidPayload, unpack_whenThePayloadHoldsMoreThanTheMostDexFiles_returnsNothing) {
  EXPECT_FALSE(unpack(from_hex(kKey), seal(empty_dex_files(kMaxDexFiles + 1))).has_value());
}

TEST(AndroidPayload, unpack_whenTheCountIsCutShort_returnsNothing) {
  EXPECT_FALSE(unpack(from_hex(kKey), seal(std::vector<std::uint8_t>{0, 0, 0})).has_value());
}

}  // namespace
}  // namespace rasp::android::payload
