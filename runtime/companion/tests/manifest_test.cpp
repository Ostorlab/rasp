/// Hostile manifest bytes exercise the production codec and independently checked digest.
#include "manifest.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <memory>
#include <psa/crypto.h>

namespace {
TEST(ScopedManifest, decode_whenEveryBytePositionCorrupted_neverAcceptsTornOrForeignBytes) {
  ASSERT_EQ(psa_crypto_init(), PSA_SUCCESS);
  auto original = std::make_unique<rasp::keys::Manifest>();
  auto decoded = std::make_unique<rasp::keys::Manifest>();
  auto bytes = std::make_unique<std::array<std::uint8_t, 8192>>();
  original->generation.bytes[0] = 1;
  ASSERT_TRUE(rasp::keys::encode_manifest(*original, *bytes));
  ASSERT_TRUE(rasp::keys::decode_manifest(*bytes, *decoded));
  for (std::size_t index = 0; index < bytes->size(); ++index) {
    std::span(*bytes)[index] ^= std::uint8_t{1};
    ASSERT_FALSE(rasp::keys::decode_manifest(*bytes, *decoded)) << index;
    std::span(*bytes)[index] ^= std::uint8_t{1};
  }
  EXPECT_FALSE(rasp::keys::decode_manifest(std::span(*bytes).first(8191), *decoded));
}
TEST(ScopedManifest, decode_whenDuplicateOrUnknownStateHasValidChecksum_stillRejects) {
  auto manifest = std::make_unique<rasp::keys::Manifest>();
  auto decoded = std::make_unique<rasp::keys::Manifest>();
  auto bytes = std::make_unique<std::array<std::uint8_t, 8192>>();
  manifest->generation.bytes[0] = 1;
  manifest->records[0].state = rasp::keys::KeyState::kReserved;
  manifest->records[0].info.key_id.bytes[0] = 3;
  manifest->records[1] = manifest->records[0];
  ASSERT_TRUE(rasp::keys::encode_manifest(*manifest, *bytes));
  EXPECT_FALSE(rasp::keys::decode_manifest(*bytes, *decoded));
  manifest->records[1] = {};
  manifest->records[0].state = static_cast<rasp::keys::KeyState>(42);
  ASSERT_TRUE(rasp::keys::encode_manifest(*manifest, *bytes));
  EXPECT_FALSE(rasp::keys::decode_manifest(*bytes, *decoded));
}
}  // namespace
