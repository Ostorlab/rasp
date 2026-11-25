/// Tests for the iOS at-rest layer: the key binds to the runtime's own code hash, so a region decrypts to its
/// plaintext only when the hash is the one used to encrypt it, and not when the hash differs (a patched or removed
/// runtime). This is the property that makes the guard enforced by key derivation rather than by a branch.

#include "selfdecrypt/atrest.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <span>
#include <vector>

#include "selfdecrypt/chacha20.h"

namespace rasp::ios::selfdecrypt {
namespace {

/// A 16-byte counter and nonce for the tests.
constexpr std::array<std::uint8_t, kNonceSize> kNonce = {
    0x00, 0x00, 0x00, 0x00, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac,
};

/// Stand-in bytes for the runtime's own code: byte i is (3 * i + 1) mod 256, for 512 bytes.
[[nodiscard]] std::vector<std::uint8_t> code_bytes() {
  std::vector<std::uint8_t> bytes(512);
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    bytes[i] = static_cast<std::uint8_t>(((i * 3) + 1) & 0xFFU);
  }
  return bytes;
}

/// The plaintext of a guarded region: byte i is (5 * i + 2) mod 256, for 200 bytes.
[[nodiscard]] std::vector<std::uint8_t> region_plaintext() {
  std::vector<std::uint8_t> bytes(200);
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    bytes[i] = static_cast<std::uint8_t>(((i * 5) + 2) & 0xFFU);
  }
  return bytes;
}

/// A per-build seed for the tests.
constexpr std::array<std::uint8_t, 8> kSeed = {0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04};

/// Encrypts `plaintext` the way the packer would: derive the key from the code hash and seed, then ChaCha20 it.
[[nodiscard]] std::vector<std::uint8_t> packer_encrypt(const std::vector<std::uint8_t>& plaintext,
                                                       const std::array<std::uint8_t, kKeyBytes>& code_hash) {
  std::vector<std::uint8_t> region = plaintext;
  decrypt_region(region, code_hash, kSeed, kNonce.data());  // same call encrypts and decrypts
  return region;
}

TEST(AtRest, hashRegion_whenBytesDifferByOne_differsInTheDigest) {
  std::vector<std::uint8_t> bytes = code_bytes();
  const std::array<std::uint8_t, kKeyBytes> before = hash_region(bytes);
  bytes[100] ^= 0x01U;
  const std::array<std::uint8_t, kKeyBytes> after = hash_region(bytes);

  EXPECT_NE(before, after);
}

TEST(AtRest, deriveKey_whenTheCodeHashIsTheSame_givesTheSameKey) {
  const std::array<std::uint8_t, kKeyBytes> code_hash = hash_region(code_bytes());

  EXPECT_EQ(derive_key(code_hash, kSeed), derive_key(code_hash, kSeed));
}

TEST(AtRest, deriveKey_whenTheCodeHashDiffers_givesADifferentKey) {
  std::vector<std::uint8_t> code = code_bytes();
  const std::array<std::uint8_t, kKeyBytes> genuine = derive_key(hash_region(code), kSeed);
  code[0] ^= 0x01U;  // a patched runtime
  const std::array<std::uint8_t, kKeyBytes> patched = derive_key(hash_region(code), kSeed);

  EXPECT_NE(genuine, patched);
}

TEST(AtRest, decryptRegion_whenTheRuntimeIsIntact_recoversThePlaintext) {
  const std::vector<std::uint8_t> plaintext = region_plaintext();
  const std::array<std::uint8_t, kKeyBytes> code_hash = hash_region(code_bytes());
  std::vector<std::uint8_t> region = packer_encrypt(plaintext, code_hash);
  ASSERT_NE(region, plaintext);  // it really is encrypted

  decrypt_region(region, code_hash, kSeed, kNonce.data());

  EXPECT_EQ(region, plaintext);
}

TEST(AtRest, hashFunctions_whenAnyCoveredFunctionIsPatched_changesTheDigest) {
  // Three stand-in functions: the decrypt path and two checks. The key must cover all of them, so patching a check (not
  // the decrypt path) still changes the digest -- the attacker cannot keep decrypt intact and strip a check.
  std::vector<std::uint8_t> decrypt_fn = {0xff, 0x83, 0x00, 0xd1, 0x01, 0x02, 0x03, 0x04};
  std::vector<std::uint8_t> check_a = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22};
  std::vector<std::uint8_t> check_b = {0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00};
  const std::array<CodeSpan, 3> regions = {CodeSpan{decrypt_fn}, CodeSpan{check_a}, CodeSpan{check_b}};
  const std::array<std::uint8_t, kKeyBytes> intact = hash_functions(regions);

  // The attacker leaves the decrypt path alone and patches only a check.
  check_a[0] ^= 0x01U;
  const std::array<CodeSpan, 3> patched_regions = {CodeSpan{decrypt_fn}, CodeSpan{check_a}, CodeSpan{check_b}};
  const std::array<std::uint8_t, kKeyBytes> patched = hash_functions(patched_regions);

  EXPECT_NE(intact, patched);
}

TEST(AtRest, hashFunctions_whenAllCoveredFunctionsAreIntact_givesTheSameDigest) {
  const std::vector<std::uint8_t> a = {0x01, 0x02, 0x03, 0x04};
  const std::vector<std::uint8_t> b = {0x05, 0x06, 0x07, 0x08};
  const std::array<CodeSpan, 2> regions = {CodeSpan{a}, CodeSpan{b}};

  EXPECT_EQ(hash_functions(regions), hash_functions(regions));
}

TEST(AtRest, hashFunctions_whenAByteMovesBetweenRegions_stillChangesTheDigest) {
  // The length separators make region boundaries part of the input, so the same bytes split differently differ.
  const std::vector<std::uint8_t> left = {0x01, 0x02, 0x03};
  const std::vector<std::uint8_t> right = {0x04, 0x05};
  const std::array<CodeSpan, 2> split_three_two = {CodeSpan{left}, CodeSpan{right}};

  const std::vector<std::uint8_t> left2 = {0x01, 0x02};
  const std::vector<std::uint8_t> right2 = {0x03, 0x04, 0x05};
  const std::array<CodeSpan, 2> split_two_three = {CodeSpan{left2}, CodeSpan{right2}};

  EXPECT_NE(hash_functions(split_three_two), hash_functions(split_two_three));
}

TEST(AtRest, decryptRegion_whenTheRuntimeIsPatched_doesNotRecoverThePlaintext) {
  const std::vector<std::uint8_t> plaintext = region_plaintext();
  std::vector<std::uint8_t> code = code_bytes();
  const std::array<std::uint8_t, kKeyBytes> genuine_hash = hash_region(code);
  std::vector<std::uint8_t> region = packer_encrypt(plaintext, genuine_hash);

  // The attacker patched a runtime function; the hash the runtime computes at load now differs.
  code[200] ^= 0x01U;
  const std::array<std::uint8_t, kKeyBytes> patched_hash = hash_region(code);
  decrypt_region(region, patched_hash, kSeed, kNonce.data());

  EXPECT_NE(region, plaintext);
}

}  // namespace
}  // namespace rasp::ios::selfdecrypt
