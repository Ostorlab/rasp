/// Tests for sha256 and hmac_sha256, against the test vectors of FIPS 180-4 and RFC 4231.

#include "rasp/util/sha256.h"

#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <vector>

namespace rasp {
namespace {

/// The bytes of `text`.
[[nodiscard]] std::vector<std::uint8_t> bytes_of(std::string_view text) { return {text.begin(), text.end()}; }

/// Writes `digest` as lowercase hex digits, two per byte.
[[nodiscard]] std::string to_hex(const Sha256Digest& digest) {
  constexpr std::string_view kHexDigits = "0123456789abcdef";
  std::string text;
  text.reserve(2 * digest.size());
  for (const std::uint8_t byte : digest) {
    text.push_back(kHexDigits[byte >> 4U]);
    text.push_back(kHexDigits[byte & 0x0FU]);
  }
  return text;
}

TEST(Sha256, sha256_whenGivenNoBytes_returnsTheDigestOfTheEmptyMessage) {
  EXPECT_EQ(to_hex(sha256({})), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(Sha256, sha256_whenGivenAbc_returnsTheFipsDigest) {
  EXPECT_EQ(to_hex(sha256(bytes_of("abc"))), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(Sha256, sha256_whenThePaddingNeedsASecondBlock_returnsTheFipsDigest) {
  EXPECT_EQ(to_hex(sha256(bytes_of("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

TEST(Sha256, sha256_whenTheMessageFillsTheFirstBlockWithItsPadding_returnsTheDigest) {
  EXPECT_EQ(to_hex(sha256(std::vector<std::uint8_t>(55, 'a'))),
            "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318");
}

TEST(Sha256, sha256_whenTheMessageIsExactlyOneBlock_returnsTheDigest) {
  EXPECT_EQ(to_hex(sha256(std::vector<std::uint8_t>(64, 'a'))),
            "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb");
}

TEST(Sha256, sha256_whenTheMessageSpansSeveralBlocks_returnsTheFipsDigest) {
  EXPECT_EQ(to_hex(sha256(bytes_of("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopq"
                                   "klmnopqrlmnopqrsmnopqrstnopqrstu"))),
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
}

TEST(Sha256, sha256_whenGivenOneMillionBytes_returnsTheFipsDigest) {
  constexpr std::size_t kMillion = 1'000'000;

  EXPECT_EQ(to_hex(sha256(std::vector<std::uint8_t>(kMillion, 'a'))),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

TEST(HmacSha256, hmacSha256_whenGivenRfc4231TestCase1_returnsItsTag) {
  EXPECT_EQ(to_hex(hmac_sha256(std::vector<std::uint8_t>(20, 0x0b), bytes_of("Hi There"))),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
}

TEST(HmacSha256, hmacSha256_whenTheKeyIsShorterThanABlock_returnsTheRfc4231Tag) {
  EXPECT_EQ(to_hex(hmac_sha256(bytes_of("Jefe"), bytes_of("what do ya want for nothing?"))),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}

TEST(HmacSha256, hmacSha256_whenTheKeyIsExactlyOneBlock_usesTheKeyAsItIs) {
  EXPECT_EQ(to_hex(hmac_sha256(std::vector<std::uint8_t>(64, 0xaa), bytes_of("exactly one block key"))),
            "a070cce143022ab2ac2136358023c8c78babe36c586ccf6dac456c18dfa00eba");
}

TEST(HmacSha256, hmacSha256_whenTheKeyIsLongerThanABlock_hashesTheKeyFirst) {
  EXPECT_EQ(to_hex(hmac_sha256(std::vector<std::uint8_t>(131, 0xaa),
                               bytes_of("Test Using Larger Than Block-Size Key - Hash Key First"))),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
}

}  // namespace
}  // namespace rasp
