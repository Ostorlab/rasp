// Tests for the SHA-1 and SHA-256 digests.

#include "raw/digest.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <vector>

namespace dexsplit::raw {
namespace {

template <std::size_t N> std::string hex(const std::array<uint8_t, N> &digest)
{
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    for (uint8_t b : digest) {
        out += digits[b >> 4];
        out += digits[b & 0xF];
    }
    return out;
}

std::vector<uint8_t> bytes(std::string_view s) { return {s.begin(), s.end()}; }

constexpr std::string_view kFiftySixBytes =
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

TEST(Digest, sha1_whenInputIsEmpty_returnsTheKnownDigest)
{
    EXPECT_EQ(hex(sha1(bytes(""))), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
}

TEST(Digest, sha1_whenInputFitsOneBlock_returnsTheKnownDigest)
{
    EXPECT_EQ(hex(sha1(bytes("abc"))), "a9993e364706816aba3e25717850c26c9cd0d89d");
}

TEST(Digest, sha1_whenPaddingNeedsASecondBlock_returnsTheKnownDigest)
{
    EXPECT_EQ(hex(sha1(bytes(kFiftySixBytes))), "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
}

TEST(Digest, sha1_whenInputSpansManyBlocks_returnsTheKnownDigest)
{
    std::vector<uint8_t> million(1000000, 'a');

    EXPECT_EQ(hex(sha1(million)), "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
}

TEST(Digest, sha256_whenInputIsEmpty_returnsTheKnownDigest)
{
    EXPECT_EQ(hex(sha256(bytes(""))),
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(Digest, sha256_whenInputFitsOneBlock_returnsTheKnownDigest)
{
    EXPECT_EQ(hex(sha256(bytes("abc"))),
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(Digest, sha256_whenPaddingNeedsASecondBlock_returnsTheKnownDigest)
{
    EXPECT_EQ(hex(sha256(bytes(kFiftySixBytes))),
              "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

TEST(Digest, sha256_whenInputSpansManyBlocks_returnsTheKnownDigest)
{
    std::vector<uint8_t> million(1000000, 'a');

    EXPECT_EQ(hex(sha256(million)),
              "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

} // namespace
} // namespace dexsplit::raw
