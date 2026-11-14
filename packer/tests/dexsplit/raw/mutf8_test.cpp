// Tests for the lossless conversion between DEX string data (MUTF-8) and WTF-8.

#include "raw/mutf8.hpp"

#include <cstdint>
#include <gtest/gtest.h>
#include <random>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace dexsplit::raw {
namespace {

std::vector<uint8_t> item(uint32_t utf16_size, std::vector<uint8_t> bytes)
{
    std::vector<uint8_t> out;
    do {
        uint8_t b = utf16_size & 0x7F;
        utf16_size >>= 7;
        out.push_back(utf16_size ? (b | 0x80) : b);
    } while (utf16_size);
    out.insert(out.end(), bytes.begin(), bytes.end());
    out.push_back(0);
    return out;
}

std::string decode(uint32_t utf16_size, std::vector<uint8_t> bytes)
{
    auto buf = item(utf16_size, std::move(bytes));
    auto r = mutf8::decode_string_data(buf, 0);
    EXPECT_TRUE(r.has_value()) << (r ? "" : r.error().message);
    return r ? *r : std::string("<error>");
}

bool rejects(uint32_t utf16_size, std::vector<uint8_t> bytes)
{
    auto buf = item(utf16_size, std::move(bytes));
    return !mutf8::decode_string_data(buf, 0).has_value();
}

std::vector<uint8_t> encode(std::string_view s)
{
    std::vector<uint8_t> out;
    mutf8::append_mutf8(s, out);
    return out;
}

TEST(Mutf8, decodeStringData_whenBytesAreAscii_returnsThem)
{
    EXPECT_EQ(decode(3, {'a', 'b', 'c'}), "abc");
}

TEST(Mutf8, decodeStringData_whenSequenceHasTwoBytes_returnsItUnchanged)
{
    EXPECT_EQ(decode(1, {0xC3, 0xA9}), "\xC3\xA9");
}

TEST(Mutf8, decodeStringData_whenSequenceHasThreeBytes_returnsItUnchanged)
{
    EXPECT_EQ(decode(1, {0xE2, 0x82, 0xAC}), "\xE2\x82\xAC");
}

TEST(Mutf8, decodeStringData_whenStringIsEmpty_returnsEmpty) { EXPECT_EQ(decode(0, {}), ""); }

TEST(Mutf8, decodeStringData_whenNulIsEncodedAsTwoBytes_returnsOneZeroByte)
{
    EXPECT_EQ(decode(3, {'a', 0xC0, 0x80, 'b'}), std::string("a\0b", 3));
}

TEST(Mutf8, decodeStringData_whenBytesAreASurrogatePair_returnsOneFourByteCharacter)
{
    EXPECT_EQ(decode(2, {0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80}), "\xF0\x9F\x98\x80");
}

TEST(Mutf8, decodeStringData_whenHighSurrogateEndsTheString_keepsItsThreeBytes)
{
    EXPECT_EQ(decode(2, {'a', 0xED, 0xA0, 0x80}), "a\xED\xA0\x80");
}

TEST(Mutf8, decodeStringData_whenLowSurrogateIsAlone_keepsItsThreeBytes)
{
    EXPECT_EQ(decode(1, {0xED, 0xB0, 0x80}), "\xED\xB0\x80");
}

TEST(Mutf8, decodeStringData_whenHighSurrogateIsFollowedByAscii_keepsItsThreeBytes)
{
    EXPECT_EQ(decode(2, {0xED, 0xA0, 0x80, 'x'}), "\xED\xA0\x80x");
}

TEST(Mutf8, decodeStringData_whenSurrogateIsUnpaired_differsFromTheReplacementCharacter)
{
    EXPECT_NE(decode(1, {0xED, 0xA0, 0x80}), decode(1, {0xEF, 0xBF, 0xBD}));
}

TEST(Mutf8, decodeStringData_whenContinuationByteIsStray_returnsAnError)
{
    EXPECT_TRUE(rejects(1, {0x80}));
}

TEST(Mutf8, decodeStringData_whenSequenceHasFourBytes_returnsAnError)
{
    EXPECT_TRUE(rejects(1, {0xF0, 0x9F, 0x98, 0x80}));
}

TEST(Mutf8, decodeStringData_whenTwoByteSequenceIsOverlong_returnsAnError)
{
    EXPECT_TRUE(rejects(1, {0xC0, 0x81}));
}

TEST(Mutf8, decodeStringData_whenThreeByteSequenceIsOverlong_returnsAnError)
{
    EXPECT_TRUE(rejects(1, {0xE0, 0x80, 0x80}));
}

TEST(Mutf8, decodeStringData_whenContinuationByteIsBad_returnsAnError)
{
    EXPECT_TRUE(rejects(1, {0xC3, 0x41}));
}

TEST(Mutf8, decodeStringData_whenStringIsShorterThanDeclared_returnsAnError)
{
    EXPECT_TRUE(rejects(2, {'a'}));
}

TEST(Mutf8, decodeStringData_whenStringIsLongerThanDeclared_returnsAnError)
{
    EXPECT_TRUE(rejects(1, {'a', 'b'}));
}

TEST(Mutf8, decodeStringData_whenTerminatorIsMissing_returnsAnError)
{
    std::vector<uint8_t> cut = {0x02, 'a'};

    EXPECT_FALSE(mutf8::decode_string_data(cut, 0).has_value());
}

TEST(Mutf8, decodeStringData_whenBytesAreRandomCodeUnits_roundTripsThroughAppendMutf8)
{
    std::mt19937 rng(20261020);
    for (int round = 0; round < 2000; ++round) {
        std::vector<uint8_t> bytes;
        uint32_t units = rng() % 12;
        for (uint32_t i = 0; i < units; ++i) {
            uint32_t u = rng() % 4 == 0 ? 0xD800 + rng() % 0x800 : rng() % 0x10000;
            if (u != 0 && u < 0x80) {
                bytes.push_back(static_cast<uint8_t>(u));
            }
            else if (u < 0x800) {
                bytes.push_back(static_cast<uint8_t>(0xC0 | (u >> 6)));
                bytes.push_back(static_cast<uint8_t>(0x80 | (u & 0x3F)));
            }
            else {
                bytes.push_back(static_cast<uint8_t>(0xE0 | (u >> 12)));
                bytes.push_back(static_cast<uint8_t>(0x80 | ((u >> 6) & 0x3F)));
                bytes.push_back(static_cast<uint8_t>(0x80 | (u & 0x3F)));
            }
        }
        auto buf = item(units, bytes);

        auto s = mutf8::decode_string_data(buf, 0);

        ASSERT_TRUE(s.has_value());
        EXPECT_TRUE(mutf8::is_valid_wtf8(*s));
        EXPECT_TRUE(mutf8::is_canonical(*s));
        EXPECT_EQ(mutf8::utf16_length(*s), units);
        EXPECT_EQ(encode(*s), bytes);
    }
}

TEST(Mutf8, appendMutf8_whenOutputIsDecoded_returnsTheSameString)
{
    const std::vector<std::string> samples = {
        "",
        "plain",
        std::string("a\0b", 3),
        "\xC3\xA9",
        "\xE2\x82\xAC",
        "\xF0\x9F\x98\x80",
        "a\xED\xA0\x80",
        "\xED\xB0\x80z",
    };
    for (const std::string &s : samples) {
        auto buf = item(mutf8::utf16_length(s), encode(s));

        auto back = mutf8::decode_string_data(buf, 0);

        ASSERT_TRUE(back.has_value()) << s;
        EXPECT_EQ(*back, s);
    }
}

TEST(Mutf8, appendMutf8_whenStringHasAZeroByte_writesC080)
{
    EXPECT_EQ(encode(std::string("\0", 1)), (std::vector<uint8_t>{0xC0, 0x80}));
}

TEST(Mutf8, appendMutf8_whenCharacterIsSupplementary_writesASurrogatePair)
{
    EXPECT_EQ(encode("\xF0\x9F\x98\x80"),
              (std::vector<uint8_t>{0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80}));
}

TEST(Mutf8, utf16Length_whenStringIsAscii_countsOneUnitPerByte)
{
    EXPECT_EQ(mutf8::utf16_length("abc"), 3u);
}

TEST(Mutf8, utf16Length_whenCharacterIsSupplementary_countsTwoUnits)
{
    EXPECT_EQ(mutf8::utf16_length("\xF0\x9F\x98\x80"), 2u);
}

TEST(Mutf8, utf16Length_whenSurrogateIsUnpaired_countsOneUnit)
{
    EXPECT_EQ(mutf8::utf16_length("\xED\xA0\x80"), 1u);
}

TEST(Mutf8, utf16Length_whenStringIsAZeroByte_countsOneUnit)
{
    EXPECT_EQ(mutf8::utf16_length(std::string("\0", 1)), 1u);
}

TEST(Mutf8, isValidWtf8_whenStringIsAscii_returnsTrue) { EXPECT_TRUE(mutf8::is_valid_wtf8("abc")); }

TEST(Mutf8, isValidWtf8_whenSurrogateIsUnpaired_returnsTrue)
{
    EXPECT_TRUE(mutf8::is_valid_wtf8("\xED\xA0\x80"));
}

TEST(Mutf8, isValidWtf8_whenCodePointIsTheLargest_returnsTrue)
{
    EXPECT_TRUE(mutf8::is_valid_wtf8("\xF4\x8F\xBF\xBF"));
}

TEST(Mutf8, isValidWtf8_whenSequenceIsOverlong_returnsFalse)
{
    EXPECT_FALSE(mutf8::is_valid_wtf8("\xC0\x80"));
}

TEST(Mutf8, isValidWtf8_whenCodePointIsAboveTheLargest_returnsFalse)
{
    EXPECT_FALSE(mutf8::is_valid_wtf8("\xF4\x90\x80\x80"));
}

TEST(Mutf8, isValidWtf8_whenSequenceIsCutOff_returnsFalse)
{
    EXPECT_FALSE(mutf8::is_valid_wtf8("\xC3"));
}

TEST(Mutf8, isValidWtf8_whenByteIsNeverValid_returnsFalse)
{
    EXPECT_FALSE(mutf8::is_valid_wtf8("\xFF"));
}

TEST(Mutf8, isCanonical_whenSurrogatePairIsTwoSequences_returnsFalse)
{
    EXPECT_FALSE(mutf8::is_canonical("\xED\xA0\xBD\xED\xB8\x80"));
}

TEST(Mutf8, isCanonical_whenSupplementaryCharacterIsOneSequence_returnsTrue)
{
    EXPECT_TRUE(mutf8::is_canonical("\xF0\x9F\x98\x80"));
}

TEST(Mutf8, isCanonical_whenSurrogateIsUnpaired_returnsTrue)
{
    EXPECT_TRUE(mutf8::is_canonical("\xED\xA0\x80x"));
}

TEST(Mutf8, canonical_whenSurrogatePairIsTwoSequences_joinsThemIntoOne)
{
    EXPECT_EQ(mutf8::canonical("\xED\xA0\xBD\xED\xB8\x80"), "\xF0\x9F\x98\x80");
}

TEST(Mutf8, canonical_whenSurrogateIsUnpaired_returnsTheStringUnchanged)
{
    EXPECT_EQ(mutf8::canonical("\xED\xA0\x80x"), "\xED\xA0\x80x");
}

TEST(Mutf8, compareUtf16_whenBmpCharacterIsAboveTheSurrogates_ordersItAfterASupplementaryOne)
{
    const std::string bmp = "\xEF\xBF\xBD";
    const std::string supplementary = "\xF0\x9F\x98\x80";

    EXPECT_LT(bmp, supplementary);
    EXPECT_GT(mutf8::compare_utf16(bmp, supplementary), 0);
}

TEST(Mutf8, compareUtf16_whenFirstStringIsSmaller_returnsNegative)
{
    EXPECT_LT(mutf8::compare_utf16("a", "b"), 0);
}

TEST(Mutf8, compareUtf16_whenFirstStringIsAPrefix_returnsNegative)
{
    EXPECT_LT(mutf8::compare_utf16("a", "ab"), 0);
}

TEST(Mutf8, compareUtf16_whenStringsAreEqual_returnsZero)
{
    EXPECT_EQ(mutf8::compare_utf16("same", "same"), 0);
}

TEST(Mutf8, compareUtf16_whenOneStringIsTheSplitFormOfTheOther_returnsZero)
{
    EXPECT_EQ(mutf8::compare_utf16("\xF0\x9F\x98\x80", "\xED\xA0\xBD\xED\xB8\x80"), 0);
}

} // namespace
} // namespace dexsplit::raw
