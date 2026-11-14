// Tests for the little-endian integer, LEB128 and MUTF-8 readers.

#include "raw/parsing_utils.hpp"

#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "raw/error.hpp"

namespace dexsplit::raw {
namespace {

using parse_utils::decode_mutf8;
using parse_utils::read_uint16;
using parse_utils::read_uint32;
using parse_utils::read_uleb128;

TEST(ParsingUtils, readUint32_whenValueIsOne_returnsOne)
{
    std::vector<std::uint8_t> buf = {0x01, 0x00, 0x00, 0x00};
    std::uint32_t offset = 0;

    auto result = read_uint32(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 0x01u);
    EXPECT_EQ(offset, 4u);
}

TEST(ParsingUtils, readUint32_whenValueUsesTwoBytes_returnsTheValue)
{
    std::vector<std::uint8_t> buf = {0x34, 0x12, 0x00, 0x00};
    std::uint32_t offset = 0;

    auto result = read_uint32(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 0x1234u);
    EXPECT_EQ(offset, 4u);
}

TEST(ParsingUtils, readUint32_whenValueUsesFourBytes_returnsTheValue)
{
    std::vector<std::uint8_t> buf = {0x78, 0x56, 0x34, 0x12};
    std::uint32_t offset = 0;

    auto result = read_uint32(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 0x12345678u);
    EXPECT_EQ(offset, 4u);
}

TEST(ParsingUtils, readUint32_whenAllBitsAreSet_returnsTheMaximum)
{
    std::vector<std::uint8_t> buf = {0xFF, 0xFF, 0xFF, 0xFF};
    std::uint32_t offset = 0;

    auto result = read_uint32(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 0xFFFFFFFFu);
    EXPECT_EQ(offset, 4u);
}

TEST(ParsingUtils, readUint32_whenAllBytesAreZero_returnsZero)
{
    std::vector<std::uint8_t> buf = {0x00, 0x00, 0x00, 0x00};
    std::uint32_t offset = 0;

    auto result = read_uint32(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 0x00u);
    EXPECT_EQ(offset, 4u);
}

TEST(ParsingUtils, readUint32_whenCalledInSequence_readsOneValuePerCall)
{
    std::vector<std::uint8_t> buf = {0x01, 0x00, 0x00, 0x00, 0x02, 0x00,
                                     0x00, 0x00, 0x03, 0x00, 0x00, 0x00};
    std::uint32_t offset = 0;

    auto r1 = read_uint32(buf, offset);
    ASSERT_TRUE(r1.has_value());
    EXPECT_EQ(*r1, 0x01u);
    EXPECT_EQ(offset, 4u);

    auto r2 = read_uint32(buf, offset);
    ASSERT_TRUE(r2.has_value());
    EXPECT_EQ(*r2, 0x02u);
    EXPECT_EQ(offset, 8u);

    auto r3 = read_uint32(buf, offset);
    ASSERT_TRUE(r3.has_value());
    EXPECT_EQ(*r3, 0x03u);
    EXPECT_EQ(offset, 12u);
}

TEST(ParsingUtils, readUint32_whenOffsetIsInTheMiddle_readsFromThatOffset)
{
    std::vector<std::uint8_t> buf = {0xAA, 0xAA, 0xAA, 0xAA, 0x78, 0x56,
                                     0x34, 0x12, 0xBB, 0xBB, 0xBB, 0xBB};
    std::uint32_t offset = 4;

    auto result = read_uint32(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 0x12345678u);
    EXPECT_EQ(offset, 8u);
}

TEST(ParsingUtils, readUint32_whenBytesAreInBigEndianOrder_readsThemAsLittleEndian)
{
    std::vector<std::uint8_t> buf = {0x12, 0x34, 0x56, 0x78};
    std::uint32_t offset = 0;

    auto result = read_uint32(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 0x78563412u);
    EXPECT_EQ(offset, 4u);
}

TEST(ParsingUtils, readUint32_whenBytesAlternate_keepsEachByteInItsPlace)
{
    std::vector<std::uint8_t> buf = {0xFF, 0x00, 0xFF, 0x00};
    std::uint32_t offset = 0;

    auto result = read_uint32(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 0x00FF00FFu);
    EXPECT_EQ(offset, 4u);
}

TEST(ParsingUtils, readUint32_whenOffsetIsNotAligned_readsFromThatOffset)
{
    std::vector<std::uint8_t> buf = {0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12};
    std::uint32_t offset = 5;

    auto result = read_uint32(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 0x12345678u);
    EXPECT_EQ(offset, 9u);
}

TEST(ParsingUtils, readUint32_whenBytesAreTheDexMagic_returnsItsLittleEndianValue)
{
    std::vector<std::uint8_t> buf = {0x64, 0x65, 0x78, 0x0a};
    std::uint32_t offset = 0;

    auto result = read_uint32(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 0x0a786564u);
    EXPECT_EQ(offset, 4u);
}

TEST(ParsingUtils, readUint32_whenFewerThanFourBytesRemain_returnsOutOfBounds)
{
    std::vector<std::uint8_t> buf = {0x01, 0x02, 0x03};
    std::uint32_t offset = 0;

    auto result = read_uint32(buf, offset);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ParseError::Code::OutOfBounds);
}

TEST(ParsingUtils, readUint32_whenOffsetPlusFourOverflows_returnsOutOfBounds)
{
    std::vector<std::uint8_t> buf(16, 0);
    std::uint32_t offset = 0xFFFFFFFE;

    auto result = read_uint32(buf, offset);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ParseError::Code::OutOfBounds);
}

TEST(ParsingUtils, readUint16_whenValueIsOne_returnsOne)
{
    std::vector<std::uint8_t> buf = {0x01, 0x00};
    std::uint32_t offset = 0;

    auto result = read_uint16(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 0x0001u);
    EXPECT_EQ(offset, 2u);
}

TEST(ParsingUtils, readUint16_whenValueUsesTwoBytes_returnsTheValue)
{
    std::vector<std::uint8_t> buf = {0x34, 0x12};
    std::uint32_t offset = 0;

    auto result = read_uint16(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 0x1234u);
    EXPECT_EQ(offset, 2u);
}

TEST(ParsingUtils, readUint16_whenAllBitsAreSet_returnsTheMaximum)
{
    std::vector<std::uint8_t> buf = {0xFF, 0xFF};
    std::uint32_t offset = 0;

    auto result = read_uint16(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 0xFFFFu);
    EXPECT_EQ(offset, 2u);
}

TEST(ParsingUtils, readUint16_whenAllBytesAreZero_returnsZero)
{
    std::vector<std::uint8_t> buf = {0x00, 0x00};
    std::uint32_t offset = 0;

    auto result = read_uint16(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 0x0000u);
    EXPECT_EQ(offset, 2u);
}

TEST(ParsingUtils, readUint16_whenCalledInSequence_readsOneValuePerCall)
{
    std::vector<std::uint8_t> buf = {0x01, 0x00, 0x02, 0x00, 0x03, 0x00};
    std::uint32_t offset = 0;

    auto r1 = read_uint16(buf, offset);
    ASSERT_TRUE(r1.has_value());
    EXPECT_EQ(*r1, 0x0001u);
    EXPECT_EQ(offset, 2u);

    auto r2 = read_uint16(buf, offset);
    ASSERT_TRUE(r2.has_value());
    EXPECT_EQ(*r2, 0x0002u);
    EXPECT_EQ(offset, 4u);

    auto r3 = read_uint16(buf, offset);
    ASSERT_TRUE(r3.has_value());
    EXPECT_EQ(*r3, 0x0003u);
    EXPECT_EQ(offset, 6u);
}

TEST(ParsingUtils, readUint16_whenOffsetIsInTheMiddle_readsFromThatOffset)
{
    std::vector<std::uint8_t> buf = {0xAA, 0xAA, 0x34, 0x12, 0xBB, 0xBB};
    std::uint32_t offset = 2;

    auto result = read_uint16(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 0x1234u);
    EXPECT_EQ(offset, 4u);
}

TEST(ParsingUtils, readUint16_whenBytesAreInBigEndianOrder_readsThemAsLittleEndian)
{
    std::vector<std::uint8_t> buf = {0x12, 0x34};
    std::uint32_t offset = 0;

    auto result = read_uint16(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 0x3412u);
    EXPECT_EQ(offset, 2u);
}

TEST(ParsingUtils, readUint16_whenBytesAlternate_keepsEachByteInItsPlace)
{
    std::vector<std::uint8_t> buf = {0xFF, 0x00};
    std::uint32_t offset = 0;

    auto result = read_uint16(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 0x00FFu);
    EXPECT_EQ(offset, 2u);
}

TEST(ParsingUtils, readUint16_whenOffsetIsNotAligned_readsFromThatOffset)
{
    std::vector<std::uint8_t> buf = {0x00, 0x00, 0x00, 0x34, 0x12};
    std::uint32_t offset = 3;

    auto result = read_uint16(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 0x1234u);
    EXPECT_EQ(offset, 5u);
}

TEST(ParsingUtils, readUint16_whenBytesAreTheDexHeaderSize_returns0x70)
{
    std::vector<std::uint8_t> buf = {0x70, 0x00};
    std::uint32_t offset = 0;

    auto result = read_uint16(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 0x0070u);
    EXPECT_EQ(offset, 2u);
}

TEST(ParsingUtils, readUint16_whenFewerThanTwoBytesRemain_returnsOutOfBounds)
{
    std::vector<std::uint8_t> buf = {0x01};
    std::uint32_t offset = 0;

    auto result = read_uint16(buf, offset);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ParseError::Code::OutOfBounds);
}

TEST(ParsingUtils, readUint16_whenOffsetPlusTwoOverflows_returnsOutOfBounds)
{
    std::vector<std::uint8_t> buf(16, 0);
    std::uint32_t offset = 0xFFFFFFFF;

    auto result = read_uint16(buf, offset);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ParseError::Code::OutOfBounds);
}

TEST(ParsingUtils, readUleb128_whenValueIsZero_returnsZero)
{
    std::vector<std::uint8_t> buf = {0x00};
    std::uint32_t offset = 0;

    auto result = read_uleb128(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 0u);
    EXPECT_EQ(offset, 1u);
}

TEST(ParsingUtils, readUleb128_whenValuesFitOneByte_readsOneBytePerValue)
{
    std::vector<std::uint8_t> buf = {0x01, 0x7F};
    std::uint32_t offset = 0;

    auto r1 = read_uleb128(buf, offset);
    ASSERT_TRUE(r1.has_value());
    EXPECT_EQ(*r1, 0x01u);
    EXPECT_EQ(offset, 1u);

    auto r2 = read_uleb128(buf, offset);
    ASSERT_TRUE(r2.has_value());
    EXPECT_EQ(*r2, 0x7Fu);
    EXPECT_EQ(offset, 2u);
}

TEST(ParsingUtils, readUleb128_whenValueIs128_readsTwoBytes)
{
    std::vector<std::uint8_t> buf = {0x80, 0x01};
    std::uint32_t offset = 0;

    auto result = read_uleb128(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 128u);
    EXPECT_EQ(offset, 2u);
}

TEST(ParsingUtils, readUleb128_whenValueIs129_readsTwoBytes)
{
    std::vector<std::uint8_t> buf = {0x81, 0x01};
    std::uint32_t offset = 0;

    auto result = read_uleb128(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 129u);
    EXPECT_EQ(offset, 2u);
}

TEST(ParsingUtils, readUleb128_whenValueIsTheTwoByteMaximum_returns16383)
{
    std::vector<std::uint8_t> buf = {0xFF, 0x7F};
    std::uint32_t offset = 0;

    auto result = read_uleb128(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 16383u);
    EXPECT_EQ(offset, 2u);
}

TEST(ParsingUtils, readUleb128_whenValueIs16384_readsThreeBytes)
{
    std::vector<std::uint8_t> buf = {0x80, 0x80, 0x01};
    std::uint32_t offset = 0;

    auto result = read_uleb128(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 16384u);
    EXPECT_EQ(offset, 3u);
}

TEST(ParsingUtils, readUleb128_whenValueIsTheThreeByteMaximum_returns2097151)
{
    std::vector<std::uint8_t> buf = {0xFF, 0xFF, 0x7F};
    std::uint32_t offset = 0;

    auto result = read_uleb128(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 2097151u);
    EXPECT_EQ(offset, 3u);
}

TEST(ParsingUtils, readUleb128_whenValueIs2097152_readsFourBytes)
{
    std::vector<std::uint8_t> buf = {0x80, 0x80, 0x80, 0x01};
    std::uint32_t offset = 0;

    auto result = read_uleb128(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 2097152u);
    EXPECT_EQ(offset, 4u);
}

TEST(ParsingUtils, readUleb128_whenValueIsTheFiveByteMaximum_returns4294967295)
{
    std::vector<std::uint8_t> buf = {0xFF, 0xFF, 0xFF, 0xFF, 0x0F};
    std::uint32_t offset = 0;

    auto result = read_uleb128(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 4294967295u);
    EXPECT_EQ(offset, 5u);
}

TEST(ParsingUtils, readUleb128_whenCalledInSequence_readsOneValuePerCall)
{
    std::vector<std::uint8_t> buf = {0x01, 0x7F, 0x80, 0x01, 0xFF, 0x7F};
    std::uint32_t offset = 0;

    auto r1 = read_uleb128(buf, offset);
    ASSERT_TRUE(r1.has_value());
    EXPECT_EQ(*r1, 0x01u);
    EXPECT_EQ(offset, 1u);

    auto r2 = read_uleb128(buf, offset);
    ASSERT_TRUE(r2.has_value());
    EXPECT_EQ(*r2, 0x7Fu);
    EXPECT_EQ(offset, 2u);

    auto r3 = read_uleb128(buf, offset);
    ASSERT_TRUE(r3.has_value());
    EXPECT_EQ(*r3, 128u);
    EXPECT_EQ(offset, 4u);

    auto r4 = read_uleb128(buf, offset);
    ASSERT_TRUE(r4.has_value());
    EXPECT_EQ(*r4, 16383u);
    EXPECT_EQ(offset, 6u);
}

TEST(ParsingUtils, readUleb128_whenOffsetIsInTheMiddle_readsFromThatOffset)
{
    std::vector<std::uint8_t> buf = {0xFF, 0xFF, 0xFF, 0x80, 0x80, 0x01, 0xFF, 0xFF, 0xFF};
    std::uint32_t offset = 3;

    auto result = read_uleb128(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 16384u);
    EXPECT_EQ(offset, 6u);
}

TEST(ParsingUtils, readUleb128_whenValueEndsTheBuffer_readsUpToTheLastByte)
{
    std::vector<std::uint8_t> buf = {0x00, 0x00, 0x00, 0xFF, 0x7F};
    std::uint32_t offset = 3;

    auto result = read_uleb128(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 16383u);
    EXPECT_EQ(offset, 5u);
}

TEST(ParsingUtils, readUleb128_whenValueIsFive_readsOneByte)
{
    std::vector<std::uint8_t> buf = {0x05};
    std::uint32_t offset = 0;

    auto result = read_uleb128(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 5u);
    EXPECT_EQ(offset, 1u);
}

TEST(ParsingUtils, readUleb128_whenValueIs624485_readsThreeBytes)
{
    std::vector<std::uint8_t> buf = {0xE5, 0x8E, 0x26};
    std::uint32_t offset = 0;

    auto result = read_uleb128(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 624485u);
    EXPECT_EQ(offset, 3u);
}

TEST(ParsingUtils, readUleb128_whenBufferIsEmpty_returnsOutOfBounds)
{
    std::vector<std::uint8_t> buf = {};
    std::uint32_t offset = 0;

    auto result = read_uleb128(buf, offset);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ParseError::Code::OutOfBounds);
}

TEST(ParsingUtils, readUleb128_whenFiveBytesAllContinue_returnsInvalidLeb128)
{
    std::vector<std::uint8_t> buf = {0x80, 0x80, 0x80, 0x80, 0x80, 0x00};
    std::uint32_t offset = 0;

    auto result = read_uleb128(buf, offset);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ParseError::Code::InvalidLeb128);
}

TEST(ParsingUtils, decodeMutf8_whenStringIsEmpty_returnsEmpty)
{
    std::vector<std::uint8_t> buf = {0x00};
    std::uint32_t offset = 0;

    auto result = decode_mutf8(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, "");
    EXPECT_EQ(offset, 1u);
}

TEST(ParsingUtils, decodeMutf8_whenBytesAreAscii_returnsThem)
{
    std::vector<std::uint8_t> buf = {'H', 'e', 'l', 'l', 'o', 0x00};
    std::uint32_t offset = 0;

    auto result = decode_mutf8(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, "Hello");
    EXPECT_EQ(offset, 6u);
}

TEST(ParsingUtils, decodeMutf8_whenBytesAreASurrogatePair_returnsOneFourByteCharacter)
{
    std::vector<std::uint8_t> buf = {0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80, 0x00};
    std::uint32_t offset = 0;

    auto result = decode_mutf8(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, std::string("\xF0\x9F\x98\x80"));
    EXPECT_EQ(offset, 7u);
}

TEST(ParsingUtils, decodeMutf8_whenHighSurrogateIsUnpaired_returnsTheReplacementCharacter)
{
    std::vector<std::uint8_t> buf = {0xED, 0xA7, 0xBF, 'x', 0x00};
    std::uint32_t offset = 0;

    auto result = decode_mutf8(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, std::string("\xEF\xBF\xBD"
                                   "x"));
}

TEST(ParsingUtils, decodeMutf8_whenStringHasSpaces_keepsThem)
{
    std::vector<std::uint8_t> buf = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', 0x00};
    std::uint32_t offset = 0;

    auto result = decode_mutf8(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, "Hello World");
    EXPECT_EQ(offset, 12u);
}

TEST(ParsingUtils, decodeMutf8_whenNulIsEncodedAsTwoBytes_returnsOneZeroByte)
{
    std::vector<std::uint8_t> buf = {'H', 'i', 0xC0, 0x80, '!', 0x00};
    std::uint32_t offset = 0;

    auto result = decode_mutf8(buf, offset);

    ASSERT_TRUE(result.has_value());
    std::string expected({'H', 'i', '\0', '!'});
    EXPECT_EQ(*result, expected);
    EXPECT_EQ(offset, 6u);
}

TEST(ParsingUtils, decodeMutf8_whenStringHasSeveralEncodedNuls_returnsEachAsAZeroByte)
{
    std::vector<std::uint8_t> buf = {0xC0, 0x80, 'A', 0xC0, 0x80, 'B', 0xC0, 0x80, 0x00};
    std::uint32_t offset = 0;

    auto result = decode_mutf8(buf, offset);

    ASSERT_TRUE(result.has_value());
    std::string expected({'\0', 'A', '\0', 'B', '\0'});
    EXPECT_EQ(*result, expected);
    EXPECT_EQ(offset, 9u);
}

TEST(ParsingUtils, decodeMutf8_whenSequenceHasTwoBytes_returnsItUnchanged)
{
    std::vector<std::uint8_t> buf = {0xC2, 0xA9, 0x00};
    std::uint32_t offset = 0;

    auto result = decode_mutf8(buf, offset);

    ASSERT_TRUE(result.has_value());
    std::string expected({static_cast<char>(0xC2), static_cast<char>(0xA9)});
    EXPECT_EQ(*result, expected);
    EXPECT_EQ(offset, 3u);
}

TEST(ParsingUtils, decodeMutf8_whenSequenceHasThreeBytes_returnsItUnchanged)
{
    std::vector<std::uint8_t> buf = {0xE2, 0x82, 0xAC, 0x00};
    std::uint32_t offset = 0;

    auto result = decode_mutf8(buf, offset);

    ASSERT_TRUE(result.has_value());
    std::string expected(
        {static_cast<char>(0xE2), static_cast<char>(0x82), static_cast<char>(0xAC)});
    EXPECT_EQ(*result, expected);
    EXPECT_EQ(offset, 4u);
}

TEST(ParsingUtils, decodeMutf8_whenSequenceHasFourBytes_returnsInvalidUtf8String)
{
    std::vector<std::uint8_t> buf = {0xF0, 0x9F, 0x98, 0x80, 0x00};
    std::uint32_t offset = 0;

    auto result = decode_mutf8(buf, offset);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ParseError::Code::InvalidUtf8String);
    EXPECT_EQ(result.error().offset, 0u);
}

TEST(ParsingUtils, decodeMutf8_whenAsciiAndMultiByteAreMixed_keepsTheirOrder)
{
    std::vector<std::uint8_t> buf = {'A', 0xC2, 0xA9, 'B', 0xE2, 0x82, 0xAC, 'C', 0x00};
    std::uint32_t offset = 0;

    auto result = decode_mutf8(buf, offset);

    ASSERT_TRUE(result.has_value());
    std::string expected({'A', static_cast<char>(0xC2), static_cast<char>(0xA9), 'B',
                          static_cast<char>(0xE2), static_cast<char>(0x82), static_cast<char>(0xAC),
                          'C'});
    EXPECT_EQ(*result, expected);
    EXPECT_EQ(offset, 9u);
}

TEST(ParsingUtils, decodeMutf8_whenCalledInSequence_readsOneStringPerCall)
{
    std::vector<std::uint8_t> buf = {'F', 'i', 'r', 's', 't', 0x00, 'S',
                                     'e', 'c', 'o', 'n', 'd', 0x00};
    std::uint32_t offset = 0;

    auto r1 = decode_mutf8(buf, offset);
    ASSERT_TRUE(r1.has_value());
    EXPECT_EQ(*r1, "First");
    EXPECT_EQ(offset, 6u);

    auto r2 = decode_mutf8(buf, offset);
    ASSERT_TRUE(r2.has_value());
    EXPECT_EQ(*r2, "Second");
    EXPECT_EQ(offset, 13u);
}

TEST(ParsingUtils, decodeMutf8_whenOffsetIsInTheMiddle_readsFromThatOffset)
{
    std::vector<std::uint8_t> buf = {0xFF, 0xFF, 0xFF, 'M',  'i',  'd', 'd',
                                     'l',  'e',  0x00, 0xFF, 0xFF, 0xFF};
    std::uint32_t offset = 3;

    auto result = decode_mutf8(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, "Middle");
    EXPECT_EQ(offset, 10u);
}

TEST(ParsingUtils, decodeMutf8_whenStringEndsTheBuffer_readsUpToTheTerminator)
{
    std::vector<std::uint8_t> buf = {0x00, 0x00, 0x00, 'O', 'f', 'f', 's', 'e', 't', 0x00};
    std::uint32_t offset = 3;

    auto result = decode_mutf8(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, "Offset");
    EXPECT_EQ(offset, 10u);
}

TEST(ParsingUtils, decodeMutf8_whenStringIsATypeDescriptor_returnsIt)
{
    std::vector<std::uint8_t> buf = {'L', 'j', 'a', 'v', 'a', '/', 'l', 'a', 'n', 'g',
                                     '/', 'O', 'b', 'j', 'e', 'c', 't', ';', 0x00};
    std::uint32_t offset = 0;

    auto result = decode_mutf8(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, "Ljava/lang/Object;");
    EXPECT_EQ(offset, 19u);
}

TEST(ParsingUtils, decodeMutf8_whenStringHasDigitsAndSymbols_keepsThem)
{
    std::vector<std::uint8_t> buf = {'T', 'e', 's', 't', '1', '2', '3', '!', '@',
                                     '#', '$', '%', '^', '&', '*', '(', ')', 0x00};
    std::uint32_t offset = 0;

    auto result = decode_mutf8(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, "Test123!@#$%^&*()");
    EXPECT_EQ(offset, 18u);
}

TEST(ParsingUtils, decodeMutf8_whenStringIsOnlyAnEncodedNul_returnsOneZeroByte)
{
    std::vector<std::uint8_t> buf = {0xC0, 0x80, 0x00};
    std::uint32_t offset = 0;

    auto result = decode_mutf8(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, std::string("\0", 1));
    EXPECT_EQ(offset, 3u);
}

TEST(ParsingUtils, decodeMutf8_whenStringStartsWithAnEncodedNul_keepsTheRest)
{
    std::vector<std::uint8_t> buf = {0xC0, 0x80, 'S', 't', 'a', 'r', 't', 0x00};
    std::uint32_t offset = 0;

    auto result = decode_mutf8(buf, offset);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, std::string("\0Start", 6));
    EXPECT_EQ(offset, 8u);
}

TEST(ParsingUtils, decodeMutf8_whenTerminatorIsMissing_returnsOutOfBounds)
{
    std::vector<std::uint8_t> buf = {'A', 'B', 'C'};
    std::uint32_t offset = 0;

    auto result = decode_mutf8(buf, offset);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ParseError::Code::OutOfBounds);
}

TEST(ParsingUtils, decodeMutf8_whenFourByteLeadIsCutOff_returnsAnError)
{
    std::vector<std::uint8_t> buf = {0xF0, 0x80, 0x80};
    std::uint32_t offset = 0;

    auto result = decode_mutf8(buf, offset);

    EXPECT_FALSE(result.has_value());
}

TEST(ParsingUtils, decodeMutf8_whenThreeByteSequenceIsCutOff_returnsOutOfBounds)
{
    std::vector<std::uint8_t> buf = {0xE0, 0x80};
    std::uint32_t offset = 0;

    auto result = decode_mutf8(buf, offset);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ParseError::Code::OutOfBounds);
}

} // namespace
} // namespace dexsplit::raw
