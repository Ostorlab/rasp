// Tests for the writer of DEX-encoded values.

#include "raw/byte_writer.hpp"

#include <cstdint>
#include <gtest/gtest.h>
#include <limits>
#include <vector>

#include "raw/parsing_utils.hpp"
#include "raw/types.hpp"

namespace dexsplit::raw {
namespace {

using parse_utils::read_sleb128;
using parse_utils::read_uint16;
using parse_utils::read_uint32;
using parse_utils::read_uleb128;

std::vector<uint8_t> uleb128_bytes(uint32_t value)
{
    ByteWriter writer;
    writer.uleb128(value);
    return writer.take();
}

std::vector<uint8_t> sleb128_bytes(int32_t value)
{
    ByteWriter writer;
    writer.sleb128(value);
    return writer.take();
}

TEST(ByteWriter, size_whenNothingWasWritten_returnsZero)
{
    ByteWriter writer;

    EXPECT_EQ(writer.size(), 0u);
}

TEST(ByteWriter, size_whenBytesWereWritten_returnsTheirCount)
{
    ByteWriter writer;
    writer.u8(1);
    writer.u16(2);
    writer.u32(3);

    EXPECT_EQ(writer.size(), 7u);
}

TEST(ByteWriter, bytes_whenNothingWasWritten_returnsAnEmptyBuffer)
{
    ByteWriter writer;

    EXPECT_TRUE(writer.bytes().empty());
}

TEST(ByteWriter, bytes_whenValuesWereWritten_returnsThemInOrder)
{
    ByteWriter writer;
    writer.u8(0x01);
    writer.u16(0x0302);

    EXPECT_EQ(writer.bytes(), (std::vector<uint8_t>{0x01, 0x02, 0x03}));
}

TEST(ByteWriter, take_whenBytesWereWritten_returnsThemAndLeavesTheWriterEmpty)
{
    ByteWriter writer;
    writer.u8(0xAB);
    writer.u8(0xCD);

    std::vector<uint8_t> taken = writer.take();

    EXPECT_EQ(taken, (std::vector<uint8_t>{0xAB, 0xCD}));
    EXPECT_EQ(writer.size(), 0u);
}

TEST(ByteWriter, u8_whenCalled_appendsOneByte)
{
    ByteWriter writer;
    writer.u8(0x00);
    writer.u8(0xFF);

    EXPECT_EQ(writer.bytes(), (std::vector<uint8_t>{0x00, 0xFF}));
}

TEST(ByteWriter, u16_whenCalled_writesTheLowByteFirst)
{
    ByteWriter writer;
    writer.u16(0x1234);

    EXPECT_EQ(writer.bytes(), (std::vector<uint8_t>{0x34, 0x12}));
}

TEST(ByteWriter, u16_whenReadBack_returnsTheSameValue)
{
    for (uint16_t value : {uint16_t{0}, uint16_t{1}, uint16_t{0x1234}, uint16_t{0xFFFF}}) {
        ByteWriter writer;
        writer.u16(value);
        uint32_t offset = 0;

        auto back = read_uint16(writer.bytes(), offset);

        ASSERT_TRUE(back.has_value()) << value;
        EXPECT_EQ(*back, value);
        EXPECT_EQ(offset, writer.size()) << value;
    }
}

TEST(ByteWriter, u32_whenCalled_writesTheLowByteFirst)
{
    ByteWriter writer;
    writer.u32(0x12345678);

    EXPECT_EQ(writer.bytes(), (std::vector<uint8_t>{0x78, 0x56, 0x34, 0x12}));
}

TEST(ByteWriter, u32_whenReadBack_returnsTheSameValue)
{
    for (uint32_t value : {0u, 1u, 0x12345678u, 0xFFFFFFFFu}) {
        ByteWriter writer;
        writer.u32(value);
        uint32_t offset = 0;

        auto back = read_uint32(writer.bytes(), offset);

        ASSERT_TRUE(back.has_value()) << value;
        EXPECT_EQ(*back, value);
        EXPECT_EQ(offset, writer.size()) << value;
    }
}

TEST(ByteWriter, uleb128_whenValueIsZero_writesOneZeroByte)
{
    EXPECT_EQ(uleb128_bytes(0), (std::vector<uint8_t>{0x00}));
}

TEST(ByteWriter, uleb128_whenValueIs127_writesOneByte)
{
    EXPECT_EQ(uleb128_bytes(127), (std::vector<uint8_t>{0x7F}));
}

TEST(ByteWriter, uleb128_whenValueIs128_writesTwoBytes)
{
    EXPECT_EQ(uleb128_bytes(128), (std::vector<uint8_t>{0x80, 0x01}));
}

TEST(ByteWriter, uleb128_whenValueIs624485_writesThreeBytes)
{
    EXPECT_EQ(uleb128_bytes(624485), (std::vector<uint8_t>{0xE5, 0x8E, 0x26}));
}

TEST(ByteWriter, uleb128_whenValueIsTheMaximum_writesFiveBytes)
{
    EXPECT_EQ(uleb128_bytes(0xFFFFFFFF), (std::vector<uint8_t>{0xFF, 0xFF, 0xFF, 0xFF, 0x0F}));
}

TEST(ByteWriter, uleb128_whenReadBack_returnsTheSameValue)
{
    for (uint32_t value : {0u, 127u, 128u, 16383u, 16384u, 0x7FFFFFFFu, 0xFFFFFFFFu}) {
        std::vector<uint8_t> bytes = uleb128_bytes(value);
        uint32_t offset = 0;

        auto back = read_uleb128(bytes, offset);

        ASSERT_TRUE(back.has_value()) << value;
        EXPECT_EQ(*back, value);
        EXPECT_EQ(offset, bytes.size()) << value;
    }
}

TEST(ByteWriter, sleb128_whenValueIsZero_writesOneZeroByte)
{
    EXPECT_EQ(sleb128_bytes(0), (std::vector<uint8_t>{0x00}));
}

TEST(ByteWriter, sleb128_whenValueIsMinusOne_writesOneByte)
{
    EXPECT_EQ(sleb128_bytes(-1), (std::vector<uint8_t>{0x7F}));
}

TEST(ByteWriter, sleb128_whenValueIs63_writesOneByte)
{
    EXPECT_EQ(sleb128_bytes(63), (std::vector<uint8_t>{0x3F}));
}

TEST(ByteWriter, sleb128_whenValueIs64_writesTwoBytesToKeepTheSign)
{
    EXPECT_EQ(sleb128_bytes(64), (std::vector<uint8_t>{0xC0, 0x00}));
}

TEST(ByteWriter, sleb128_whenValueIsMinus64_writesOneByte)
{
    EXPECT_EQ(sleb128_bytes(-64), (std::vector<uint8_t>{0x40}));
}

TEST(ByteWriter, sleb128_whenValueIsMinus65_writesTwoBytesToKeepTheSign)
{
    EXPECT_EQ(sleb128_bytes(-65), (std::vector<uint8_t>{0xBF, 0x7F}));
}

TEST(ByteWriter, sleb128_whenValueIsTheMinimum_writesFiveBytes)
{
    EXPECT_EQ(sleb128_bytes(std::numeric_limits<int32_t>::min()),
              (std::vector<uint8_t>{0x80, 0x80, 0x80, 0x80, 0x78}));
}

TEST(ByteWriter, sleb128_whenValueIsTheMaximum_writesFiveBytes)
{
    EXPECT_EQ(sleb128_bytes(std::numeric_limits<int32_t>::max()),
              (std::vector<uint8_t>{0xFF, 0xFF, 0xFF, 0xFF, 0x07}));
}

TEST(ByteWriter, sleb128_whenReadBack_returnsTheSameValue)
{
    for (int32_t value : {0, -1, 63, 64, -64, -65, std::numeric_limits<int32_t>::min(),
                          std::numeric_limits<int32_t>::max()}) {
        std::vector<uint8_t> bytes = sleb128_bytes(value);
        uint32_t offset = 0;

        auto back = read_sleb128(bytes, offset);

        ASSERT_TRUE(back.has_value()) << value;
        EXPECT_EQ(*back, value);
        EXPECT_EQ(offset, bytes.size()) << value;
    }
}

TEST(ByteWriter, uleb128p1_whenValueIsNoIndex_writesOneZeroByte)
{
    ByteWriter writer;
    writer.uleb128p1(NO_INDEX);

    EXPECT_EQ(writer.bytes(), (std::vector<uint8_t>{0x00}));
}

TEST(ByteWriter, uleb128p1_whenValueIsZero_writesOne)
{
    ByteWriter writer;
    writer.uleb128p1(0);

    EXPECT_EQ(writer.bytes(), (std::vector<uint8_t>{0x01}));
}

TEST(ByteWriter, uleb128p1_whenValueIs127_writesTheTwoBytesOf128)
{
    ByteWriter writer;
    writer.uleb128p1(127);

    EXPECT_EQ(writer.bytes(), (std::vector<uint8_t>{0x80, 0x01}));
}

TEST(ByteWriter, uleb128p1_whenReadBack_returnsTheValuePlusOne)
{
    ByteWriter writer;
    writer.uleb128p1(0x1234);
    uint32_t offset = 0;

    auto back = read_uleb128(writer.bytes(), offset);

    ASSERT_TRUE(back.has_value());
    EXPECT_EQ(*back, 0x1235u);
}

TEST(ByteWriter, append_whenGivenBytes_addsThemAfterTheExistingOnes)
{
    ByteWriter writer;
    writer.u8(0x01);
    const std::vector<uint8_t> data = {0x02, 0x03, 0x04};

    writer.append(data);

    EXPECT_EQ(writer.bytes(), (std::vector<uint8_t>{0x01, 0x02, 0x03, 0x04}));
}

TEST(ByteWriter, append_whenGivenNoBytes_writesNothing)
{
    ByteWriter writer;
    writer.u8(0x01);

    writer.append({});

    EXPECT_EQ(writer.bytes(), (std::vector<uint8_t>{0x01}));
}

TEST(ByteWriter, align_whenSizeIsNotAMultiple_padsWithZeroBytes)
{
    ByteWriter writer;
    writer.u8(0xAA);

    writer.align(4);

    EXPECT_EQ(writer.bytes(), (std::vector<uint8_t>{0xAA, 0x00, 0x00, 0x00}));
}

TEST(ByteWriter, align_whenSizeIsAlreadyAMultiple_writesNothing)
{
    ByteWriter writer;
    writer.u32(0xAABBCCDD);

    writer.align(4);

    EXPECT_EQ(writer.size(), 4u);
}

TEST(ByteWriter, align_whenWriterIsEmpty_writesNothing)
{
    ByteWriter writer;

    writer.align(4);

    EXPECT_EQ(writer.size(), 0u);
}

TEST(ByteWriter, putU32_whenCalled_overwritesFourBytesAndKeepsTheOthers)
{
    ByteWriter writer;
    writer.u8(0xAA);
    writer.u32(0);
    writer.u8(0xBB);

    writer.put_u32(1, 0x12345678);

    EXPECT_EQ(writer.bytes(), (std::vector<uint8_t>{0xAA, 0x78, 0x56, 0x34, 0x12, 0xBB}));
}

} // namespace
} // namespace dexsplit::raw
