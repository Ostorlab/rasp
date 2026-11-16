// Tests for the encoder of values and annotations of the DEX writer.

#include "model/value_encoder.hpp"

#include <bit>
#include <cstddef>
#include <cstdint>
#include <format>
#include <gtest/gtest.h>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

#include "common/ids.hpp"
#include "model/io.hpp"
#include "model/pools.hpp"
#include "model/types.hpp"
#include "raw/byte_writer.hpp"
#include "raw/parser.hpp"
#include "raw/types.hpp"
#include "support/models.hpp"

namespace dexsplit::model::detail {
namespace {

using support::write_failure;

using Bytes = std::vector<uint8_t>;

constexpr int64_t kInt64Min = std::numeric_limits<int64_t>::min();
constexpr int64_t kInt64Max = std::numeric_limits<int64_t>::max();
constexpr int32_t kInt32Min = std::numeric_limits<int32_t>::min();
constexpr int32_t kInt32Max = std::numeric_limits<int32_t>::max();

int64_t largest_signed(uint32_t bytes)
{
    return bytes == 8 ? kInt64Max : (int64_t{1} << (8 * bytes - 1)) - 1;
}

int64_t smallest_signed(uint32_t bytes)
{
    return bytes == 8 ? kInt64Min : -(int64_t{1} << (8 * bytes - 1));
}

Pools empty_pools()
{
    Pools pools;
    pools.finish();
    return pools;
}

Pools pools_with_strings(std::size_t count)
{
    Pools pools;
    for (std::size_t i = 0; i < count; ++i)
        pools.add_string(std::format("s{:05}", i));
    pools.finish();
    return pools;
}

Pools pools_with_fields()
{
    Pools pools;
    for (const char *name : {"a", "b", "c"})
        pools.add_field(FieldId{"LA;", name, "I"});
    pools.finish();
    return pools;
}

Bytes encoded(const Value &value, const Pools &pools)
{
    raw::ByteWriter out;
    ValueEncoder(pools).value(out, value);
    return out.take();
}

Bytes encoded(const Value &value) { return encoded(value, empty_pools()); }

raw::EncodedValue parsed(const Bytes &bytes)
{
    uint32_t offset = 0;
    auto value = raw::parser::parse_encoded_value(bytes, offset);
    if (!value.has_value())
        throw std::runtime_error("the parser rejected the value: " + value.error().message);
    if (offset != bytes.size())
        throw std::runtime_error("the parser did not read every byte of the value");
    return std::move(*value);
}

TEST(ValueEncoder, signedSize_whenValueIsZero_returnsOne) { EXPECT_EQ(signed_size(0), 1u); }

TEST(ValueEncoder, signedSize_whenValueIsTheLargestOfAWidth_returnsThatWidth)
{
    for (uint32_t bytes = 1; bytes <= 8; ++bytes)
        EXPECT_EQ(signed_size(largest_signed(bytes)), bytes) << bytes << " bytes";
}

TEST(ValueEncoder, signedSize_whenValueIsOneAboveTheLargestOfAWidth_returnsTheNextWidth)
{
    for (uint32_t bytes = 1; bytes <= 7; ++bytes)
        EXPECT_EQ(signed_size(largest_signed(bytes) + 1), bytes + 1) << bytes << " bytes";
}

TEST(ValueEncoder, signedSize_whenValueIsTheSmallestOfAWidth_returnsThatWidth)
{
    for (uint32_t bytes = 1; bytes <= 8; ++bytes)
        EXPECT_EQ(signed_size(smallest_signed(bytes)), bytes) << bytes << " bytes";
}

TEST(ValueEncoder, signedSize_whenValueIsOneBelowTheSmallestOfAWidth_returnsTheNextWidth)
{
    for (uint32_t bytes = 1; bytes <= 7; ++bytes)
        EXPECT_EQ(signed_size(smallest_signed(bytes) - 1), bytes + 1) << bytes << " bytes";
}

TEST(ValueEncoder, signedSize_whenValueIsMinusOne_returnsOne) { EXPECT_EQ(signed_size(-1), 1u); }

TEST(ValueEncoder, unsignedSize_whenValueIsZero_returnsOne) { EXPECT_EQ(unsigned_size(0), 1u); }

TEST(ValueEncoder, unsignedSize_whenValueIsTheLargestOfAWidth_returnsThatWidth)
{
    for (uint32_t bytes = 1; bytes <= 7; ++bytes)
        EXPECT_EQ(unsigned_size((uint64_t{1} << (8 * bytes)) - 1), bytes) << bytes << " bytes";
    EXPECT_EQ(unsigned_size(std::numeric_limits<uint64_t>::max()), 8u);
}

TEST(ValueEncoder, unsignedSize_whenValueIsOneAboveTheLargestOfAWidth_returnsTheNextWidth)
{
    for (uint32_t bytes = 1; bytes <= 7; ++bytes)
        EXPECT_EQ(unsigned_size(uint64_t{1} << (8 * bytes)), bytes + 1) << bytes << " bytes";
}

// Expected bytes follow the encoded_value format: (value_arg << 5) | value_type, then the value.
TEST(ValueEncoder, value_whenValueIsNull_writesOnlyTheHeader)
{
    EXPECT_EQ(encoded(Value{Value::Null{}}), (Bytes{0x1e}));
}

TEST(ValueEncoder, value_whenValueIsFalse_writesZeroInTheHeader)
{
    EXPECT_EQ(encoded(Value{Value::Boolean{false}}), (Bytes{0x1f}));
}

TEST(ValueEncoder, value_whenValueIsTrue_writesOneInTheHeader)
{
    EXPECT_EQ(encoded(Value{Value::Boolean{true}}), (Bytes{0x3f}));
}

TEST(ValueEncoder, value_whenValueIsAByte_writesOneByte)
{
    EXPECT_EQ(encoded(Value{Value::Byte{0}}), (Bytes{0x00, 0x00}));
    EXPECT_EQ(encoded(Value{Value::Byte{127}}), (Bytes{0x00, 0x7F}));
    EXPECT_EQ(encoded(Value{Value::Byte{-1}}), (Bytes{0x00, 0xFF}));
    EXPECT_EQ(encoded(Value{Value::Byte{-128}}), (Bytes{0x00, 0x80}));
}

TEST(ValueEncoder, value_whenShortFitsOneByte_writesOneByte)
{
    EXPECT_EQ(encoded(Value{Value::Short{0}}), (Bytes{0x02, 0x00}));
    EXPECT_EQ(encoded(Value{Value::Short{127}}), (Bytes{0x02, 0x7F}));
    EXPECT_EQ(encoded(Value{Value::Short{-1}}), (Bytes{0x02, 0xFF}));
    EXPECT_EQ(encoded(Value{Value::Short{-128}}), (Bytes{0x02, 0x80}));
}

TEST(ValueEncoder, value_whenShortNeedsTwoBytes_writesTwoBytes)
{
    EXPECT_EQ(encoded(Value{Value::Short{128}}), (Bytes{0x22, 0x80, 0x00}));
    EXPECT_EQ(encoded(Value{Value::Short{-129}}), (Bytes{0x22, 0x7F, 0xFF}));
    EXPECT_EQ(encoded(Value{Value::Short{32767}}), (Bytes{0x22, 0xFF, 0x7F}));
    EXPECT_EQ(encoded(Value{Value::Short{-32768}}), (Bytes{0x22, 0x00, 0x80}));
}

TEST(ValueEncoder, value_whenCharFitsOneByte_writesOneByteWithoutSignExtension)
{
    EXPECT_EQ(encoded(Value{Value::Char{u'\0'}}), (Bytes{0x03, 0x00}));
    EXPECT_EQ(encoded(Value{Value::Char{u'a'}}), (Bytes{0x03, 0x61}));
    EXPECT_EQ(encoded(Value{Value::Char{u'\x80'}}), (Bytes{0x03, 0x80}));
    EXPECT_EQ(encoded(Value{Value::Char{u'\xFF'}}), (Bytes{0x03, 0xFF}));
}

TEST(ValueEncoder, value_whenCharNeedsTwoBytes_writesTwoBytes)
{
    EXPECT_EQ(encoded(Value{Value::Char{u'\x100'}}), (Bytes{0x23, 0x00, 0x01}));
    EXPECT_EQ(encoded(Value{Value::Char{u'\xFFFF'}}), (Bytes{0x23, 0xFF, 0xFF}));
}

TEST(ValueEncoder, value_whenIntFitsOneByte_writesOneByte)
{
    EXPECT_EQ(encoded(Value{Value::Int{0}}), (Bytes{0x04, 0x00}));
    EXPECT_EQ(encoded(Value{Value::Int{127}}), (Bytes{0x04, 0x7F}));
    EXPECT_EQ(encoded(Value{Value::Int{-1}}), (Bytes{0x04, 0xFF}));
    EXPECT_EQ(encoded(Value{Value::Int{-128}}), (Bytes{0x04, 0x80}));
}

TEST(ValueEncoder, value_whenIntNeedsTwoBytes_writesTwoBytes)
{
    EXPECT_EQ(encoded(Value{Value::Int{128}}), (Bytes{0x24, 0x80, 0x00}));
    EXPECT_EQ(encoded(Value{Value::Int{-129}}), (Bytes{0x24, 0x7F, 0xFF}));
    EXPECT_EQ(encoded(Value{Value::Int{32767}}), (Bytes{0x24, 0xFF, 0x7F}));
    EXPECT_EQ(encoded(Value{Value::Int{-32768}}), (Bytes{0x24, 0x00, 0x80}));
}

TEST(ValueEncoder, value_whenIntNeedsThreeBytes_writesThreeBytes)
{
    EXPECT_EQ(encoded(Value{Value::Int{32768}}), (Bytes{0x44, 0x00, 0x80, 0x00}));
    EXPECT_EQ(encoded(Value{Value::Int{-32769}}), (Bytes{0x44, 0xFF, 0x7F, 0xFF}));
    EXPECT_EQ(encoded(Value{Value::Int{8388607}}), (Bytes{0x44, 0xFF, 0xFF, 0x7F}));
    EXPECT_EQ(encoded(Value{Value::Int{-8388608}}), (Bytes{0x44, 0x00, 0x00, 0x80}));
}

TEST(ValueEncoder, value_whenIntNeedsFourBytes_writesFourBytes)
{
    EXPECT_EQ(encoded(Value{Value::Int{8388608}}), (Bytes{0x64, 0x00, 0x00, 0x80, 0x00}));
    EXPECT_EQ(encoded(Value{Value::Int{-8388609}}), (Bytes{0x64, 0xFF, 0xFF, 0x7F, 0xFF}));
    EXPECT_EQ(encoded(Value{Value::Int{kInt32Max}}), (Bytes{0x64, 0xFF, 0xFF, 0xFF, 0x7F}));
    EXPECT_EQ(encoded(Value{Value::Int{kInt32Min}}), (Bytes{0x64, 0x00, 0x00, 0x00, 0x80}));
}

TEST(ValueEncoder, value_whenLongFitsOneByte_writesOneByte)
{
    EXPECT_EQ(encoded(Value{Value::Long{0}}), (Bytes{0x06, 0x00}));
    EXPECT_EQ(encoded(Value{Value::Long{-1}}), (Bytes{0x06, 0xFF}));
}

TEST(ValueEncoder, value_whenLongIsJustOutsideTheIntRange_writesFiveBytes)
{
    EXPECT_EQ(encoded(Value{Value::Long{int64_t{kInt32Max} + 1}}),
              (Bytes{0x86, 0x00, 0x00, 0x00, 0x80, 0x00}));
    EXPECT_EQ(encoded(Value{Value::Long{int64_t{kInt32Min} - 1}}),
              (Bytes{0x86, 0xFF, 0xFF, 0xFF, 0x7F, 0xFF}));
}

TEST(ValueEncoder, value_whenLongNeedsEightBytes_writesThemLowByteFirst)
{
    EXPECT_EQ(encoded(Value{Value::Long{0x123456789ABCDEF0}}),
              (Bytes{0xE6, 0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12}));
    EXPECT_EQ(encoded(Value{Value::Long{kInt64Max}}),
              (Bytes{0xE6, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F}));
    EXPECT_EQ(encoded(Value{Value::Long{kInt64Min}}),
              (Bytes{0xE6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80}));
}

TEST(ValueEncoder, value_whenLongIsAtAByteBoundary_writesTheSmallestSizeThatReadsBack)
{
    for (uint32_t bytes = 1; bytes <= 8; ++bytes)
        for (int64_t value : {largest_signed(bytes), smallest_signed(bytes)}) {
            Bytes out = encoded(Value{Value::Long{value}});

            EXPECT_EQ(out.size(), 1u + bytes) << value;
            EXPECT_EQ(out[0], ((bytes - 1) << 5) | 0x06) << value;
            EXPECT_EQ(std::get<int64_t>(parsed(out).value), value);
        }
}

TEST(ValueEncoder, value_whenIntIsAtAByteBoundary_readsBackWithItsSign)
{
    for (uint32_t bytes = 1; bytes <= 4; ++bytes)
        for (int64_t value : {largest_signed(bytes), smallest_signed(bytes)}) {
            raw::EncodedValue back =
                parsed(encoded(Value{Value::Int{static_cast<int32_t>(value)}}));

            EXPECT_EQ(back.type, raw::EncodedValue::Type::Int);
            EXPECT_EQ(std::get<int64_t>(back.value), value);
        }
}

TEST(ValueEncoder, value_whenShortIsNegative_readsBackNegative)
{
    raw::EncodedValue back = parsed(encoded(Value{Value::Short{-300}}));

    EXPECT_EQ(back.type, raw::EncodedValue::Type::Short);
    EXPECT_EQ(std::get<int64_t>(back.value), -300);
}

TEST(ValueEncoder, value_whenCharHasItsHighBitSet_readsBackPositive)
{
    raw::EncodedValue back = parsed(encoded(Value{Value::Char{u'\xFFFF'}}));

    EXPECT_EQ(back.type, raw::EncodedValue::Type::Char);
    EXPECT_EQ(std::get<int64_t>(back.value), 0xFFFF);
}

TEST(ValueEncoder, value_whenFloatIsZero_writesOneZeroByte)
{
    EXPECT_EQ(encoded(Value{Value::Float{0.0f}}), (Bytes{0x10, 0x00}));
}

TEST(ValueEncoder, value_whenFloatIsMinusZero_writesTheSignByte)
{
    EXPECT_EQ(encoded(Value{Value::Float{-0.0f}}), (Bytes{0x10, 0x80}));
}

TEST(ValueEncoder, value_whenFloatHasZeroLowBytes_dropsThem)
{
    // 1.0f is 0x3F800000.
    EXPECT_EQ(encoded(Value{Value::Float{1.0f}}), (Bytes{0x30, 0x80, 0x3F}));
}

TEST(ValueEncoder, value_whenFloatHasAZeroByteAboveANonZeroOne_keepsIt)
{
    const float value = std::bit_cast<float>(uint32_t{0x3F000100});

    EXPECT_EQ(encoded(Value{Value::Float{value}}), (Bytes{0x50, 0x01, 0x00, 0x3F}));
}

TEST(ValueEncoder, value_whenFloatUsesEveryByte_writesFourBytes)
{
    const float value = std::bit_cast<float>(uint32_t{0x7F800001});

    EXPECT_EQ(encoded(Value{Value::Float{value}}), (Bytes{0x70, 0x01, 0x00, 0x80, 0x7F}));
}

TEST(ValueEncoder, value_whenFloatIsReadBack_keepsItsBits)
{
    for (uint32_t bits : {0x00000000u, 0x80000000u, 0x3F800000u, 0x3F8CCCCDu, 0x7F7FFFFFu,
                          0x00800000u, 0x7F800000u, 0xFF800000u, 0x00000001u}) {
        raw::EncodedValue back = parsed(encoded(Value{Value::Float{std::bit_cast<float>(bits)}}));

        EXPECT_EQ(back.type, raw::EncodedValue::Type::Float);
        EXPECT_EQ(std::bit_cast<uint32_t>(static_cast<float>(std::get<double>(back.value))), bits);
    }
}

TEST(ValueEncoder, value_whenDoubleIsZero_writesOneZeroByte)
{
    EXPECT_EQ(encoded(Value{Value::Double{0.0}}), (Bytes{0x11, 0x00}));
}

TEST(ValueEncoder, value_whenDoubleIsMinusZero_writesTheSignByte)
{
    EXPECT_EQ(encoded(Value{Value::Double{-0.0}}), (Bytes{0x11, 0x80}));
}

TEST(ValueEncoder, value_whenDoubleHasZeroLowBytes_dropsThem)
{
    // 1.5 is 0x3FF8000000000000; 1.1f widened is 0x3FF19999A0000000.
    EXPECT_EQ(encoded(Value{Value::Double{1.5}}), (Bytes{0x31, 0xF8, 0x3F}));
    EXPECT_EQ(encoded(Value{Value::Double{static_cast<double>(1.1f)}}),
              (Bytes{0x91, 0xA0, 0x99, 0x99, 0xF1, 0x3F}));
}

TEST(ValueEncoder, value_whenDoubleUsesEveryByte_writesEightBytes)
{
    // 0.1 is 0x3FB999999999999A.
    EXPECT_EQ(encoded(Value{Value::Double{0.1}}),
              (Bytes{0xF1, 0x9A, 0x99, 0x99, 0x99, 0x99, 0x99, 0xB9, 0x3F}));
}

TEST(ValueEncoder, value_whenDoubleHasOnlyItsLowestBitSet_writesEightBytes)
{
    const double value = std::bit_cast<double>(uint64_t{1});

    EXPECT_EQ(encoded(Value{Value::Double{value}}),
              (Bytes{0xF1, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}));
}

TEST(ValueEncoder, value_whenDoubleIsReadBack_keepsItsBits)
{
    for (uint64_t bits :
         {uint64_t{0}, uint64_t{0x8000000000000000}, uint64_t{0x3FF0000000000000},
          uint64_t{0x3FB999999999999A}, uint64_t{0x7FF0000000000001}, uint64_t{0x7FEFFFFFFFFFFFFF},
          uint64_t{0x0000000000000100}, uint64_t{0x3FF19999A0000000}}) {
        raw::EncodedValue back = parsed(encoded(Value{Value::Double{std::bit_cast<double>(bits)}}));

        EXPECT_EQ(back.type, raw::EncodedValue::Type::Double);
        EXPECT_EQ(std::bit_cast<uint64_t>(std::get<double>(back.value)), bits);
    }
}

TEST(ValueEncoder, value_whenValueIsAString_writesItsStringIndex)
{
    Pools pools = pools_with_strings(3);

    EXPECT_EQ(encoded(Value{Value::String{"s00002"}}, pools), (Bytes{0x17, 0x02}));
}

TEST(ValueEncoder, value_whenAnIndexFitsOneByte_writesOneByte)
{
    Pools pools = pools_with_strings(256);

    EXPECT_EQ(encoded(Value{Value::String{"s00255"}}, pools), (Bytes{0x17, 0xFF}));
}

TEST(ValueEncoder, value_whenAnIndexNeedsTwoBytes_writesTwoBytes)
{
    Pools pools = pools_with_strings(65536);

    EXPECT_EQ(encoded(Value{Value::String{"s00256"}}, pools), (Bytes{0x37, 0x00, 0x01}));
    EXPECT_EQ(encoded(Value{Value::String{"s65535"}}, pools), (Bytes{0x37, 0xFF, 0xFF}));
}

TEST(ValueEncoder, value_whenAnIndexNeedsThreeBytes_writesThreeBytes)
{
    Pools pools = pools_with_strings(65537);

    EXPECT_EQ(encoded(Value{Value::String{"s65536"}}, pools), (Bytes{0x57, 0x00, 0x00, 0x01}));
}

TEST(ValueEncoder, value_whenStringIsNotInThePools_fails)
{
    Pools pools = pools_with_strings(1);

    Error error = write_failure([&] { encoded(Value{Value::String{"missing"}}, pools); });

    EXPECT_EQ(error.kind, Error::Kind::Invalid);
}

TEST(ValueEncoder, value_whenValueIsAType_writesItsTypeIndex)
{
    Pools pools;
    for (const char *type : {"LB;", "I", "LA;"})
        pools.add_type(type);
    pools.finish();

    EXPECT_EQ(encoded(Value{Value::Type{"LB;"}}, pools), (Bytes{0x18, 0x02}));
}

TEST(ValueEncoder, value_whenValueIsAField_writesItsFieldIndex)
{
    Pools pools = pools_with_fields();

    EXPECT_EQ(encoded(Value{Value::Field{FieldId{"LA;", "c", "I"}}}, pools), (Bytes{0x19, 0x02}));
}

TEST(ValueEncoder, value_whenValueIsAnEnum_writesItsFieldIndexWithTheEnumType)
{
    Pools pools = pools_with_fields();

    EXPECT_EQ(encoded(Value{Value::Enum{FieldId{"LA;", "b", "I"}}}, pools), (Bytes{0x1b, 0x01}));
}

TEST(ValueEncoder, value_whenValueIsAMethod_writesItsMethodIndex)
{
    Pools pools;
    for (const char *name : {"a", "b", "c"})
        pools.add_method(MethodId{"LA;", name, "()V"});
    pools.finish();

    EXPECT_EQ(encoded(Value{Value::Method{MethodId{"LA;", "c", "()V"}}}, pools),
              (Bytes{0x1a, 0x02}));
}

TEST(ValueEncoder, value_whenValueIsAMethodType_writesItsPrototypeIndex)
{
    Pools pools;
    for (const char *proto : {"()I", "()V", "(I)V"})
        pools.add_proto(proto);
    pools.finish();

    EXPECT_EQ(encoded(Value{Value::MethodType{"(I)V"}}, pools), (Bytes{0x15, 0x02}));
}

TEST(ValueEncoder, value_whenValueIsAMethodHandle_writesItsHandleIndex)
{
    const MethodHandle put{MethodHandleKind::StaticPut, FieldId{"LA;", "f", "I"}};
    const MethodHandle get{MethodHandleKind::StaticGet, FieldId{"LA;", "f", "I"}};
    Pools pools;
    pools.add_method_handle(get);
    pools.add_method_handle(put);
    pools.finish();

    EXPECT_EQ(encoded(Value{get}, pools), (Bytes{0x16, 0x01}));
}

TEST(ValueEncoder, value_whenReferencesAreReadBack_returnsEachTypeAndIndex)
{
    const MethodHandle handle{MethodHandleKind::InvokeStatic, MethodId{"LA;", "b", "()V"}};
    Pools pools;
    pools.add_field(FieldId{"LA;", "a", "I"});
    pools.add_field(FieldId{"LA;", "b", "I"});
    pools.add_method(MethodId{"LA;", "a", "()V"});
    pools.add_method_handle(handle);
    pools.finish();
    // Strings: "I", "LA;", "V", "a", "b".  Types: "I", "LA;", "V".
    const std::vector<std::tuple<Value, raw::EncodedValue::Type, uint32_t>> values{
        {Value{Value::String{"b"}}, raw::EncodedValue::Type::String, 4},
        {Value{Value::Type{"LA;"}}, raw::EncodedValue::Type::Type, 1},
        {Value{Value::Field{FieldId{"LA;", "b", "I"}}}, raw::EncodedValue::Type::Field, 1},
        {Value{Value::Enum{FieldId{"LA;", "b", "I"}}}, raw::EncodedValue::Type::Enum, 1},
        {Value{Value::Method{MethodId{"LA;", "b", "()V"}}}, raw::EncodedValue::Type::Method, 1},
        {Value{Value::MethodType{"()V"}}, raw::EncodedValue::Type::MethodType, 0},
        {Value{handle}, raw::EncodedValue::Type::MethodHandle, 0},
    };

    for (const auto &[value, type, index] : values) {
        raw::EncodedValue back = parsed(encoded(value, pools));

        EXPECT_EQ(back.type, type);
        EXPECT_EQ(std::get<uint32_t>(back.value), index);
    }
}

TEST(ValueEncoder, value_whenValueIsAnEmptyArray_writesAZeroCount)
{
    EXPECT_EQ(encoded(Value{Value::Array{{}}}), (Bytes{0x1c, 0x00}));
}

TEST(ValueEncoder, value_whenValueIsAnArray_writesTheCountThenEachElement)
{
    const Value array{
        Value::Array{{Value{Value::Int{1}}, Value{Value::Boolean{true}}, Value{Value::Null{}}}}};

    EXPECT_EQ(encoded(array), (Bytes{0x1c, 0x03, 0x04, 0x01, 0x3f, 0x1e}));
}

TEST(ValueEncoder, value_whenArraysAreNested_writesTheInnerArrayAsAnElement)
{
    const Value array{Value::Array{{Value{Value::Array{{Value{Value::Byte{7}}}}}}}};

    EXPECT_EQ(encoded(array), (Bytes{0x1c, 0x01, 0x1c, 0x01, 0x00, 0x07}));
}

TEST(ValueEncoder, value_whenValueIsAnAnnotation_writesTheHeaderThenTheAnnotation)
{
    const EncodedAnnotation inner{"LInner;", {NamedValue{"value", Value{Value::Int{1}}}}};
    Pools pools;
    pools.add_annotation(inner);
    pools.finish();

    Bytes out = encoded(Value{Shared<EncodedAnnotation>(inner)}, pools);

    // Strings and types: "LInner;" is 0, "value" is 1.
    EXPECT_EQ(out, (Bytes{0x1d, 0x00, 0x01, 0x01, 0x04, 0x01}));
}

TEST(ValueEncoder, value_whenAnAnnotationIsReadBack_returnsItsTypeAndElements)
{
    const EncodedAnnotation inner{"LInner;", {NamedValue{"value", Value{Value::Int{-5}}}}};
    Pools pools;
    pools.add_annotation(inner);
    pools.finish();

    raw::EncodedValue back = parsed(encoded(Value{Shared<EncodedAnnotation>(inner)}, pools));

    ASSERT_EQ(back.type, raw::EncodedValue::Type::Annotation);
    const auto &annotation = *std::get<std::unique_ptr<raw::EncodedAnnotation>>(back.value);
    EXPECT_EQ(annotation.type_idx, pools.type("LInner;"));
    ASSERT_EQ(annotation.elements.size(), 1u);
    EXPECT_EQ(annotation.elements[0].name_idx, pools.string("value"));
    EXPECT_EQ(std::get<int64_t>(annotation.elements[0].value.value), -5);
}

TEST(ValueEncoder, array_whenThereAreNoValues_writesAZeroCount)
{
    Pools pools = empty_pools();
    raw::ByteWriter out;

    ValueEncoder(pools).array(out, {});

    EXPECT_EQ(out.bytes(), (Bytes{0x00}));
}

TEST(ValueEncoder, array_whenThereAreValues_writesTheCountThenEachValueWithoutAHeader)
{
    Pools pools = empty_pools();
    const std::vector<Value> values{Value{Value::Int{5}}, Value{Value::Boolean{false}}};
    raw::ByteWriter out;

    ValueEncoder(pools).array(out, values);

    EXPECT_EQ(out.bytes(), (Bytes{0x02, 0x04, 0x05, 0x1f}));
}

TEST(ValueEncoder, array_whenThereAreMoreThan127Values_writesTheCountAsUleb128)
{
    Pools pools = empty_pools();
    const std::vector<Value> values(128, Value{Value::Null{}});
    raw::ByteWriter out;

    ValueEncoder(pools).array(out, values);

    ASSERT_EQ(out.size(), 130u);
    EXPECT_EQ(out.bytes()[0], 0x80);
    EXPECT_EQ(out.bytes()[1], 0x01);
}

TEST(ValueEncoder, array_whenReadBack_returnsEveryValue)
{
    Pools pools = empty_pools();
    const std::vector<Value> values{Value{Value::Int{-70000}}, Value{Value::Long{1}},
                                    Value{Value::Boolean{true}}};
    raw::ByteWriter out;
    ValueEncoder(pools).array(out, values);
    uint32_t offset = 0;

    auto back = raw::parser::parse_encoded_array(out.bytes(), offset);

    ASSERT_TRUE(back.has_value());
    ASSERT_EQ(back->size(), 3u);
    EXPECT_EQ(offset, out.size());
    EXPECT_EQ(std::get<int64_t>((*back)[0].value), -70000);
    EXPECT_EQ(std::get<int64_t>((*back)[1].value), 1);
    EXPECT_EQ(std::get<bool>((*back)[2].value), true);
}

TEST(ValueEncoder, annotation_whenAnnotationHasNoElements_writesItsTypeAndAZeroCount)
{
    Pools pools;
    pools.add_type("LA;");
    pools.add_type("LAnno;");
    pools.finish();
    raw::ByteWriter out;

    ValueEncoder(pools).annotation(out, EncodedAnnotation{"LAnno;", {}});

    EXPECT_EQ(out.bytes(), (Bytes{0x01, 0x00}));
}

TEST(ValueEncoder, annotation_whenElementsAreOutOfOrder_writesThemByNameIndex)
{
    const EncodedAnnotation annotation{"LAnno;",
                                       {NamedValue{"c", Value{Value::Int{3}}},
                                        NamedValue{"a", Value{Value::Int{1}}},
                                        NamedValue{"b", Value{Value::Int{2}}}}};
    Pools pools;
    pools.add_annotation(annotation);
    pools.finish();
    raw::ByteWriter out;

    ValueEncoder(pools).annotation(out, annotation);

    // Strings: "LAnno;" is 0, "a" 1, "b" 2, "c" 3.
    EXPECT_EQ(out.bytes(),
              (Bytes{0x00, 0x03, 0x01, 0x04, 0x01, 0x02, 0x04, 0x02, 0x03, 0x04, 0x03}));
}

TEST(ValueEncoder, annotation_whenAnElementIsAString_writesItsIndex)
{
    const EncodedAnnotation annotation{"LAnno;",
                                       {NamedValue{"name", Value{Value::String{"text"}}}}};
    Pools pools;
    pools.add_annotation(annotation);
    pools.finish();
    raw::ByteWriter out;

    ValueEncoder(pools).annotation(out, annotation);

    // Strings: "LAnno;" is 0, "name" 1, "text" 2.
    EXPECT_EQ(out.bytes(), (Bytes{0x00, 0x01, 0x01, 0x17, 0x02}));
}

TEST(ValueEncoder, annotation_whenAnElementIsAnAnnotation_writesItAsAValueInsideTheElement)
{
    const EncodedAnnotation inner{"LInner;", {NamedValue{"value", Value{Value::Boolean{true}}}}};
    const EncodedAnnotation outer{"LOuter;",
                                  {NamedValue{"nested", Value{Shared<EncodedAnnotation>(inner)}}}};
    Pools pools;
    pools.add_annotation(outer);
    pools.finish();
    raw::ByteWriter out;

    ValueEncoder(pools).annotation(out, outer);

    // Strings and types: "LInner;" is 0, "LOuter;" 1; strings: "nested" 2, "value" 3.
    EXPECT_EQ(out.bytes(), (Bytes{0x01, 0x01, 0x02, 0x1d, 0x00, 0x01, 0x03, 0x3f}));
}

TEST(ValueEncoder, annotation_whenReadBack_returnsTheElementsInNameOrder)
{
    const EncodedAnnotation annotation{
        "LAnno;",
        {NamedValue{"second", Value{Value::Int{2}}}, NamedValue{"first", Value{Value::Int{1}}}}};
    Pools pools;
    pools.add_annotation(annotation);
    pools.finish();
    raw::ByteWriter out;
    ValueEncoder(pools).annotation(out, annotation);
    uint32_t offset = 0;

    auto back = raw::parser::parse_encoded_annotation(out.bytes(), offset);

    ASSERT_TRUE(back.has_value());
    EXPECT_EQ(offset, out.size());
    EXPECT_EQ(back->type_idx, pools.type("LAnno;"));
    ASSERT_EQ(back->elements.size(), 2u);
    EXPECT_EQ(back->elements[0].name_idx, pools.string("first"));
    EXPECT_EQ(back->elements[1].name_idx, pools.string("second"));
}

TEST(ValueEncoder, defaultValue_whenTypeIsBoolean_returnsFalse)
{
    EXPECT_EQ(default_value("Z"), Value{Value::Boolean{false}});
}

TEST(ValueEncoder, defaultValue_whenTypeIsByte_returnsAZeroByte)
{
    EXPECT_EQ(default_value("B"), Value{Value::Byte{0}});
}

TEST(ValueEncoder, defaultValue_whenTypeIsShort_returnsAZeroShort)
{
    EXPECT_EQ(default_value("S"), Value{Value::Short{0}});
}

TEST(ValueEncoder, defaultValue_whenTypeIsChar_returnsAZeroChar)
{
    EXPECT_EQ(default_value("C"), Value{Value::Char{0}});
}

TEST(ValueEncoder, defaultValue_whenTypeIsInt_returnsAZeroInt)
{
    EXPECT_EQ(default_value("I"), Value{Value::Int{0}});
}

TEST(ValueEncoder, defaultValue_whenTypeIsLong_returnsAZeroLong)
{
    EXPECT_EQ(default_value("J"), Value{Value::Long{0}});
}

TEST(ValueEncoder, defaultValue_whenTypeIsFloat_returnsPositiveZero)
{
    EXPECT_EQ(default_value("F"), Value{Value::Float{0.0f}});
}

TEST(ValueEncoder, defaultValue_whenTypeIsDouble_returnsPositiveZero)
{
    EXPECT_EQ(default_value("D"), Value{Value::Double{0.0}});
}

TEST(ValueEncoder, defaultValue_whenTypeIsAClass_returnsNull)
{
    EXPECT_EQ(default_value("Ljava/lang/String;"), Value{Value::Null{}});
}

TEST(ValueEncoder, defaultValue_whenTypeIsAnArray_returnsNull)
{
    EXPECT_EQ(default_value("[I"), Value{Value::Null{}});
}

TEST(ValueEncoder, defaultValue_whenTypeIsEmpty_returnsNull)
{
    EXPECT_EQ(default_value(""), Value{Value::Null{}});
}

} // namespace
} // namespace dexsplit::model::detail
