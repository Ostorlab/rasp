// Tests for read() and read_file(), run on the files under fixtures/ and on patched copies.

#include "model/io.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "common/access_flags.hpp"
#include "common/annotation_visibility.hpp"
#include "common/ids.hpp"
#include "model/types.hpp"
#include "raw/types.hpp"
#include "support/fixtures.hpp"

namespace dexsplit::model {
namespace {

using support::fixture_path;
using support::load_fixture;

const ReadOptions kNoDebugInfo{.debug_info = false, .keep_class = {}};

// Offsets of code items, from dexdump -d.
constexpr std::size_t kCastsMakeArrayCode = 0x140;
constexpr std::size_t kClassesInitCode = 0x168;
constexpr std::size_t kFibonacciClassifyCode = 0x140;
constexpr std::size_t kTrycatchDivideCode = 0x1a8;
constexpr std::size_t kTrycatchSafeParseCode = 0x1d0;

// Pool indices of fibonacci.dex; the P1 forms are index plus one, as debug info stores them.
constexpr uint16_t kStringNegative = 0x0E;
constexpr uint16_t kStringZero = 0x11;
constexpr uint8_t kStringFileNameP1 = 0x02;
constexpr uint8_t kStringLjP1 = 0x07;
constexpr uint8_t kStringNegativeP1 = 0x0F;
constexpr uint8_t kStringSmallP1 = 0x10;
constexpr uint8_t kTypeLongP1 = 0x02;

constexpr std::size_t kEndianTagOff = 0x28;
constexpr std::size_t kFieldIdsOff = 0x54;
constexpr std::size_t kMethodIdsOff = 0x5C;
constexpr std::size_t kClassDefsOff = 0x64;
constexpr std::size_t kClassDefSize = 32;
constexpr std::size_t kSuperclassIdx = 8;
constexpr std::size_t kSourceFileIdx = 16;
constexpr std::size_t kAnnotationsOff = 20;
constexpr std::size_t kClassDataOff = 24;
constexpr std::size_t kStaticValuesOff = 28;
constexpr std::size_t kCodeDebugInfoOff = 8;
constexpr std::size_t kCodeInsnsSize = 12;
constexpr std::size_t kCodeInsns = 16;

uint32_t get_u32(const std::vector<uint8_t> &b, std::size_t off)
{
    return b[off] | (uint32_t{b[off + 1]} << 8) | (uint32_t{b[off + 2]} << 16) |
           (uint32_t{b[off + 3]} << 24);
}

void put_u16(std::vector<uint8_t> &b, std::size_t off, uint16_t v)
{
    b[off] = v & 0xFF;
    b[off + 1] = v >> 8;
}

void put_u32(std::vector<uint8_t> &b, std::size_t off, uint32_t v)
{
    put_u16(b, off, v & 0xFFFF);
    put_u16(b, off + 2, v >> 16);
}

std::size_t class_def_off(const std::vector<uint8_t> &b, std::size_t index)
{
    return get_u32(b, kClassDefsOff) + index * kClassDefSize;
}

void set_insns(std::vector<uint8_t> &b, std::size_t code_off, const std::vector<uint16_t> &units)
{
    put_u32(b, code_off + kCodeDebugInfoOff, 0);
    put_u32(b, code_off + kCodeInsnsSize, static_cast<uint32_t>(units.size()));
    std::size_t at = code_off + kCodeInsns;
    for (uint16_t unit : units) {
        put_u16(b, at, unit);
        at += 2;
    }
}

void set_debug_info(std::vector<uint8_t> &b, std::size_t code_off, const std::vector<uint8_t> &item)
{
    put_u32(b, code_off + kCodeDebugInfoOff, static_cast<uint32_t>(b.size()));
    b.insert(b.end(), item.begin(), item.end());
}

void set_static_values(std::vector<uint8_t> &b, std::span<const uint8_t> encoded_array)
{
    put_u32(b, class_def_off(b, 0) + kStaticValuesOff, static_cast<uint32_t>(b.size()));
    b.insert(b.end(), encoded_array.begin(), encoded_array.end());
}

Dex read_or_throw(std::span<const uint8_t> bytes, const ReadOptions &options = {})
{
    auto dex = read(bytes, options);
    if (!dex.has_value())
        throw std::runtime_error("read() failed: " + dex.error().message);
    return std::move(*dex);
}

Dex read_fixture(std::string_view name, const ReadOptions &options = {})
{
    return read_or_throw(load_fixture(name), options);
}

Error read_error(std::span<const uint8_t> bytes)
{
    auto dex = read(bytes);
    if (dex.has_value())
        throw std::runtime_error("read() accepted the input");
    return dex.error();
}

const ClassDef &class_of(const Dex &dex, std::string_view type)
{
    const ClassDef *c = dex.find_class(type);
    if (c == nullptr)
        throw std::runtime_error("no class " + std::string(type));
    return *c;
}

const FieldDef &field_of(const Dex &dex, std::string_view type, std::string_view name,
                         std::string_view field_type)
{
    const FieldDef *f = class_of(dex, type).find_field(name, field_type);
    if (f == nullptr)
        throw std::runtime_error("no field " + std::string(name));
    return *f;
}

const MethodDef &method_of(const Dex &dex, std::string_view type, std::string_view name,
                           std::string_view proto)
{
    const MethodDef *m = class_of(dex, type).find_method(name, proto);
    if (m == nullptr)
        throw std::runtime_error("no method " + std::string(name));
    return *m;
}

const Code &code_of(const Dex &dex, std::string_view type, std::string_view name,
                    std::string_view proto)
{
    const MethodDef &m = method_of(dex, type, name, proto);
    if (!m.code.has_value())
        throw std::runtime_error("no code in " + std::string(name));
    return *m.code;
}

std::vector<Insn> insns_of(const Code &code)
{
    std::vector<Insn> out;
    for (const Item &item : code.items)
        if (const Insn *insn = std::get_if<Insn>(&item))
            out.push_back(*insn);
    return out;
}

template <class T> std::size_t count_of(const Code &code)
{
    std::size_t count = 0;
    for (const Item &item : code.items)
        count += std::holds_alternative<T>(item) ? 1 : 0;
    return count;
}

std::vector<std::pair<uint32_t, std::size_t>> lines_with_insns_before(const Code &code)
{
    std::vector<std::pair<uint32_t, std::size_t>> out;
    std::size_t insns = 0;
    for (const Item &item : code.items) {
        if (std::holds_alternative<Insn>(item))
            ++insns;
        else if (const LineNumber *line = std::get_if<LineNumber>(&item))
            out.emplace_back(line->line, insns);
    }
    return out;
}

Code fibonacci_classify_with_insns(const std::vector<uint16_t> &units)
{
    auto bytes = load_fixture("fibonacci.dex");
    set_insns(bytes, kFibonacciClassifyCode, units);
    Dex dex = read_or_throw(bytes);
    return code_of(dex, "LFibonacci;", "classify", "(J)Ljava/lang/String;");
}

Error fibonacci_classify_insns_error(const std::vector<uint16_t> &units)
{
    auto bytes = load_fixture("fibonacci.dex");
    set_insns(bytes, kFibonacciClassifyCode, units);
    return read_error(bytes);
}

Code fibonacci_classify_with_debug_info(const std::vector<uint8_t> &item)
{
    auto bytes = load_fixture("fibonacci.dex");
    set_debug_info(bytes, kFibonacciClassifyCode, item);
    Dex dex = read_or_throw(bytes);
    return code_of(dex, "LFibonacci;", "classify", "(J)Ljava/lang/String;");
}

// A switch on v3 at 0, const-string at 3 and 6, return-object at 5 and 8, the payload at 10.
std::vector<uint16_t> switch_code(uint16_t switch_unit, const std::vector<uint16_t> &payload)
{
    std::vector<uint16_t> units{switch_unit, 0x000A, 0x0000,      0x031A, kStringNegative,
                                0x0311,      0x031A, kStringZero, 0x0311, 0x0000};
    units.insert(units.end(), payload.begin(), payload.end());
    return units;
}

std::vector<std::optional<Value>> multistring_static_values(std::span<const uint8_t> encoded_array)
{
    auto bytes = load_fixture("multistring.dex");
    set_static_values(bytes, encoded_array);
    Dex dex = read_or_throw(bytes);
    std::vector<std::optional<Value>> out;
    for (const FieldDef &f : dex.classes[0].fields)
        out.push_back(f.initial_value);
    return out;
}

Error multistring_static_values_error(std::span<const uint8_t> encoded_array)
{
    auto bytes = load_fixture("multistring.dex");
    set_static_values(bytes, encoded_array);
    return read_error(bytes);
}

bool contains(std::string_view text, std::string_view part)
{
    return text.find(part) != std::string_view::npos;
}

// Expected values for the fixtures are ground truth from dexdump -d and the Java sources.
TEST(Read, read_whenMagicSaysVersion39_returnsVersion39)
{
    Dex dex = read_fixture("classes.dex");

    EXPECT_EQ(dex.version, 39u);
}

TEST(Read, read_whenMagicSaysVersion35_returnsVersion35)
{
    Dex dex = read_fixture("fibonacci.dex");

    EXPECT_EQ(dex.version, 35u);
}

TEST(Read, read_whenMagicSaysVersion37_returnsVersion37)
{
    Dex dex = read_fixture("inherit.dex");

    EXPECT_EQ(dex.version, 37u);
}

TEST(Read, read_whenFileHasFourClasses_returnsThemInFileOrder)
{
    Dex dex = read_fixture("shapes.dex");

    std::vector<std::string> types;
    for (const ClassDef &c : dex.classes)
        types.push_back(c.type);
    EXPECT_EQ(types,
              (std::vector<std::string>{"LShape;", "LAbstractShape;", "LCircle;", "LRectangle;"}));
}

TEST(Read, read_whenClassExtendsAnotherClass_returnsTheSuperclass)
{
    Dex dex = read_fixture("shapes.dex");

    EXPECT_EQ(class_of(dex, "LCircle;").superclass, "LAbstractShape;");
}

TEST(Read, read_whenClassHasNoSuperclass_returnsNoSuperclass)
{
    auto bytes = load_fixture("fibonacci.dex");
    put_u32(bytes, class_def_off(bytes, 0) + kSuperclassIdx, raw::NO_INDEX);

    Dex dex = read_or_throw(bytes);

    EXPECT_EQ(dex.classes[0].superclass, std::nullopt);
}

TEST(Read, read_whenClassImplementsAnInterface_returnsTheInterface)
{
    Dex dex = read_fixture("shapes.dex");

    EXPECT_EQ(class_of(dex, "LAbstractShape;").interfaces, (std::vector<std::string>{"LShape;"}));
}

TEST(Read, read_whenClassImplementsNothing_returnsNoInterfaces)
{
    Dex dex = read_fixture("shapes.dex");

    EXPECT_TRUE(class_of(dex, "LCircle;").interfaces.empty());
}

TEST(Read, read_whenClassIsAnInterface_returnsTheInterfaceAndAbstractFlags)
{
    Dex dex = read_fixture("shapes.dex");

    EXPECT_EQ(class_of(dex, "LShape;").access, AccessFlags::Interface | AccessFlags::Abstract);
}

TEST(Read, read_whenClassIsPublic_returnsThePublicFlag)
{
    Dex dex = read_fixture("classes.dex");

    EXPECT_EQ(class_of(dex, "LTestDex;").access, AccessFlags::Public);
}

TEST(Read, read_whenClassIsAnAnnotationType_returnsTheAnnotationFlag)
{
    Dex dex = read_fixture("annotated.dex");

    EXPECT_EQ(class_of(dex, "LMarker;").access,
              AccessFlags::Interface | AccessFlags::Abstract | AccessFlags::Annotation);
}

TEST(Read, read_whenClassHasASourceFile_returnsItsName)
{
    Dex dex = read_fixture("shapes.dex");

    EXPECT_EQ(class_of(dex, "LRectangle;").source_file, "Shapes.java");
}

TEST(Read, read_whenClassHasNoSourceFile_returnsNoSourceFile)
{
    auto bytes = load_fixture("fibonacci.dex");
    put_u32(bytes, class_def_off(bytes, 0) + kSourceFileIdx, raw::NO_INDEX);

    Dex dex = read_or_throw(bytes);

    EXPECT_EQ(dex.classes[0].source_file, std::nullopt);
}

TEST(Read, read_whenClassHasNoClassData_returnsNoFieldsAndNoMethods)
{
    Dex dex = read_fixture("inherit.dex");

    const ClassDef &tagged = class_of(dex, "LTagged;");
    EXPECT_TRUE(tagged.fields.empty());
    EXPECT_TRUE(tagged.methods.empty());
    EXPECT_EQ(tagged.interfaces, (std::vector<std::string>{"LNamed;"}));
}

TEST(Read, read_whenKeepClassIsSet_returnsOnlyTheClassesItAccepts)
{
    ReadOptions options;
    options.keep_class = [](std::string_view type) { return type == "LCircle;"; };

    Dex dex = read_fixture("shapes.dex", options);

    ASSERT_EQ(dex.classes.size(), 1u);
    EXPECT_EQ(dex.classes[0].type, "LCircle;");
}

TEST(Read, read_whenKeepClassIsSet_asksAboutEachClassInFileOrder)
{
    std::vector<std::string> asked;
    ReadOptions options;
    options.keep_class = [&](std::string_view type) {
        asked.emplace_back(type);
        return false;
    };

    Dex dex = read_fixture("shapes.dex", options);

    EXPECT_TRUE(dex.classes.empty());
    EXPECT_EQ(asked,
              (std::vector<std::string>{"LShape;", "LAbstractShape;", "LCircle;", "LRectangle;"}));
}

TEST(Read, read_whenClassHasInstanceFields_returnsNameTypeAndAccessOfEach)
{
    Dex dex = read_fixture("shapes.dex");

    const std::vector<FieldDef> &fields = class_of(dex, "LRectangle;").fields;
    ASSERT_EQ(fields.size(), 2u);
    EXPECT_EQ(fields[0].name, "height");
    EXPECT_EQ(fields[0].type, "D");
    EXPECT_EQ(fields[0].access, AccessFlags::Private);
    EXPECT_EQ(fields[1].name, "width");
    EXPECT_EQ(fields[1].type, "D");
    EXPECT_EQ(fields[1].access, AccessFlags::Private);
}

TEST(Read, read_whenFieldIsProtectedAndFinal_returnsBothFlags)
{
    Dex dex = read_fixture("polymorphic.dex");

    EXPECT_EQ(field_of(dex, "LPet;", "name", "Ljava/lang/String;").access,
              AccessFlags::Protected | AccessFlags::Final);
}

TEST(Read, read_whenFieldIsAnInstanceField_returnsNoInitialValue)
{
    Dex dex = read_fixture("fibonacci.dex");

    EXPECT_EQ(field_of(dex, "LFibonacci;", "sumFib", "J").initial_value, std::nullopt);
}

TEST(Read, read_whenClassHasStaticFields_returnsThemInFileOrder)
{
    Dex dex = read_fixture("annotated.dex");

    std::vector<std::string> names;
    for (const FieldDef &f : class_of(dex, "LAnnotated;").fields)
        names.push_back(f.name);
    EXPECT_EQ(names,
              (std::vector<std::string>{"BIG", "FLAG", "GREETING", "MAGIC", "PI", "counter"}));
}

TEST(Read, read_whenFieldIsStaticAndFinal_returnsBothFlags)
{
    Dex dex = read_fixture("annotated.dex");

    EXPECT_EQ(field_of(dex, "LAnnotated;", "MAGIC", "I").access,
              AccessFlags::Static | AccessFlags::Final);
}

TEST(Read, read_whenStaticFieldHasALongValue_returnsALong)
{
    Dex dex = read_fixture("annotated.dex");

    EXPECT_EQ(field_of(dex, "LAnnotated;", "BIG", "J").initial_value,
              Value{Value::Long{1234567890123}});
}

TEST(Read, read_whenStaticFieldHasABooleanValue_returnsABoolean)
{
    Dex dex = read_fixture("annotated.dex");

    EXPECT_EQ(field_of(dex, "LAnnotated;", "FLAG", "Z").initial_value, Value{Value::Boolean{true}});
}

TEST(Read, read_whenStaticFieldHasAStringValue_returnsAString)
{
    Dex dex = read_fixture("annotated.dex");

    EXPECT_EQ(field_of(dex, "LAnnotated;", "GREETING", "Ljava/lang/String;").initial_value,
              Value{Value::String{"hello"}});
}

TEST(Read, read_whenStaticFieldHasAnIntValue_returnsAnInt)
{
    Dex dex = read_fixture("annotated.dex");

    EXPECT_EQ(field_of(dex, "LAnnotated;", "MAGIC", "I").initial_value, Value{Value::Int{42}});
}

TEST(Read, read_whenStaticFieldHasADoubleValue_returnsADouble)
{
    Dex dex = read_fixture("annotated.dex");

    EXPECT_EQ(field_of(dex, "LAnnotated;", "PI", "D").initial_value, Value{Value::Double{3.25}});
}

TEST(Read, read_whenStaticFieldHasNoRecordedValue_returnsNoInitialValue)
{
    Dex dex = read_fixture("annotated.dex");

    EXPECT_EQ(field_of(dex, "LAnnotated;", "counter", "I").initial_value, std::nullopt);
}

// The encoded arrays below follow the encoded_value format of the DEX specification.
TEST(Read, read_whenStaticValuesAreSmallNumbers_returnsEachWithItsTypeAndSign)
{
    // clang-format off
    const std::vector<uint8_t> values = {
        7,
        0x00, 0xFF,
        0x02, 0xFE,
        0x03, 0x41,
        0x04, 0xFD,
        0x26, 0x00, 0x80,
        0x30, 0x80, 0x3F,
        0x31, 0xF0, 0x3F,
    };
    // clang-format on

    auto fields = multistring_static_values(values);

    ASSERT_EQ(fields.size(), 7u);
    EXPECT_EQ(fields[0], Value{Value::Byte{-1}});
    EXPECT_EQ(fields[1], Value{Value::Short{-2}});
    EXPECT_EQ(fields[2], Value{Value::Char{u'A'}});
    EXPECT_EQ(fields[3], Value{Value::Int{-3}});
    EXPECT_EQ(fields[4], Value{Value::Long{-32768}});
    EXPECT_EQ(fields[5], Value{Value::Float{1.0f}});
    EXPECT_EQ(fields[6], Value{Value::Double{1.0}});
}

TEST(Read, read_whenStaticValuesAreReferences_returnsEachReferenceInFull)
{
    // In multistring.dex: string 0x15 "main", type 3 String, field 7 System.out, method 3 println.
    // clang-format off
    const std::vector<uint8_t> values = {
        6,
        0x17, 0x15,
        0x18, 0x03,
        0x19, 0x07,
        0x1A, 0x03,
        0x1B, 0x07,
        0x1E,
    };
    // clang-format on
    const FieldId out{"Ljava/lang/System;", "out", "Ljava/io/PrintStream;"};

    auto fields = multistring_static_values(values);

    ASSERT_EQ(fields.size(), 7u);
    EXPECT_EQ(fields[0], Value{Value::String{"main"}});
    EXPECT_EQ(fields[1], Value{Value::Type{"Ljava/lang/String;"}});
    EXPECT_EQ(fields[2], Value{Value::Field{out}});
    EXPECT_EQ(fields[3], (Value{Value::Method{MethodId{"Ljava/io/PrintStream;", "println",
                                                       "(Ljava/lang/String;)V"}}}));
    EXPECT_EQ(fields[4], Value{Value::Enum{out}});
    EXPECT_EQ(fields[5], Value{Value::Null{}});
    EXPECT_EQ(fields[6], std::nullopt);
}

TEST(Read, read_whenAStaticValueIsAnArray_returnsItsElements)
{
    const std::vector<uint8_t> values = {1, 0x1C, 2, 0x1F, 0x3F};

    auto fields = multistring_static_values(values);

    EXPECT_EQ(fields[0],
              (Value{Value::Array{{Value{Value::Boolean{false}}, Value{Value::Boolean{true}}}}}));
}

TEST(Read, read_whenAStaticValueIsAMethodType_returnsThePrototype)
{
    // Prototype 1 of multistring.dex is (Ljava/lang/String;)V.
    const std::vector<uint8_t> values = {1, 0x15, 0x01};

    auto fields = multistring_static_values(values);

    EXPECT_EQ(fields[0], Value{Value::MethodType{"(Ljava/lang/String;)V"}});
}

TEST(Read, read_whenThereAreMoreStaticValuesThanStaticFields_returnsMalformed)
{
    const std::vector<uint8_t> values = {8, 0x1E, 0x1E, 0x1E, 0x1E, 0x1E, 0x1E, 0x1E, 0x1E};

    Error error = multistring_static_values_error(values);

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_EQ(error.message, "LMultiStringTest;: more static values than static fields");
}

TEST(Read, read_whenAnEncodedValueHasAnUnknownType_returnsMalformed)
{
    const std::vector<uint8_t> values = {1, 0x01};

    Error error = multistring_static_values_error(values);

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_EQ(error.message, "LMultiStringTest;: bad encoded value type 0x01");
}

TEST(Read, read_whenAnEncodedValueIsTooWideForItsType_returnsMalformed)
{
    const std::vector<uint8_t> values = {1, 0x20, 0x00, 0x00};

    Error error = multistring_static_values_error(values);

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_EQ(error.message, "LMultiStringTest;: bad size 2 for encoded value type 0x00");
}

TEST(Read, read_whenAnEncodedValueRunsPastTheEndOfTheFile_returnsMalformed)
{
    const std::vector<uint8_t> values = {1, 0x77, 0x01};

    Error error = multistring_static_values_error(values);

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_EQ(error.message, "LMultiStringTest;: encoded value runs past the end of the file");
}

TEST(Read, read_whenEncodedValuesNestDeeperThan64Levels_returnsMalformed)
{
    std::vector<uint8_t> values = {1};
    for (int depth = 0; depth < 66; ++depth)
        values.insert(values.end(), {0x1C, 1});
    values.push_back(0x1E);

    Error error = multistring_static_values_error(values);

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_EQ(error.message, "LMultiStringTest;: encoded values nest too deeply");
}

TEST(Read, read_whenAStaticValueNamesAMethodHandleTheFileDoesNotHave_returnsMalformed)
{
    const std::vector<uint8_t> values = {1, 0x16, 0x00};

    Error error = multistring_static_values_error(values);

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_EQ(error.message, "LMultiStringTest;: method handle index 0 is out of range");
}

TEST(Read, read_whenAClassWithoutClassDataHasStaticValues_returnsMalformed)
{
    auto bytes = load_fixture("inherit.dex");
    constexpr std::size_t kTagged = 19;
    put_u32(bytes, class_def_off(bytes, kTagged) + kStaticValuesOff,
            static_cast<uint32_t>(bytes.size()));
    bytes.push_back(0);

    Error error = read_error(bytes);

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_EQ(error.message, "LTagged;: static values without static fields");
}

TEST(Read, read_whenClassHasDirectAndVirtualMethods_returnsTheDirectMethodsFirst)
{
    Dex dex = read_fixture("fibonacci.dex");

    const std::vector<MethodDef> &methods = class_of(dex, "LFibonacci;").methods;
    ASSERT_EQ(methods.size(), 3u);
    EXPECT_EQ(methods[0].name, "<init>");
    EXPECT_EQ(methods[0].proto, "()V");
    EXPECT_EQ(methods[1].name, "classify");
    EXPECT_EQ(methods[1].proto, "(J)Ljava/lang/String;");
    EXPECT_EQ(methods[2].name, "compute");
    EXPECT_EQ(methods[2].proto, "(I)J");
}

TEST(Read, read_whenMethodIsAConstructor_returnsTheConstructorFlag)
{
    Dex dex = read_fixture("classes.dex");

    EXPECT_EQ(method_of(dex, "LTestDex;", "<init>", "()V").access,
              AccessFlags::Public | AccessFlags::Constructor);
}

TEST(Read, read_whenMethodIsAStaticInitializer_returnsTheStaticAndConstructorFlags)
{
    Dex dex = read_fixture("multistring.dex");

    EXPECT_EQ(method_of(dex, "LMultiStringTest;", "<clinit>", "()V").access,
              AccessFlags::Static | AccessFlags::Constructor);
}

TEST(Read, read_whenMethodIsPublicAndStatic_returnsBothFlags)
{
    Dex dex = read_fixture("fibonacci.dex");

    EXPECT_EQ(method_of(dex, "LFibonacci;", "classify", "(J)Ljava/lang/String;").access,
              AccessFlags::Public | AccessFlags::Static);
}

TEST(Read, read_whenMethodIsAbstract_returnsTheAbstractFlagAndNoCode)
{
    Dex dex = read_fixture("shapes.dex");

    const MethodDef &area = method_of(dex, "LShape;", "area", "()D");
    EXPECT_EQ(area.access, AccessFlags::Public | AccessFlags::Abstract);
    EXPECT_FALSE(area.code.has_value());
}

TEST(Read, read_whenMethodTakesSeveralParameters_returnsTheWholePrototype)
{
    Dex dex = read_fixture("shapes.dex");

    const ClassDef &rectangle = class_of(dex, "LRectangle;");

    EXPECT_NE(rectangle.find_method("<init>", "(Ljava/lang/String;DD)V"), nullptr);
}

TEST(Read, read_whenAnInterfaceHasADefaultMethod_returnsItsCode)
{
    Dex dex = read_fixture("inherit.dex");

    const MethodDef &greet = method_of(dex, "LGreeter;", "greet", "()V");
    EXPECT_EQ(greet.access, AccessFlags::Public);
    EXPECT_TRUE(greet.code.has_value());
}

TEST(Read, read_whenMethodHasCode_returnsItsRegisterCount)
{
    Dex dex = read_fixture("fibonacci.dex");

    EXPECT_EQ(code_of(dex, "LFibonacci;", "compute", "(I)J").registers, 11);
}

TEST(Read, read_whenCodeUsesFieldsAndMethods_returnsEachReferenceInFull)
{
    Dex dex = read_fixture("classes.dex", kNoDebugInfo);

    const Code &code = code_of(dex, "LTestDex;", "main", "([Ljava/lang/String;)V");

    const std::vector<Item> expected{
        Insn{StaticGet{ValueKind::Object, 1,
                       FieldId{"Ljava/lang/System;", "out", "Ljava/io/PrintStream;"}}},
        Insn{Invoke{
            Invoke::Kind::Static, {}, MethodId{"LTestDex;", "helloDex", "()Ljava/lang/String;"}}},
        Insn{MoveResult{ValueKind::Object, 0}},
        Insn{Invoke{Invoke::Kind::Virtual,
                    {1, 0},
                    MethodId{"Ljava/io/PrintStream;", "println", "(Ljava/lang/String;)V"}}},
        Insn{ReturnVoid{}},
    };
    EXPECT_EQ(code.items, expected);
}

TEST(Read, read_whenCodeReturnsAStringConstant_returnsTheStringAndAnObjectReturn)
{
    Dex dex = read_fixture("classes.dex", kNoDebugInfo);

    const Code &code = code_of(dex, "LTestDex;", "helloDex", "()Ljava/lang/String;");

    const std::vector<Item> expected{
        Insn{ConstString{0, "Hello Dex++!!"}},
        Insn{Return{ValueKind::Object, 0}},
    };
    EXPECT_EQ(code.items, expected);
}

TEST(Read, read_whenCodeBranchesForward_placesALabelBeforeEachTarget)
{
    Dex dex = read_fixture("fibonacci.dex", kNoDebugInfo);

    const Code &code = code_of(dex, "LFibonacci;", "classify", "(J)Ljava/lang/String;");

    const std::vector<Item> expected{
        Insn{ConstWide{0, 0}},
        Insn{Compare{CompareOp::CmpLong, 2, 3, 0}},
        Insn{IfZero{Condition::Ge, 2, Label{0}}},
        Insn{ConstString{3, "negative"}},
        Insn{Return{ValueKind::Object, 3}},
        Label{0},
        Insn{Compare{CompareOp::CmpLong, 2, 3, 0}},
        Insn{IfZero{Condition::Ne, 2, Label{1}}},
        Insn{ConstString{3, "zero"}},
        Insn{Return{ValueKind::Object, 3}},
        Label{1},
        Insn{ConstWide{0, 10}},
        Insn{Compare{CompareOp::CmpLong, 2, 3, 0}},
        Insn{IfZero{Condition::Ge, 2, Label{2}}},
        Insn{ConstString{3, "small"}},
        Insn{Return{ValueKind::Object, 3}},
        Label{2},
        Insn{ConstWide{0, 100}},
        Insn{Compare{CompareOp::CmpLong, 2, 3, 0}},
        Insn{IfZero{Condition::Ge, 2, Label{3}}},
        Insn{ConstString{3, "medium"}},
        Insn{Return{ValueKind::Object, 3}},
        Label{3},
        Insn{ConstString{3, "large"}},
        Insn{Return{ValueKind::Object, 3}},
    };
    EXPECT_EQ(code.items, expected);
}

TEST(Read, read_whenCodeHasLabels_countsThemInTheCode)
{
    Dex dex = read_fixture("fibonacci.dex");

    EXPECT_EQ(code_of(dex, "LFibonacci;", "classify", "(J)Ljava/lang/String;").label_count(), 4u);
}

TEST(Read, read_whenCodeBranchesBackward_placesTheLabelBeforeTheEarlierInstruction)
{
    Dex dex = read_fixture("fibonacci.dex", kNoDebugInfo);

    const std::vector<Item> &items = code_of(dex, "LFibonacci;", "compute", "(I)J").items;

    // Labels 0..3 are at code offsets 0x05, 0x0a, 0x14 and 0x20.
    ASSERT_EQ(items.size(), 31u);
    EXPECT_EQ(items[17], Item{Label{2}});
    EXPECT_EQ(items[18], (Item{Insn{If{Condition::Gt, 6, 10, Label{3}}}}));
    EXPECT_EQ(items[27], (Item{Insn{Goto{Label{2}}}}));
    EXPECT_EQ(items[28], Item{Label{3}});
}

TEST(Read, read_whenCodeHasNops_keepsThem)
{
    Dex dex = read_fixture("fibonacci.dex");

    std::vector<Insn> insns = insns_of(code_of(dex, "LFibonacci;", "compute", "(I)J"));

    ASSERT_EQ(insns.size(), 27u);
    EXPECT_EQ(insns[6], Insn{Nop{}});
    EXPECT_EQ(insns[7], Insn{Nop{}});
    EXPECT_EQ(insns[8], Insn{Nop{}});
}

TEST(Read, read_whenCodeUsesATwoAddressOperation_returnsTheDestinationAsTheFirstOperand)
{
    Dex dex = read_fixture("fibonacci.dex");

    std::vector<Insn> insns = insns_of(code_of(dex, "LFibonacci;", "compute", "(I)J"));

    ASSERT_EQ(insns.size(), 27u);
    EXPECT_EQ(insns[16], (Insn{Binary{BinaryOp::AddLong, 2, 2, 0}}));
}

TEST(Read, read_whenCodeAddsAnEightBitLiteral_returnsABinaryLiteral)
{
    Dex dex = read_fixture("fibonacci.dex");

    std::vector<Insn> insns = insns_of(code_of(dex, "LFibonacci;", "compute", "(I)J"));

    ASSERT_EQ(insns.size(), 27u);
    EXPECT_EQ(insns[20], (Insn{BinaryLiteral{LiteralOp::Add, 6, 6, 1}}));
}

TEST(Read, read_whenCodeMovesAWideValue_returnsAWideMove)
{
    Dex dex = read_fixture("fibonacci.dex");

    std::vector<Insn> insns = insns_of(code_of(dex, "LFibonacci;", "compute", "(I)J"));

    ASSERT_EQ(insns.size(), 27u);
    EXPECT_EQ(insns[11], (Insn{Move{ValueKind::Wide, 4, 2}}));
}

TEST(Read, read_whenCodeLoadsASmallIntConstant_returnsItsValue)
{
    Dex dex = read_fixture("fibonacci.dex");

    std::vector<Insn> insns = insns_of(code_of(dex, "LFibonacci;", "compute", "(I)J"));

    ASSERT_EQ(insns.size(), 27u);
    EXPECT_EQ(insns[10], (Insn{Const{4, 2}}));
}

TEST(Read, read_whenCodeLoadsANegativeWideConstant_returnsTheSignExtendedValue)
{
    Dex dex = read_fixture("fibonacci.dex");

    std::vector<Insn> insns = insns_of(code_of(dex, "LFibonacci;", "compute", "(I)J"));

    ASSERT_EQ(insns.size(), 27u);
    EXPECT_EQ(insns[1], (Insn{ConstWide{0, -1}}));
    EXPECT_EQ(insns[2], (Insn{Return{ValueKind::Wide, 0}}));
}

TEST(Read, read_whenCodeWritesAWideInstanceField_returnsTheFieldAndBothRegisters)
{
    Dex dex = read_fixture("fibonacci.dex");

    std::vector<Insn> insns = insns_of(code_of(dex, "LFibonacci;", "compute", "(I)J"));

    ASSERT_EQ(insns.size(), 27u);
    EXPECT_EQ(insns[25],
              (Insn{InstancePut{ValueKind::Wide, 4, 9, FieldId{"LFibonacci;", "sumFib", "J"}}}));
}

TEST(Read, read_whenCodeLoadsA64BitConstant_returnsAllItsBits)
{
    Dex dex = read_fixture("shapes.dex", kNoDebugInfo);

    const Code &code = code_of(dex, "LCircle;", "area", "()D");

    const std::vector<Item> expected{
        Insn{InstanceGet{ValueKind::Wide, 0, 4, FieldId{"LCircle;", "radius", "D"}}},
        Insn{ConstWide{2, 0x400921fb54442d18}},
        Insn{Binary{BinaryOp::MulDouble, 2, 2, 0}},
        Insn{Binary{BinaryOp::MulDouble, 2, 2, 0}},
        Insn{Return{ValueKind::Wide, 2}},
    };
    EXPECT_EQ(code.items, expected);
}

TEST(Read, read_whenCodeUsesConstWideHigh16_returnsTheValueShiftedToTheTop)
{
    Dex dex = read_fixture("shapes.dex", kNoDebugInfo);

    const Code &code = code_of(dex, "LRectangle;", "perimeter", "()D");

    const std::vector<Item> expected{
        Insn{InstanceGet{ValueKind::Wide, 0, 4, FieldId{"LRectangle;", "width", "D"}}},
        Insn{InstanceGet{ValueKind::Wide, 2, 4, FieldId{"LRectangle;", "height", "D"}}},
        Insn{Binary{BinaryOp::AddDouble, 0, 0, 2}},
        Insn{ConstWide{2, 0x4000000000000000}},
        Insn{Binary{BinaryOp::MulDouble, 0, 0, 2}},
        Insn{Return{ValueKind::Wide, 0}},
    };
    EXPECT_EQ(code.items, expected);
}

TEST(Read, read_whenCodeWritesAnObjectField_returnsAnObjectInstancePut)
{
    Dex dex = read_fixture("shapes.dex", kNoDebugInfo);

    const Code &code = code_of(dex, "LAbstractShape;", "<init>", "(Ljava/lang/String;)V");

    const std::vector<Item> expected{
        Insn{Invoke{Invoke::Kind::Direct, {0}, MethodId{"Ljava/lang/Object;", "<init>", "()V"}}},
        Insn{InstancePut{ValueKind::Object, 1, 0,
                         FieldId{"LAbstractShape;", "color", "Ljava/lang/String;"}}},
        Insn{ReturnVoid{}},
    };
    EXPECT_EQ(code.items, expected);
}

TEST(Read, read_whenCodeCallsAnInterfaceMethod_returnsAnInterfaceInvoke)
{
    Dex dex = read_fixture("polymorphic.dex", kNoDebugInfo);

    const Code &code = code_of(dex, "LKennel;", "noise", "(LAnimal;)Ljava/lang/String;");

    const std::vector<Item> expected{
        Insn{Invoke{
            Invoke::Kind::Interface, {0}, MethodId{"LAnimal;", "sound", "()Ljava/lang/String;"}}},
        Insn{MoveResult{ValueKind::Object, 0}},
        Insn{Return{ValueKind::Object, 0}},
    };
    EXPECT_EQ(code.items, expected);
}

TEST(Read, read_whenCodeCallsASuperMethod_returnsASuperInvoke)
{
    Dex dex = read_fixture("polymorphic.dex");

    std::vector<Insn> insns = insns_of(code_of(dex, "LDog;", "describe", "()Ljava/lang/String;"));

    ASSERT_EQ(insns.size(), 10u);
    EXPECT_EQ(insns[2], (Insn{Invoke{Invoke::Kind::Super,
                                     {2},
                                     MethodId{"LPet;", "describe", "()Ljava/lang/String;"}}}));
}

TEST(Read, read_whenCodeCreatesAnObject_returnsNewInstanceWithItsType)
{
    Dex dex = read_fixture("polymorphic.dex");

    std::vector<Insn> insns = insns_of(code_of(dex, "LDog;", "describe", "()Ljava/lang/String;"));

    ASSERT_EQ(insns.size(), 10u);
    EXPECT_EQ(insns[0], (Insn{NewInstance{0, "Ljava/lang/StringBuilder;"}}));
}

TEST(Read, read_whenCodeCastsAnObject_returnsCheckCastWithItsType)
{
    Dex dex = read_fixture("casts.dex", kNoDebugInfo);

    const Code &code = code_of(dex, "LCasts;", "doCast", "()Ljava/lang/String;");

    const std::vector<Item> expected{
        Insn{StaticGet{ValueKind::Object, 0, FieldId{"LCasts;", "box", "Ljava/lang/Object;"}}},
        Insn{CheckCast{0, "Ljava/lang/String;"}},
        Insn{Return{ValueKind::Object, 0}},
    };
    EXPECT_EQ(code.items, expected);
}

TEST(Read, read_whenCodeBuildsAnArray_returnsNewArrayAndTheArrayPuts)
{
    Dex dex = read_fixture("casts.dex", kNoDebugInfo);

    const Code &code =
        code_of(dex, "LCasts;", "makeArray",
                "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)[Ljava/lang/String;");

    const std::vector<Item> expected{
        Insn{Const{0, 3}},
        Insn{NewArray{0, 0, "[Ljava/lang/String;"}},
        Insn{Const{1, 0}},
        Insn{ArrayPut{ValueKind::Object, 2, 0, 1}},
        Insn{Const{2, 1}},
        Insn{ArrayPut{ValueKind::Object, 3, 0, 2}},
        Insn{Const{2, 2}},
        Insn{ArrayPut{ValueKind::Object, 4, 0, 2}},
        Insn{Return{ValueKind::Object, 0}},
    };
    EXPECT_EQ(code.items, expected);
}

TEST(Read, read_whenCodeWritesStaticFields_returnsAnObjectStaticPut)
{
    Dex dex = read_fixture("multistring.dex");

    std::vector<Insn> insns = insns_of(code_of(dex, "LMultiStringTest;", "<clinit>", "()V"));

    ASSERT_EQ(insns.size(), 15u);
    EXPECT_EQ(insns[1],
              (Insn{StaticPut{ValueKind::Object, 0,
                              FieldId{"LMultiStringTest;", "greeting", "Ljava/lang/String;"}}}));
}

TEST(Read, read_whenAStringHasSupplementaryCharacters_returnsThemAsFourByteUtf8)
{
    Dex dex = read_fixture("multistring.dex");

    std::vector<Insn> insns = insns_of(code_of(dex, "LMultiStringTest;", "<clinit>", "()V"));

    ASSERT_EQ(insns.size(), 15u);
    EXPECT_EQ(insns[8], (Insn{ConstString{0, "\xF0\x9F\x8E\x89 Party time! \xF0\x9F\x8E\x8A"}}));
}

TEST(Read, read_whenAStringIsEmpty_returnsAnEmptyString)
{
    Dex dex = read_fixture("multistring.dex");

    std::vector<Insn> insns = insns_of(code_of(dex, "LMultiStringTest;", "<clinit>", "()V"));

    ASSERT_EQ(insns.size(), 15u);
    EXPECT_EQ(insns[10], (Insn{ConstString{0, ""}}));
}

TEST(Read, read_whenAStringHasAnEmbeddedNul_returnsTheNulAsOneZeroByte)
{
    Dex dex = read_fixture("multistring.dex");

    std::vector<Insn> insns = insns_of(code_of(dex, "LMultiStringTest;", "<clinit>", "()V"));

    ASSERT_EQ(insns.size(), 15u);
    EXPECT_EQ(insns[12], (Insn{ConstString{0, std::string("test\0embedded", 13)}}));
}

TEST(Read, read_whenAStringIsNotValidMutf8_returnsMalformed)
{
    auto bytes = load_fixture("multistring.dex");
    // String 7, "LMultiStringTest;", has its data at 0x304: one length byte, then the text.
    constexpr std::size_t kSecondCharacter = 0x306;
    ASSERT_EQ(bytes[kSecondCharacter], 'M');
    bytes[kSecondCharacter] = 0xFF;

    Error error = read_error(bytes);

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_TRUE(error.message.starts_with("string 7: ")) << error.message;
}

// The code units below are written by hand and were checked with dexdump -d.
TEST(Read, read_whenCodeHasAPackedSwitch_returnsOneCasePerKeyWithALabelAtItsTarget)
{
    Code code = fibonacci_classify_with_insns(
        switch_code(0x032B, {0x0100, 0x0002, 0x0005, 0x0000, 0x0005, 0x0000, 0x0006, 0x0000}));

    const std::vector<Item> expected{
        Insn{Switch{3, {{5, Label{0}}, {6, Label{1}}}}},
        Insn{ConstString{3, "negative"}},
        Label{0},
        Insn{Return{ValueKind::Object, 3}},
        Label{1},
        Insn{ConstString{3, "zero"}},
        Insn{Return{ValueKind::Object, 3}},
    };
    EXPECT_EQ(code.items, expected);
}

TEST(Read, read_whenAPackedSwitchCaseGoesToTheNextInstruction_leavesTheCaseOut)
{
    Code code = fibonacci_classify_with_insns(switch_code(
        0x032B, {0x0100, 0x0003, 0x0005, 0x0000, 0x0006, 0x0000, 0x0003, 0x0000, 0x0005, 0x0000}));

    EXPECT_EQ(insns_of(code)[0], (Insn{Switch{3, {{5, Label{1}}, {7, Label{0}}}}}));
}

TEST(Read, read_whenANopPadsAPayload_leavesTheNopOut)
{
    Code code = fibonacci_classify_with_insns(
        switch_code(0x032B, {0x0100, 0x0002, 0x0005, 0x0000, 0x0005, 0x0000, 0x0006, 0x0000}));

    for (const Insn &insn : insns_of(code))
        EXPECT_FALSE(std::holds_alternative<Nop>(insn));
}

TEST(Read, read_whenCodeHasASparseSwitch_returnsItsKeysAndLabels)
{
    Code code = fibonacci_classify_with_insns(switch_code(
        0x032C, {0x0200, 0x0002, 0xFFFF, 0xFFFF, 0x0064, 0x0000, 0x0005, 0x0000, 0x0006, 0x0000}));

    EXPECT_EQ(insns_of(code)[0], (Insn{Switch{3, {{-1, Label{0}}, {100, Label{1}}}}}));
}

TEST(Read, read_whenCodeHasFillArrayData_returnsTheElementWidthAndTheBytes)
{
    Code code = fibonacci_classify_with_insns({
        0x0026,
        0x0004,
        0x0000,
        0x000E,
        0x0300,
        0x0001,
        0x0003,
        0x0000,
        0x0201,
        0x0003,
    });

    const std::vector<Item> expected{
        Insn{FillArrayData{0, 1, {1, 2, 3}}},
        Insn{ReturnVoid{}},
    };
    EXPECT_EQ(code.items, expected);
}

TEST(Read, read_whenNoInstructionRefersToAPayload_dropsThePayload)
{
    Code code = fibonacci_classify_with_insns({
        0x000E,
        0x0000,
        0x0300,
        0x0001,
        0x0002,
        0x0000,
        0x0201,
    });

    const std::vector<Item> expected{Insn{ReturnVoid{}}};
    EXPECT_EQ(code.items, expected);
}

TEST(Read, read_whenAnInvokeTakesARegisterRange_returnsTheRunOfRegisters)
{
    Code code = fibonacci_classify_with_insns({0x0377, 0x0001, 0x0001, 0x000E});

    EXPECT_EQ(insns_of(code)[0],
              (Insn{Invoke{Invoke::Kind::Static, RegList::range(1, 3),
                           MethodId{"LFibonacci;", "classify", "(J)Ljava/lang/String;"}}}));
}

TEST(Read, read_whenARegisterRangeRunsPastV65535_returnsMalformed)
{
    Error error = fibonacci_classify_insns_error({0x0277, 0x0001, 0xFFFF, 0x000E});

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_TRUE(contains(error.message, "register range at code offset 0 runs past v65535"))
        << error.message;
}

TEST(Read, read_whenCodeHasFilledNewArray_returnsItsRegistersAndTheArrayType)
{
    auto bytes = load_fixture("casts.dex");
    // Type 4 of casts.dex is [Ljava/lang/String;.
    set_insns(bytes, kCastsMakeArrayCode, {0x3024, 0x0004, 0x0432, 0x000C, 0x0011});

    Dex dex = read_or_throw(bytes);

    const std::vector<Item> expected{
        Insn{FilledNewArray{{2, 3, 4}, "[Ljava/lang/String;"}},
        Insn{MoveResult{ValueKind::Object, 0}},
        Insn{Return{ValueKind::Object, 0}},
    };
    const Code &code =
        code_of(dex, "LCasts;", "makeArray",
                "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)[Ljava/lang/String;");
    EXPECT_EQ(code.items, expected);
}

TEST(Read, read_whenCodeHasInvokePolymorphic_returnsTheMethodAndTheCallPrototype)
{
    Code code = fibonacci_classify_with_insns({0x20FA, 0x0002, 0x0034, 0x0001, 0x000E});

    EXPECT_EQ(insns_of(code)[0],
              (Insn{InvokePolymorphic{
                  {4, 3}, MethodId{"LFibonacci;", "compute", "(I)J"}, "(J)Ljava/lang/String;"}}));
}

TEST(Read, read_whenCodeHasConstMethodType_returnsThePrototype)
{
    Code code = fibonacci_classify_with_insns({0x02FF, 0x0000, 0x000E});

    EXPECT_EQ(insns_of(code)[0], (Insn{ConstMethodType{2, "(I)J"}}));
}

TEST(Read, read_whenCodeHasConstClass_returnsTheType)
{
    Code code = fibonacci_classify_with_insns({0x021C, 0x0004, 0x000E});

    EXPECT_EQ(insns_of(code)[0], (Insn{ConstClass{2, "Ljava/lang/String;"}}));
}

TEST(Read, read_whenCodeUsesConstHigh16_returnsTheValueShiftedToTheTop)
{
    Code code = fibonacci_classify_with_insns({0x0215, 0x3F80, 0x000E});

    EXPECT_EQ(insns_of(code)[0], (Insn{Const{2, 0x3F800000}}));
}

TEST(Read, read_whenASparseSwitchHasKeysOutOfOrder_returnsMalformed)
{
    Error error = fibonacci_classify_insns_error(switch_code(
        0x032C, {0x0200, 0x0002, 0x0064, 0x0000, 0xFFFF, 0xFFFF, 0x0005, 0x0000, 0x0006, 0x0000}));

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_TRUE(contains(error.message, "sparse-switch keys at code offset 0 are not increasing"))
        << error.message;
}

TEST(Read, read_whenPackedSwitchKeysPassTheLargestInt_returnsMalformed)
{
    Error error = fibonacci_classify_insns_error(
        switch_code(0x032B, {0x0100, 0x0002, 0xFFFF, 0x7FFF, 0x0005, 0x0000, 0x0006, 0x0000}));

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_TRUE(contains(error.message, "packed-switch keys at code offset 0 overflow"))
        << error.message;
}

TEST(Read, read_whenASwitchCaseGoesIntoAnInstruction_returnsMalformed)
{
    Error error = fibonacci_classify_insns_error(
        switch_code(0x032B, {0x0100, 0x0001, 0x0005, 0x0000, 0x0004, 0x0000}));

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_TRUE(contains(error.message,
                         "switch case at code offset 0 goes to 4, which is not an instruction"))
        << error.message;
}

TEST(Read, read_whenASwitchPointsAtAnInstruction_returnsMalformed)
{
    Error error = fibonacci_classify_insns_error({0x032B, 0x0003, 0x0000, 0x000E});

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_TRUE(contains(error.message, "instruction at code offset 0 has no payload at 3"))
        << error.message;
}

TEST(Read, read_whenASwitchPointsAtAPayloadOfAnotherKind_returnsMalformed)
{
    Error error = fibonacci_classify_insns_error({
        0x032C,
        0x0004,
        0x0000,
        0x000E,
        0x0100,
        0x0000,
        0x0000,
        0x0000,
    });

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_TRUE(contains(error.message, "instruction at code offset 0 has no payload at 4"))
        << error.message;
}

TEST(Read, read_whenAPayloadIsLongerThanTheCode_returnsMalformed)
{
    Error error = fibonacci_classify_insns_error({0x000E, 0x0000, 0x0100, 0x00FF});

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_TRUE(contains(error.message, "bad payload at code offset 2")) << error.message;
}

TEST(Read, read_whenAPayloadStartsAtAnOddOffset_returnsMalformed)
{
    Error error = fibonacci_classify_insns_error({0x000E, 0x0100, 0x0000, 0x0000, 0x0000});

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_TRUE(contains(error.message, "payload at odd code offset 1")) << error.message;
}

TEST(Read, read_whenABranchGoesPastTheCode_returnsMalformed)
{
    Error error = fibonacci_classify_insns_error({0x0528, 0x000E});

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_TRUE(
        contains(error.message, "branch at code offset 0 goes to 5, which is not an instruction"))
        << error.message;
}

TEST(Read, read_whenABranchGoesBeforeTheCode_returnsMalformed)
{
    Error error = fibonacci_classify_insns_error({0xFF28, 0x000E});

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_TRUE(
        contains(error.message, "branch at code offset 0 goes to -1, which is not an instruction"))
        << error.message;
}

TEST(Read, read_whenABranchGoesIntoAnInstruction_returnsMalformed)
{
    Error error = fibonacci_classify_insns_error({0x0228, 0x031A, kStringNegative, 0x0311});

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_TRUE(
        contains(error.message, "branch at code offset 0 goes to 2, which is not an instruction"))
        << error.message;
}

TEST(Read, read_whenTheLastInstructionIsCutShort_returnsMalformed)
{
    Error error = fibonacci_classify_insns_error({0x000E, 0x031A});

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_TRUE(contains(error.message, "code offset 1: ")) << error.message;
}

TEST(Read, read_whenAStringIndexIsOutOfRange_returnsMalformed)
{
    Error error = fibonacci_classify_insns_error({0x031A, 0xFFFF, 0x0311});

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_TRUE(contains(error.message, "string index 65535 is out of range")) << error.message;
}

TEST(Read, read_whenATypeIndexIsOutOfRange_returnsMalformed)
{
    Error error = fibonacci_classify_insns_error({0x031C, 0xFFFF, 0x0311});

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_TRUE(contains(error.message, "type index 65535 is out of range")) << error.message;
}

TEST(Read, read_whenAFieldIndexIsOutOfRange_returnsMalformed)
{
    Error error = fibonacci_classify_insns_error({0x0360, 0xFFFF, 0x0311});

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_TRUE(contains(error.message, "field index 65535 is out of range")) << error.message;
}

TEST(Read, read_whenAMethodIndexIsOutOfRange_returnsMalformed)
{
    Error error = fibonacci_classify_insns_error({0x0071, 0xFFFF, 0x0000, 0x000E});

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_TRUE(contains(error.message, "method index 65535 is out of range")) << error.message;
}

TEST(Read, read_whenAPrototypeIndexIsOutOfRange_returnsMalformed)
{
    Error error = fibonacci_classify_insns_error({0x02FF, 0xFFFF, 0x000E});

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_TRUE(contains(error.message, "prototype index 65535 is out of range")) << error.message;
}

TEST(Read, read_whenCodeNamesAMethodHandleTheFileDoesNotHave_returnsMalformed)
{
    Error error = fibonacci_classify_insns_error({0x02FE, 0x0000, 0x000E});

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_TRUE(contains(error.message, "method handle index 0 is out of range")) << error.message;
}

TEST(Read, read_whenCodeNamesACallSiteTheFileDoesNotHave_returnsMalformed)
{
    Error error = fibonacci_classify_insns_error({0x00FC, 0x0000, 0x0000, 0x000E});

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_TRUE(contains(error.message, "call site index 0 is out of range")) << error.message;
}

TEST(Read, read_whenCodeHasAnUnusedOpcode_returnsMalformed)
{
    auto bytes = load_fixture("classes.dex");
    constexpr std::size_t kReturnVoid = kClassesInitCode + kCodeInsns + 6;
    ASSERT_EQ(bytes[kReturnVoid], 0x0E);
    bytes[kReturnVoid] = 0x3E;

    Error error = read_error(bytes);

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
}

TEST(Read, read_whenCodeIsMalformed_namesTheMethodInTheMessage)
{
    auto bytes = load_fixture("classes.dex");
    constexpr std::size_t kReturnVoid = kClassesInitCode + kCodeInsns + 6;
    ASSERT_EQ(bytes[kReturnVoid], 0x0E);
    bytes[kReturnVoid] = 0x3E;

    Error error = read_error(bytes);

    EXPECT_TRUE(error.message.starts_with("LTestDex;-><init>()V: code offset 3: "))
        << error.message;
}

TEST(Read, read_whenMethodHasOneTryBlock_returnsItsRangeAndItsTypedHandler)
{
    Dex dex = read_fixture("trycatch.dex", kNoDebugInfo);

    const Code &code = code_of(dex, "LTryCatch;", "divide", "(II)I");

    const std::vector<Item> expected_items{
        Label{0},           Insn{Binary{BinaryOp::DivInt, 0, 0, 1}},
        Label{1},           Insn{Return{ValueKind::Normal, 0}},
        Label{2},           Insn{MoveException{0}},
        Insn{Const{0, -1}}, Insn{Return{ValueKind::Normal, 0}},
    };
    const std::vector<TryRange> expected_tries{
        TryRange{Label{0}, Label{1}, {Catch{"Ljava/lang/ArithmeticException;", Label{2}}}, {}},
    };
    EXPECT_EQ(code.items, expected_items);
    EXPECT_EQ(code.tries, expected_tries);
}

TEST(Read, read_whenATryBlockHasATypedHandlerAndACatchAll_returnsBoth)
{
    Dex dex = read_fixture("trycatch.dex");

    const Code &code =
        code_of(dex, "LTryCatch;", "safeParse", "(Ljava/lang/String;)Ljava/lang/String;");

    // Labels 0..6 are at code offsets 0x02, 0x0a, 0x10, 0x12, 0x13, 0x15 and 0x1b.
    ASSERT_EQ(code.tries.size(), 2u);
    EXPECT_EQ(
        code.tries[0],
        (TryRange{
            Label{0}, Label{1}, {Catch{"Ljava/lang/NumberFormatException;", Label{3}}}, Label{2}}));
}

TEST(Read, read_whenATryBlockHasOnlyACatchAll_returnsNoTypedHandler)
{
    Dex dex = read_fixture("trycatch.dex");

    const Code &code =
        code_of(dex, "LTryCatch;", "safeParse", "(Ljava/lang/String;)Ljava/lang/String;");

    ASSERT_EQ(code.tries.size(), 2u);
    EXPECT_EQ(code.tries[1], (TryRange{Label{4}, Label{5}, {}, Label{2}}));
}

TEST(Read, read_whenTwoTryBlocksShareAHandler_placesItsLabelOnceBeforeMoveException)
{
    Dex dex = read_fixture("trycatch.dex", kNoDebugInfo);

    const std::vector<Item> &items =
        code_of(dex, "LTryCatch;", "safeParse", "(Ljava/lang/String;)Ljava/lang/String;").items;

    std::vector<std::size_t> positions;
    for (std::size_t i = 0; i < items.size(); ++i)
        if (items[i] == Item{Label{2}})
            positions.push_back(i);
    ASSERT_EQ(positions.size(), 1u);
    ASSERT_LT(positions[0] + 1, items.size());
    EXPECT_EQ(items[positions[0] + 1], (Item{Insn{MoveException{2}}}));
}

TEST(Read, read_whenMethodHasNoTryBlock_returnsNoTryRanges)
{
    Dex dex = read_fixture("fibonacci.dex");

    EXPECT_TRUE(code_of(dex, "LFibonacci;", "compute", "(I)J").tries.empty());
}

TEST(Read, read_whenATryRangeStartsInsideAnInstruction_returnsMalformed)
{
    auto bytes = load_fixture("trycatch.dex");
    // safeParse has 33 code units, so its first try_item is at code item + 16 + 66 + 2.
    constexpr std::size_t kStartAddr = kTrycatchSafeParseCode + 0x54;
    ASSERT_EQ(get_u32(bytes, kStartAddr), 2u);
    put_u32(bytes, kStartAddr, 3);

    Error error = read_error(bytes);

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_EQ(error.message,
              "LTryCatch;->safeParse(Ljava/lang/String;)Ljava/lang/String;: try range at code "
              "offset 3 does not cover whole instructions");
}

TEST(Read, read_whenATryRangeEndsInsideAnInstruction_returnsMalformed)
{
    auto bytes = load_fixture("trycatch.dex");
    constexpr std::size_t kInsnCount = kTrycatchSafeParseCode + 0x58;
    ASSERT_EQ(bytes[kInsnCount], 8);
    bytes[kInsnCount] = 6;

    Error error = read_error(bytes);

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_TRUE(
        contains(error.message, "try range at code offset 2 does not cover whole instructions"))
        << error.message;
}

TEST(Read, read_whenATryRangeCoversNoInstruction_returnsMalformed)
{
    auto bytes = load_fixture("trycatch.dex");
    constexpr std::size_t kInsnCount = kTrycatchSafeParseCode + 0x58;
    ASSERT_EQ(bytes[kInsnCount], 8);
    bytes[kInsnCount] = 0;

    Error error = read_error(bytes);

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_TRUE(
        contains(error.message, "try range at code offset 2 does not cover whole instructions"))
        << error.message;
}

TEST(Read, read_whenATryRangeNamesNoHandler_returnsMalformed)
{
    auto bytes = load_fixture("trycatch.dex");
    constexpr std::size_t kHandlerOff = kTrycatchSafeParseCode + 0x5A;
    ASSERT_EQ(bytes[kHandlerOff], 1);
    bytes[kHandlerOff] = 0x7F;

    Error error = read_error(bytes);

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_TRUE(contains(error.message, "try range at code offset 2 has no handler at 127"))
        << error.message;
}

TEST(Read, read_whenACatchHandlerIsNotAtAnInstruction_returnsMalformed)
{
    auto bytes = load_fixture("trycatch.dex");
    // The handler address is the last byte of divide's encoded_catch_handler_list.
    constexpr std::size_t kHandlerAddr = kTrycatchDivideCode + 0x27;
    ASSERT_EQ(bytes[kHandlerAddr], 2);
    bytes[kHandlerAddr] = 9;

    Error error = read_error(bytes);

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_TRUE(contains(error.message,
                         "catch handler at code offset 0 goes to 9, which is not an instruction"))
        << error.message;
}

TEST(Read, read_whenDebugInfoIsRead_returnsALineNumberBeforeTheInstructionAtEachPosition)
{
    Dex dex = read_fixture("classes.dex");

    const Code &code = code_of(dex, "LTestDex;", "main", "([Ljava/lang/String;)V");

    EXPECT_EQ(lines_with_insns_before(code),
              (std::vector<std::pair<uint32_t, std::size_t>>{{14, 0}, {15, 4}}));
}

TEST(Read, read_whenDebugInfoDoesNotNameAParameter_returnsNoNameForIt)
{
    Dex dex = read_fixture("classes.dex");

    const Code &code = code_of(dex, "LTestDex;", "main", "([Ljava/lang/String;)V");

    EXPECT_EQ(code.parameter_names, (std::vector<std::optional<std::string>>{std::nullopt}));
}

TEST(Read, read_whenDebugInfoIsOff_returnsOnlyInstructionsAndLabels)
{
    Dex with_debug = read_fixture("fibonacci.dex");
    Dex without_debug = read_fixture("fibonacci.dex", kNoDebugInfo);

    const Code &with = code_of(with_debug, "LFibonacci;", "compute", "(I)J");
    const Code &without = code_of(without_debug, "LFibonacci;", "compute", "(I)J");

    EXPECT_EQ(count_of<LineNumber>(with), 13u);
    EXPECT_EQ(count_of<Insn>(without) + count_of<Label>(without), without.items.size());
}

TEST(Read, read_whenDebugInfoIsOff_returnsNoParameterNames)
{
    Dex dex = read_fixture("classes.dex", kNoDebugInfo);

    const Code &code = code_of(dex, "LTestDex;", "main", "([Ljava/lang/String;)V");

    EXPECT_TRUE(code.parameter_names.empty());
}

TEST(Read, read_whenCodeHasNoDebugInfo_returnsOnlyInstructionsAndLabels)
{
    auto bytes = load_fixture("classes.dex");
    put_u32(bytes, kClassesInitCode + kCodeDebugInfoOff, 0);

    Dex dex = read_or_throw(bytes);

    const Code &code = code_of(dex, "LTestDex;", "<init>", "()V");
    EXPECT_EQ(code.items.size(), 2u);
    EXPECT_TRUE(code.parameter_names.empty());
}

// The debug_info_items below are written by hand: line_start, parameters_size, names, opcodes.
TEST(Read, read_whenDebugInfoNamesAParameter_returnsTheName)
{
    Code code =
        fibonacci_classify_with_debug_info({1, 1, kStringNegativeP1, raw::DBG_END_SEQUENCE});

    EXPECT_EQ(code.parameter_names, (std::vector<std::optional<std::string>>{"negative"}));
}

TEST(Read, read_whenDebugInfoStartsALocal_returnsItsRegisterNameAndType)
{
    Code code = fibonacci_classify_with_debug_info(
        {1, 0, raw::DBG_START_LOCAL, 0, kStringSmallP1, kTypeLongP1, raw::DBG_END_SEQUENCE});

    ASSERT_FALSE(code.items.empty());
    EXPECT_EQ(code.items[0], (Item{LocalStart{0, LocalVariable{"small", "J", std::nullopt}}}));
}

TEST(Read, read_whenALocalHasNoNameAndNoType_returnsNeither)
{
    Code code = fibonacci_classify_with_debug_info(
        {1, 0, raw::DBG_START_LOCAL, 3, 0, 0, raw::DBG_END_SEQUENCE});

    ASSERT_FALSE(code.items.empty());
    EXPECT_EQ(code.items[0],
              (Item{LocalStart{3, LocalVariable{std::nullopt, std::nullopt, std::nullopt}}}));
}

TEST(Read, read_whenDebugInfoStartsAnExtendedLocal_returnsItsSignature)
{
    Code code =
        fibonacci_classify_with_debug_info({1, 0, raw::DBG_START_LOCAL_EXTENDED, 1, kStringSmallP1,
                                            kTypeLongP1, kStringLjP1, raw::DBG_END_SEQUENCE});

    ASSERT_FALSE(code.items.empty());
    EXPECT_EQ(code.items[0], (Item{LocalStart{1, LocalVariable{"small", "J", "LJ"}}}));
}

TEST(Read, read_whenDebugInfoEndsALocal_returnsLocalEndWithItsRegister)
{
    Code code =
        fibonacci_classify_with_debug_info({1, 0, raw::DBG_END_LOCAL, 2, raw::DBG_END_SEQUENCE});

    ASSERT_FALSE(code.items.empty());
    EXPECT_EQ(code.items[0], Item{LocalEnd{2}});
}

TEST(Read, read_whenDebugInfoRestartsALocal_returnsLocalRestartWithItsRegister)
{
    Code code = fibonacci_classify_with_debug_info(
        {1, 0, raw::DBG_RESTART_LOCAL, 2, raw::DBG_END_SEQUENCE});

    ASSERT_FALSE(code.items.empty());
    EXPECT_EQ(code.items[0], Item{LocalRestart{2}});
}

TEST(Read, read_whenDebugInfoMarksThePrologueEnd_returnsPrologueEnd)
{
    Code code = fibonacci_classify_with_debug_info(
        {1, 0, raw::DBG_SET_PROLOGUE_END, raw::DBG_END_SEQUENCE});

    ASSERT_FALSE(code.items.empty());
    EXPECT_EQ(code.items[0], Item{PrologueEnd{}});
}

TEST(Read, read_whenDebugInfoMarksTheEpilogueBegin_returnsEpilogueBegin)
{
    Code code = fibonacci_classify_with_debug_info(
        {1, 0, raw::DBG_SET_EPILOGUE_BEGIN, raw::DBG_END_SEQUENCE});

    ASSERT_FALSE(code.items.empty());
    EXPECT_EQ(code.items[0], Item{EpilogueBegin{}});
}

TEST(Read, read_whenDebugInfoSetsTheSourceFile_returnsItsName)
{
    Code code = fibonacci_classify_with_debug_info(
        {1, 0, raw::DBG_SET_FILE, kStringFileNameP1, raw::DBG_END_SEQUENCE});

    ASSERT_FALSE(code.items.empty());
    EXPECT_EQ(code.items[0], Item{SetSourceFile{"Fibonacci.java"}});
}

TEST(Read, read_whenDebugInfoSetsAnUnknownSourceFile_returnsNoName)
{
    Code code =
        fibonacci_classify_with_debug_info({1, 0, raw::DBG_SET_FILE, 0, raw::DBG_END_SEQUENCE});

    ASSERT_FALSE(code.items.empty());
    EXPECT_EQ(code.items[0], Item{SetSourceFile{std::nullopt}});
}

TEST(Read, read_whenASpecialOpcodeAddsNothing_returnsTheStartLineAtTheFirstInstruction)
{
    Code code = fibonacci_classify_with_debug_info({7, 0, 0x0E, raw::DBG_END_SEQUENCE});

    EXPECT_EQ(lines_with_insns_before(code),
              (std::vector<std::pair<uint32_t, std::size_t>>{{7, 0}}));
}

TEST(Read, read_whenASpecialOpcodeAdvancesLineAndAddress_returnsTheLineAtTheLaterInstruction)
{
    // 0x0a + 2 * 15 + (4 + 3): two code units forward, three lines down.
    Code code = fibonacci_classify_with_debug_info({7, 0, 0x2F, raw::DBG_END_SEQUENCE});

    EXPECT_EQ(lines_with_insns_before(code),
              (std::vector<std::pair<uint32_t, std::size_t>>{{10, 1}}));
}

TEST(Read, read_whenDebugInfoAdvancesTheLine_addsTheSignedDifference)
{
    Code code = fibonacci_classify_with_debug_info(
        {7, 0, raw::DBG_ADVANCE_LINE, 0x7E, 0x0E, raw::DBG_END_SEQUENCE});

    EXPECT_EQ(lines_with_insns_before(code),
              (std::vector<std::pair<uint32_t, std::size_t>>{{5, 0}}));
}

TEST(Read, read_whenDebugInfoAdvancesTheAddress_placesTheNextEventAtThatInstruction)
{
    Code code = fibonacci_classify_with_debug_info(
        {7, 0, raw::DBG_ADVANCE_PC, 4, 0x0E, raw::DBG_END_SEQUENCE});

    EXPECT_EQ(lines_with_insns_before(code),
              (std::vector<std::pair<uint32_t, std::size_t>>{{7, 2}}));
}

TEST(Read, read_whenADebugPositionIsAtTheEndOfTheCode_keepsItAfterTheLastInstruction)
{
    Code code = fibonacci_classify_with_debug_info(
        {7, 0, raw::DBG_ADVANCE_PC, 37, 0x0E, raw::DBG_END_SEQUENCE});

    ASSERT_FALSE(code.items.empty());
    EXPECT_EQ(code.items.back(), Item{LineNumber{7}});
}

TEST(Read, read_whenADebugPositionIsPastTheEndOfTheCode_dropsIt)
{
    Code code = fibonacci_classify_with_debug_info(
        {7, 0, raw::DBG_ADVANCE_PC, 38, 0x0E, raw::DBG_END_SEQUENCE});

    EXPECT_EQ(count_of<LineNumber>(code), 0u);
}

TEST(Read, read_whenALabelAndADebugEventShareAPosition_placesTheLabelFirst)
{
    Code code = fibonacci_classify_with_debug_info(
        {7, 0, raw::DBG_ADVANCE_PC, 9, 0x0E, raw::DBG_END_SEQUENCE});

    // classify's first branch target is at code offset 9, after five instructions.
    ASSERT_GT(code.items.size(), 7u);
    EXPECT_EQ(code.items[5], Item{Label{0}});
    EXPECT_EQ(code.items[6], Item{LineNumber{7}});
    EXPECT_TRUE(std::holds_alternative<Insn>(code.items[7]));
}

TEST(Read, read_whenDebugInfoNamesARegisterAboveV65535_returnsMalformed)
{
    auto bytes = load_fixture("fibonacci.dex");
    set_debug_info(bytes, kFibonacciClassifyCode,
                   {1, 0, raw::DBG_END_LOCAL, 0x80, 0x80, 0x04, raw::DBG_END_SEQUENCE});

    Error error = read_error(bytes);

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_EQ(error.message,
              "LFibonacci;->classify(J)Ljava/lang/String;: debug info names register 65536");
}

TEST(Read, read_whenDebugInfoHasNoEndSequence_returnsMalformed)
{
    auto bytes = load_fixture("fibonacci.dex");
    set_debug_info(bytes, kFibonacciClassifyCode, {1, 0, raw::DBG_ADVANCE_PC, 2});

    Error error = read_error(bytes);

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
}

TEST(Read, read_whenDebugInfoIsBrokenButNotAskedFor_succeeds)
{
    auto bytes = load_fixture("fibonacci.dex");
    set_debug_info(bytes, kFibonacciClassifyCode, {1, 0, raw::DBG_ADVANCE_PC, 2});

    auto dex = read(bytes, kNoDebugInfo);

    EXPECT_TRUE(dex.has_value());
}

TEST(Read, read_whenClassIsAnnotated_returnsTheAnnotationWithItsElementsInFileOrder)
{
    Dex dex = read_fixture("annotated.dex");

    const std::vector<AnnotationItem> expected{AnnotationItem{
        AnnotationVisibility::Runtime,
        EncodedAnnotation{"LMarker;",
                          {
                              {"level", Value{Value::Int{3}}},
                              {"name", Value{Value::String{"cls"}}},
                              {"tags", Value{Value::Array{{Value{Value::String{"a"}},
                                                           Value{Value::String{"b"}}}}}},
                          }},
    }};
    EXPECT_EQ(class_of(dex, "LAnnotated;").annotations, expected);
}

TEST(Read, read_whenFieldIsAnnotated_returnsTheAnnotationOnThatField)
{
    Dex dex = read_fixture("annotated.dex");

    const std::vector<AnnotationItem> expected{AnnotationItem{
        AnnotationVisibility::Runtime,
        EncodedAnnotation{"LMarker;", {{"name", Value{Value::String{"fld"}}}}},
    }};
    EXPECT_EQ(field_of(dex, "LAnnotated;", "MAGIC", "I").annotations, expected);
}

TEST(Read, read_whenFieldIsNotAnnotated_returnsNoAnnotations)
{
    Dex dex = read_fixture("annotated.dex");

    EXPECT_TRUE(field_of(dex, "LAnnotated;", "BIG", "J").annotations.empty());
}

TEST(Read, read_whenMethodIsAnnotated_returnsTheAnnotationWithItsTypeValue)
{
    Dex dex = read_fixture("annotated.dex");

    const std::vector<AnnotationItem> expected{AnnotationItem{
        AnnotationVisibility::Runtime,
        EncodedAnnotation{"LMarker;",
                          {
                              {"name", Value{Value::String{"mth"}}},
                              {"target", Value{Value::Type{"Ljava/lang/String;"}}},
                          }},
    }};
    EXPECT_EQ(method_of(dex, "LAnnotated;", "greet", "()Ljava/lang/String;").annotations, expected);
}

TEST(Read, read_whenAnAnnotationHasNoElements_returnsAnEmptyElementList)
{
    Dex dex = read_fixture("annotated.dex");

    const std::vector<AnnotationItem> expected{AnnotationItem{
        AnnotationVisibility::Runtime,
        EncodedAnnotation{"Ljava/lang/Deprecated;", {}},
    }};
    EXPECT_EQ(method_of(dex, "LAnnotated;", "old", "()V").annotations, expected);
}

TEST(Read, read_whenMethodIsNotAnnotated_returnsNoAnnotations)
{
    Dex dex = read_fixture("annotated.dex");

    const MethodDef &init = method_of(dex, "LAnnotated;", "<init>", "()V");
    EXPECT_TRUE(init.annotations.empty());
    EXPECT_TRUE(init.parameter_annotations.empty());
}

TEST(Read, read_whenAnAnnotationValueIsAnAnnotation_returnsTheNestedAnnotation)
{
    Dex dex = read_fixture("annotated.dex");

    const std::vector<AnnotationItem> &annotations = class_of(dex, "LMarker;").annotations;

    const AnnotationItem expected{
        AnnotationVisibility::System,
        EncodedAnnotation{"Ldalvik/annotation/AnnotationDefault;",
                          {{"value", Value{Shared<EncodedAnnotation>(EncodedAnnotation{
                                         "LMarker;",
                                         {
                                             {"level", Value{Value::Int{1}}},
                                             {"tags", Value{Value::Array{}}},
                                             {"target", Value{Value::Type{"Ljava/lang/Object;"}}},
                                         }})}}}},
    };
    ASSERT_EQ(annotations.size(), 3u);
    EXPECT_EQ(annotations[0], expected);
}

TEST(Read, read_whenAnAnnotationValueIsAnEnumConstant_returnsItsField)
{
    Dex dex = read_fixture("annotated.dex");

    const std::vector<AnnotationItem> &annotations = class_of(dex, "LMarker;").annotations;

    const AnnotationItem expected{
        AnnotationVisibility::Runtime,
        EncodedAnnotation{"Ljava/lang/annotation/Retention;",
                          {{"value", Value{Value::Enum{FieldId{
                                         "Ljava/lang/annotation/RetentionPolicy;", "RUNTIME",
                                         "Ljava/lang/annotation/RetentionPolicy;"}}}}}},
    };
    ASSERT_EQ(annotations.size(), 3u);
    EXPECT_EQ(annotations[1], expected);
}

TEST(Read, read_whenAnAnnotationValueIsAnArrayOfEnumConstants_returnsThemInOrder)
{
    Dex dex = read_fixture("annotated.dex");

    const std::vector<AnnotationItem> &annotations = class_of(dex, "LMarker;").annotations;

    auto element_type = [](const char *name) {
        return Value{Value::Enum{FieldId{"Ljava/lang/annotation/ElementType;", name,
                                         "Ljava/lang/annotation/ElementType;"}}};
    };
    const AnnotationItem expected{
        AnnotationVisibility::Runtime,
        EncodedAnnotation{
            "Ljava/lang/annotation/Target;",
            {{"value", Value{Value::Array{{element_type("TYPE"), element_type("METHOD"),
                                           element_type("FIELD")}}}}}},
    };
    ASSERT_EQ(annotations.size(), 3u);
    EXPECT_EQ(annotations[2], expected);
}

TEST(Read, read_whenAMethodHasASystemAnnotation_returnsTheSystemVisibility)
{
    Dex dex = read_fixture("annotated.dex");

    const std::vector<AnnotationItem> expected{AnnotationItem{
        AnnotationVisibility::System,
        EncodedAnnotation{"Ldalvik/annotation/Signature;",
                          {{"value", Value{Value::Array{{Value{Value::String{"()"}},
                                                         Value{Value::String{"Ljava/lang/Class<"}},
                                                         Value{Value::String{"*>;"}}}}}}}},
    }};
    EXPECT_EQ(method_of(dex, "LMarker;", "target", "()Ljava/lang/Class;").annotations, expected);
}

TEST(Read, read_whenAnAnnotationHasAnUnknownVisibility_returnsMalformed)
{
    auto bytes = load_fixture("annotated.dex");
    std::size_t directory = get_u32(bytes, class_def_off(bytes, 0) + kAnnotationsOff);
    std::size_t set = get_u32(bytes, directory);
    std::size_t item = get_u32(bytes, set + 4);
    ASSERT_EQ(bytes[item], 0x01);
    bytes[item] = 0x03;

    Error error = read_error(bytes);

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_EQ(error.message, "LAnnotated;: bad annotation visibility 3");
}

TEST(Read, read_whenAnAnnotationItemIsOutsideTheFile_returnsMalformed)
{
    auto bytes = load_fixture("annotated.dex");
    std::size_t directory = get_u32(bytes, class_def_off(bytes, 0) + kAnnotationsOff);
    std::size_t set = get_u32(bytes, directory);
    put_u32(bytes, set + 4, static_cast<uint32_t>(bytes.size()));

    Error error = read_error(bytes);

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_EQ(error.message, "LAnnotated;: annotation item is past the end of the file");
}

TEST(Read, read_whenTheAnnotationsDirectoryNamesAFieldTheClassDoesNotDefine_returnsMalformed)
{
    auto bytes = load_fixture("annotated.dex");
    std::size_t directory = get_u32(bytes, class_def_off(bytes, 0) + kAnnotationsOff);
    constexpr std::size_t kFirstFieldIdx = 16;
    ASSERT_EQ(get_u32(bytes, directory + 4), 1u);
    put_u32(bytes, directory + kFirstFieldIdx, 0xFFFF);

    Error error = read_error(bytes);

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_EQ(error.message,
              "LAnnotated;: the annotations directory names a member the class does not define");
}

TEST(Read, read_whenClassDataIsOutsideTheFile_returnsMalformed)
{
    auto bytes = load_fixture("fibonacci.dex");
    put_u32(bytes, class_def_off(bytes, 0) + kClassDataOff, static_cast<uint32_t>(bytes.size()));

    Error error = read_error(bytes);

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_TRUE(error.message.starts_with("LFibonacci;: ")) << error.message;
}

TEST(Read, read_whenClassDataListsAFieldOfAnotherClass_returnsMalformed)
{
    auto bytes = load_fixture("fibonacci.dex");
    // Field 0 is Fibonacci.sumFib; type 4 is Ljava/lang/String;.
    std::size_t field_class_idx = get_u32(bytes, kFieldIdsOff);
    ASSERT_EQ(bytes[field_class_idx], 2);
    bytes[field_class_idx] = 4;

    Error error = read_error(bytes);

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_EQ(error.message, "LFibonacci;: field Ljava/lang/String;.sumFib is listed in the class "
                             "data of LFibonacci;");
}

TEST(Read, read_whenClassDataListsAMethodOfAnotherClass_returnsMalformed)
{
    auto bytes = load_fixture("fibonacci.dex");
    // Method 0 is Fibonacci.<init>; type 4 is Ljava/lang/String;.
    std::size_t method_class_idx = get_u32(bytes, kMethodIdsOff);
    ASSERT_EQ(bytes[method_class_idx], 2);
    bytes[method_class_idx] = 4;

    Error error = read_error(bytes);

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_EQ(error.message, "LFibonacci;: method Ljava/lang/String;-><init>()V is listed in the "
                             "class data of LFibonacci;");
}

TEST(Read, read_whenBufferIsEmpty_returnsMalformed)
{
    Error error = read_error({});

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_EQ(error.message, "not a DEX file (bad magic)");
}

TEST(Read, read_whenMagicIsWrong_returnsMalformed)
{
    const std::vector<uint8_t> junk = {'n', 'o', 't', ' ', 'd', 'e', 'x', 0};

    Error error = read_error(junk);

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_EQ(error.message, "not a DEX file (bad magic)");
}

TEST(Read, read_whenVersionIsNotThreeDigits_returnsMalformed)
{
    auto bytes = load_fixture("fibonacci.dex");
    bytes[5] = 'a';

    Error error = read_error(bytes);

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_EQ(error.message, "not a DEX file (bad magic)");
}

TEST(Read, read_whenMagicDoesNotEndWithANul_returnsMalformed)
{
    auto bytes = load_fixture("fibonacci.dex");
    bytes[7] = '5';

    Error error = read_error(bytes);

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_EQ(error.message, "not a DEX file (bad magic)");
}

TEST(Read, read_whenVersionIsUnknown_returnsMalformed)
{
    auto bytes = load_fixture("fibonacci.dex");
    bytes[6] = '6';

    Error error = read_error(bytes);

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
    EXPECT_EQ(error.message, "unknown DEX version 036");
}

TEST(Read, read_whenVersionIs41_returnsUnsupported)
{
    auto bytes = load_fixture("fibonacci.dex");
    bytes[5] = '4';
    bytes[6] = '1';

    Error error = read_error(bytes);

    EXPECT_EQ(error.kind, Error::Kind::Unsupported);
    EXPECT_EQ(error.message, "DEX version 041 (containers) is not supported");
}

TEST(Read, read_whenVersionIs40_readsTheFile)
{
    auto bytes = load_fixture("fibonacci.dex");
    bytes[5] = '4';
    bytes[6] = '0';

    Dex dex = read_or_throw(bytes);

    EXPECT_EQ(dex.version, 40u);
}

TEST(Read, read_whenEndianTagIsBigEndian_returnsUnsupported)
{
    auto bytes = load_fixture("fibonacci.dex");
    put_u32(bytes, kEndianTagOff, 0x78563412);

    Error error = read_error(bytes);

    EXPECT_EQ(error.kind, Error::Kind::Unsupported);
    EXPECT_EQ(error.message, "big-endian DEX files are not supported");
}

TEST(Read, read_whenBufferHoldsOnlyTheMagic_returnsMalformed)
{
    auto bytes = load_fixture("fibonacci.dex");
    bytes.resize(8);

    Error error = read_error(bytes);

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
}

TEST(Read, read_whenFileIsCutAfterTheHeader_returnsMalformed)
{
    auto bytes = load_fixture("fibonacci.dex");
    bytes.resize(0x70);

    Error error = read_error(bytes);

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
}

TEST(Read, read_whenFileIsCutInHalf_returnsMalformed)
{
    auto bytes = load_fixture("fibonacci.dex");
    bytes.resize(bytes.size() / 2);

    Error error = read_error(bytes);

    EXPECT_EQ(error.kind, Error::Kind::Malformed);
}

TEST(Read, read_whenReadFails_returnsNoProblems)
{
    Error error = read_error({});

    EXPECT_TRUE(error.problems.empty());
}

class ReadFixture : public ::testing::TestWithParam<std::string>
{
};

TEST_P(ReadFixture, read_whenFileIsWellFormed_succeeds)
{
    auto dex = read(load_fixture(GetParam()));

    ASSERT_TRUE(dex.has_value()) << dex.error().message;
    EXPECT_FALSE(dex->classes.empty());
}

TEST_P(ReadFixture, read_whenCalledTwice_returnsEqualModels)
{
    auto bytes = load_fixture(GetParam());

    auto first = read(bytes);
    auto second = read(bytes);

    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    EXPECT_TRUE(*first == *second);
}

INSTANTIATE_TEST_SUITE_P(AllDexFiles, ReadFixture,
                         ::testing::Values("annotated.dex", "casts.dex", "classes.dex",
                                           "fibonacci.dex", "inherit.dex", "multistring.dex",
                                           "polymorphic.dex", "shapes.dex", "trycatch.dex"),
                         [](const ::testing::TestParamInfo<ReadFixture::ParamType> &info) {
                             return info.param.substr(0, info.param.rfind('.'));
                         });

TEST(Read, readFile_whenPathIsAFixture_returnsTheSameModelAsRead)
{
    auto from_file = read_file(fixture_path("shapes.dex"));

    ASSERT_TRUE(from_file.has_value()) << from_file.error().message;
    EXPECT_TRUE(*from_file == read_fixture("shapes.dex"));
}

TEST(Read, readFile_whenOptionsTurnDebugInfoOff_readsWithoutDebugInfo)
{
    auto from_file = read_file(fixture_path("shapes.dex"), kNoDebugInfo);

    ASSERT_TRUE(from_file.has_value()) << from_file.error().message;
    EXPECT_TRUE(*from_file == read_fixture("shapes.dex", kNoDebugInfo));
    EXPECT_FALSE(*from_file == read_fixture("shapes.dex"));
}

TEST(Read, readFile_whenPathDoesNotExist_returnsAnIoError)
{
    auto file = read_file("does/not/exist.dex");

    ASSERT_FALSE(file.has_value());
    EXPECT_EQ(file.error().kind, Error::Kind::Io);
    EXPECT_EQ(file.error().message, "cannot open does/not/exist.dex");
}

TEST(Read, readFile_whenPathIsADirectory_returnsAnIoError)
{
    auto file = read_file(fixture_path(""));

    ASSERT_FALSE(file.has_value());
    EXPECT_EQ(file.error().kind, Error::Kind::Io);
}

TEST(Read, readFile_whenFileIsNotADexFile_returnsMalformed)
{
    auto file = read_file(__FILE__);

    ASSERT_FALSE(file.has_value());
    EXPECT_EQ(file.error().kind, Error::Kind::Malformed);
    EXPECT_EQ(file.error().message, "not a DEX file (bad magic)");
}

} // namespace
} // namespace dexsplit::model
