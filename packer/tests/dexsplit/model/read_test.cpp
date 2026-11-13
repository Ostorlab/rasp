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

} // namespace
} // namespace dexsplit::model
