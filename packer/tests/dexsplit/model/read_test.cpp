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

} // namespace
} // namespace dexsplit::model
