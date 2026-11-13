// Tests for write(), write_file() and pool_stats(), on models built by hand and on the fixtures.

#include "model/io.hpp"

#include <algorithm>
#include <bit>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>
#include <gtest/gtest.h>
#include <ios>
#include <iterator>
#include <limits>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

#include "common/access_flags.hpp"
#include "common/annotation_visibility.hpp"
#include "common/ids.hpp"
#include "model/model.hpp"
#include "model/types.hpp"
#include "raw/constants.hpp"
#include "raw/parser.hpp"
#include "raw/types.hpp"
#include "support/dex_check.hpp"
#include "support/fixtures.hpp"
#include "support/models.hpp"

namespace dexsplit::model {
namespace {

using support::call_site;
using support::check_dex;
using support::load_fixture;

using Bytes = std::vector<uint8_t>;
using Strings = std::vector<std::string>;

const Strings kFixtures{"annotated.dex",   "casts.dex",   "classes.dex",
                        "fibonacci.dex",   "inherit.dex", "multistring.dex",
                        "polymorphic.dex", "shapes.dex",  "trycatch.dex"};

const WriteOptions kNoDebugInfo{.debug_info = false};

// U+1F600 as a surrogate pair in two 3-byte sequences, and as one 4-byte sequence.
const std::string kSplitPair = "\xED\xA0\xBD\xED\xB8\x80";
const std::string kJoinedPair = "\xF0\x9F\x98\x80";
const std::string kUnpairedSurrogate = "a\xED\xA0\x80";

constexpr std::size_t kHeaderSize = 0x70;

Dex valid()
{
    Dex dex;
    ClassDef &c = dex.classes.emplace_back();
    c.type = "LT;";
    c.access = AccessFlags::Public;
    c.superclass = "Ljava/lang/Object;";
    MethodDef &m = c.methods.emplace_back();
    m.name = "m";
    m.proto = "()V";
    m.access = AccessFlags::Public | AccessFlags::Static;
    Code &code = m.code.emplace();
    code.registers = 4;
    code.items = {Insn{ReturnVoid{}}};
    return dex;
}

ClassDef &cls(Dex &dex) { return dex.classes[0]; }

MethodDef &method(Dex &dex) { return dex.classes[0].methods[0]; }

Code &code(Dex &dex) { return *dex.classes[0].methods[0].code; }

Dex with_code(std::vector<Item> items, Reg registers = 4)
{
    Dex dex = valid();
    code(dex).registers = registers;
    code(dex).items = std::move(items);
    return dex;
}

ClassDef class_def(std::string type, std::string superclass = "Ljava/lang/Object;")
{
    ClassDef c;
    c.type = std::move(type);
    c.superclass = std::move(superclass);
    return c;
}

FieldDef static_field(std::string name, std::string type, std::optional<Value> value = {})
{
    FieldDef f;
    f.name = std::move(name);
    f.type = std::move(type);
    f.access = AccessFlags::Static;
    f.initial_value = std::move(value);
    return f;
}

AnnotationItem annotation(std::string type, std::vector<NamedValue> elements = {})
{
    AnnotationItem a;
    a.annotation.type = std::move(type);
    a.annotation.elements = std::move(elements);
    return a;
}

Dex hello_world()
{
    Dex dex;
    ClassDef &c = dex.classes.emplace_back();
    c.type = "LHello;";
    c.access = AccessFlags::Public;
    c.superclass = "Ljava/lang/Object;";
    c.source_file = "Hello.java";
    MethodDef &main = c.methods.emplace_back();
    main.name = "main";
    main.proto = "([Ljava/lang/String;)V";
    main.access = AccessFlags::Public | AccessFlags::Static;
    Code &body = main.code.emplace();
    body.registers = 3;
    body.items = {
        Insn{StaticGet{ValueKind::Object, 0,
                       FieldId{"Ljava/lang/System;", "out", "Ljava/io/PrintStream;"}}},
        Insn{ConstString{1, "Hello"}},
        Insn{Invoke{Invoke::Kind::Virtual,
                    {0, 1},
                    MethodId{"Ljava/io/PrintStream;", "println", "(Ljava/lang/String;)V"}}},
        Insn{ReturnVoid{}},
    };
    return dex;
}

// Fields and annotation elements are in the order write() puts them in, so it reads back equal.
Dex every_value()
{
    Dex dex;
    dex.version = 38;
    ClassDef &c = dex.classes.emplace_back(class_def("LV;"));
    auto field = [&](std::string name, std::string type, Value value) {
        c.fields.push_back(static_field(std::move(name), std::move(type), std::move(value)));
        c.fields.back().access = AccessFlags::Static | AccessFlags::Final;
    };
    field("b", "B", Value{Value::Byte{-128}});
    field("c", "C", Value{Value::Char{u'\xe9'}});
    field("cls", "Ljava/lang/Class;", Value{Value::Type{"[I"}});
    field("d", "D", Value{Value::Double{1.5}});
    field("f", "F", Value{Value::Float{-0.0f}});
    field("i", "I", Value{Value::Int{std::numeric_limits<int32_t>::min()}});
    field("j", "J", Value{Value::Long{0x123456789ABCDEF0}});
    field("nan", "F", Value{Value::Float{std::bit_cast<float>(0x7F800001u)}});
    field("nul", "Ljava/lang/Object;", Value{Value::Null{}});
    field("s", "S", Value{Value::Short{-300}});
    field("str", "Ljava/lang/String;", Value{Value::String{"text"}});
    field("z", "Z", Value{Value::Boolean{true}});

    const EncodedAnnotation inner{"LInner;", {NamedValue{"value", Value{Value::Int{1}}}}};
    c.annotations.push_back(annotation(
        "LAll;",
        {
            {"array", Value{Value::Array{{Value{Value::Int{1}}, Value{Value::String{"a"}}}}}},
            {"charValue", Value{Value::Char{u'a'}}},
            {"enumValue", Value{Value::Enum{FieldId{"LE;", "ONE", "LE;"}}}},
            {"fieldValue", Value{Value::Field{FieldId{"LV;", "i", "I"}}}},
            {"handle",
             Value{MethodHandle{MethodHandleKind::InvokeStatic, MethodId{"LV;", "m", "()V"}}}},
            {"methodType", Value{Value::MethodType{"(I)V"}}},
            {"methodValue", Value{Value::Method{MethodId{"LV;", "m", "()V"}}}},
            {"nested", Value{Shared<EncodedAnnotation>(inner)}},
        }));
    return dex;
}

// The call site has the share key read() gives the first one of a file, so it reads back equal.
Dex every_section()
{
    Dex dex =
        with_code({LineNumber{1}, Insn{InvokeCustom{{}, call_site(1)}}, Insn{ReturnVoid{}}}, 1);
    dex.version = 38;
    cls(dex).interfaces = {"LI;"};
    cls(dex).annotations = {annotation("LA;")};
    cls(dex).fields = {static_field("f", "I", Value{Value::Int{5}})};
    cls(dex).fields[0].annotations = {annotation("LA;")};
    method(dex).proto = "(I)V";
    method(dex).annotations = {annotation("LA;")};
    method(dex).parameter_annotations = {{annotation("LA;")}};
    return dex;
}

// Four invoke-custom: two through one shared call site, two with equal unshared call sites.
Dex call_sites()
{
    const Shared<CallSite> shared = call_site(7);
    Dex dex = with_code({Insn{InvokeCustom{{}, shared}}, Insn{InvokeCustom{{}, shared}},
                         Insn{InvokeCustom{{}, call_site(0)}}, Insn{InvokeCustom{{}, call_site(0)}},
                         Insn{ReturnVoid{}}});
    dex.version = 38;
    return dex;
}

// An if-eqz 40000 units before its target, with a goto 200 units before its own in between.
Dex far_branch()
{
    Dex dex = valid();
    std::vector<Item> &items = code(dex).items;
    items = {Insn{IfZero{Condition::Eq, 0, Label{1}}}, Insn{Goto{Label{0}}}};
    items.insert(items.end(), 200, Item{Insn{Nop{}}});
    items.push_back(Label{0});
    items.insert(items.end(), 40000, Item{Insn{Nop{}}});
    items.push_back(Label{1});
    items.push_back(Insn{ReturnVoid{}});
    return dex;
}

template <class Make> Dex with_many_insns(uint32_t version, std::size_t count, Make make)
{
    Dex dex = valid();
    dex.version = version;
    Code &body = code(dex);
    body.items.clear();
    for (std::size_t i = 0; i < count; ++i)
        body.items.push_back(Insn{make(i)});
    body.items.push_back(Insn{ReturnVoid{}});
    return dex;
}

std::string describe(const Error &error)
{
    std::string text = error.message;
    for (const Problem &p : error.problems)
        text += "\n  " + p.where + ": " + p.message;
    return text;
}

Bytes written(const Dex &dex, const WriteOptions &options = {})
{
    auto bytes = write(dex, options);
    if (!bytes.has_value())
        throw std::runtime_error("write() failed: " + describe(bytes.error()));
    for (const std::string &problem : check_dex(*bytes))
        throw std::runtime_error("write() broke the format: " + problem);
    return std::move(*bytes);
}

Error write_error(const Dex &dex)
{
    auto bytes = write(dex);
    if (bytes.has_value())
        throw std::runtime_error("write() accepted the model");
    return bytes.error();
}

Dex reread(std::span<const uint8_t> bytes)
{
    auto dex = read(bytes);
    if (!dex.has_value())
        throw std::runtime_error("read() failed: " + dex.error().message);
    return std::move(*dex);
}

Dex read_fixture(std::string_view name) { return reread(load_fixture(name)); }

raw::DexFile parsed(std::span<const uint8_t> bytes)
{
    auto file = raw::parser::parse_buffer(bytes);
    if (!file.has_value())
        throw std::runtime_error("the raw parser failed: " + file.error().message);
    return std::move(*file);
}

raw::Header header_of(const Dex &dex) { return parsed(written(dex)).header(); }

const raw::ClassDefItem &class_def_of(const raw::DexFile &file, std::string_view type)
{
    for (const raw::ClassDefItem &cd : file.class_defs())
        if (file.strings()[file.type_ids()[cd.class_idx]] == type)
            return cd;
    throw std::runtime_error("no class " + std::string(type));
}

raw::ClassDataItem class_data_of(std::span<const uint8_t> bytes, std::string_view type)
{
    raw::DexFile file = parsed(bytes);
    return raw::parser::parse_class_data(bytes, class_def_of(file, type).class_data_off).value();
}

raw::CodeItem written_code(std::span<const uint8_t> bytes, std::string_view type,
                           std::string_view name)
{
    raw::DexFile file = parsed(bytes);
    raw::ClassDataItem data = class_data_of(bytes, type);
    for (const auto *list : {&data.direct_methods, &data.virtual_methods})
        for (const raw::EncodedMethod &em : *list)
            if (file.strings()[file.method_ids()[em.method_idx].name_idx] == name)
                return raw::parser::parse_code_item(bytes, em.code_off).value();
    throw std::runtime_error("no method " + std::string(name));
}

uint32_t map_count(std::span<const uint8_t> bytes, uint16_t type)
{
    raw::DexFile file = parsed(bytes);
    for (const raw::MapItem &item : file.map_list().items)
        if (item.type == type)
            return item.size;
    return 0;
}

std::vector<uint16_t> map_types(std::span<const uint8_t> bytes)
{
    raw::DexFile file = parsed(bytes);
    std::vector<uint16_t> types;
    for (const raw::MapItem &item : file.map_list().items)
        types.push_back(item.type);
    return types;
}

Strings class_types(const Dex &dex)
{
    Strings types;
    for (const ClassDef &c : dex.classes)
        types.push_back(c.type);
    return types;
}

std::string string_constant(const Dex &dex, std::size_t item)
{
    return std::get<ConstString>(std::get<Insn>(dex.classes[0].methods[0].code->items[item]))
        .value.get();
}

std::string temp_path(std::string_view name)
{
    return (std::filesystem::path(testing::TempDir()) / name).string();
}

Bytes file_bytes(const std::string &path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open())
        throw std::runtime_error("cannot open " + path);
    return Bytes(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
}

bool contains(std::string_view text, std::string_view part)
{
    return text.find(part) != std::string_view::npos;
}

bool operator==(const PoolStats &a, const PoolStats &b)
{
    return a.strings == b.strings && a.types == b.types && a.protos == b.protos &&
           a.fields == b.fields && a.methods == b.methods && a.method_handles == b.method_handles &&
           a.call_sites == b.call_sites;
}

PoolStats table_sizes(std::span<const uint8_t> bytes)
{
    raw::DexFile file = parsed(bytes);
    return PoolStats{file.string_ids().size(),   file.type_ids().size(),
                     file.proto_ids().size(),    file.field_ids().size(),
                     file.method_ids().size(),   file.method_handles().size(),
                     file.call_site_ids().size()};
}

TEST(Write, write_whenModelIsHelloWorld_readsBackEqual)
{
    Dex dex = hello_world();

    EXPECT_EQ(reread(written(dex)), dex);
}

TEST(Write, write_whenModelIsHelloWorld_writesTheFrameSizesOfMain)
{
    raw::CodeItem main = written_code(written(hello_world()), "LHello;", "main");

    EXPECT_EQ(main.registers_size, 3);
    EXPECT_EQ(main.ins_size, 1);
    EXPECT_EQ(main.outs_size, 2);
}

TEST(Write, write_whenValuesHaveEveryType_readsBackEqual)
{
    Dex dex = every_value();

    EXPECT_EQ(reread(written(dex)), dex);
}

TEST(Write, write_whenAFloatIsMinusZero_keepsItsSign)
{
    Dex back = reread(written(every_value()));

    const FieldDef *f = back.classes[0].find_field("f", "F");
    ASSERT_NE(f, nullptr);
    EXPECT_TRUE(std::signbit(std::get<Value::Float>(f->initial_value->data).value));
}

TEST(Write, write_whenAFloatIsASignalingNan_keepsItsBits)
{
    Dex back = reread(written(every_value()));

    const FieldDef *nan = back.classes[0].find_field("nan", "F");
    ASSERT_NE(nan, nullptr);
    EXPECT_EQ(std::bit_cast<uint32_t>(std::get<Value::Float>(nan->initial_value->data).value),
              0x7F800001u);
}

TEST(Write, write_whenFieldsAndAnnotationElementsAreInAnotherOrder_readsBackSorted)
{
    Dex dex = every_value();
    Dex reversed = dex;
    std::reverse(reversed.classes[0].fields.begin(), reversed.classes[0].fields.end());
    std::reverse(reversed.classes[0].annotations[0].annotation.elements.begin(),
                 reversed.classes[0].annotations[0].annotation.elements.end());

    EXPECT_EQ(reread(written(reversed)), dex);
}

TEST(Write, write_whenFieldsAndAnnotationElementsAreInAnotherOrder_writesTheSameBytes)
{
    Dex dex = every_value();
    Dex reversed = dex;
    std::reverse(reversed.classes[0].fields.begin(), reversed.classes[0].fields.end());
    std::reverse(reversed.classes[0].annotations[0].annotation.elements.begin(),
                 reversed.classes[0].annotations[0].annotation.elements.end());

    EXPECT_EQ(written(reversed), written(dex));
}

TEST(Write, write_whenAStringHasAnUnpairedSurrogate_readsItBackUnchanged)
{
    Dex dex = with_code({Insn{ConstString{0, kUnpairedSurrogate}}, Insn{ReturnVoid{}}});

    EXPECT_EQ(string_constant(reread(written(dex)), 0), kUnpairedSurrogate);
}

TEST(Write, write_whenAStringIsSpelledAsASplitPair_readsItBackJoined)
{
    Dex dex = with_code({Insn{ConstString{0, kSplitPair}}, Insn{ReturnVoid{}}});

    EXPECT_EQ(string_constant(reread(written(dex)), 0), kJoinedPair);
}

TEST(Write, write_whenBothSpellingsOfAPairAreUsed_writesOneString)
{
    Dex dex = with_code(
        {Insn{ConstString{0, kSplitPair}}, Insn{ConstString{0, kJoinedPair}}, Insn{ReturnVoid{}}});

    raw::DexFile file = parsed(written(dex));

    EXPECT_EQ(std::count(file.strings().begin(), file.strings().end(), kJoinedPair), 1);
    EXPECT_EQ(std::count(file.strings().begin(), file.strings().end(), kSplitPair), 0);
}

TEST(Write, write_whenAStringHasASupplementaryCharacter_storesItAsASurrogatePair)
{
    Dex dex = with_code({Insn{ConstString{0, kJoinedPair}}, Insn{ReturnVoid{}}});

    Bytes bytes = written(dex);
    raw::DexFile file = parsed(bytes);
    const auto it = std::find(file.strings().begin(), file.strings().end(), kJoinedPair);
    ASSERT_NE(it, file.strings().end());
    const uint32_t off = file.string_ids()[static_cast<std::size_t>(it - file.strings().begin())];

    // utf16_size 2, the pair as two 3-byte sequences, then the terminator.
    EXPECT_EQ(Bytes(bytes.begin() + off, bytes.begin() + off + 8),
              (Bytes{0x02, 0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80, 0x00}));
}

TEST(Write, write_whenAStringHoldsANulCharacter_readsItBackUnchanged)
{
    const std::string text("a\0b", 3);
    Dex dex = with_code({Insn{ConstString{0, text}}, Insn{ReturnVoid{}}});

    EXPECT_EQ(string_constant(reread(written(dex)), 0), text);
}

TEST(Write, write_whenCallSitesShareAKey_writesThemAsOneCallSite)
{
    raw::DexFile file = parsed(written(call_sites()));

    EXPECT_EQ(file.call_site_ids().size(), 3u);
}

TEST(Write, write_whenAModelWithSharedCallSitesIsReadBack_keepsTheSharing)
{
    Dex back = reread(written(call_sites()));

    EXPECT_EQ(pool_stats(back).call_sites, 3u);
}

TEST(Write, write_whenCallSitesAreEqualButNotShared_writesAnEncodedArrayForEach)
{
    Bytes bytes = written(call_sites());

    EXPECT_EQ(map_count(bytes, raw::TYPE_ENCODED_ARRAY_ITEM), 3u);
}

TEST(Write, write_whenClassesAreListedBeforeTheirSupertypes_writesSupertypesFirst)
{
    Dex dex;
    dex.classes.push_back(class_def("LC;", "LB;"));
    dex.classes[0].interfaces = {"LI;"};
    dex.classes.push_back(class_def("LB;", "LA;"));
    dex.classes.push_back(class_def("LI;"));
    dex.classes[2].access = AccessFlags::Interface | AccessFlags::Abstract;
    dex.classes.push_back(class_def("LA;"));

    EXPECT_EQ(class_types(reread(written(dex))), (Strings{"LA;", "LB;", "LI;", "LC;"}));
}

TEST(Write, write_whenClassesAreUnrelated_keepsTheOrderOfTheModel)
{
    Dex dex;
    for (const char *type : {"LZ;", "LA;", "LM;"})
        dex.classes.push_back(class_def(type));

    EXPECT_EQ(class_types(reread(written(dex))), (Strings{"LZ;", "LA;", "LM;"}));
}

TEST(Write, write_whenAHierarchyIsThousandsOfClassesDeep_writesSupertypesFirst)
{
    constexpr int kDepth = 3000;
    Dex dex;
    for (int i = kDepth; i > 0; --i)
        dex.classes.push_back(class_def(std::format("LC{};", i), std::format("LC{};", i - 1)));
    dex.classes.push_back(class_def("LC0;"));

    Dex back = reread(written(dex));

    ASSERT_EQ(back.classes.size(), kDepth + 1u);
    EXPECT_EQ(back.classes.front().type, "LC0;");
    EXPECT_EQ(back.classes.back().type, std::format("LC{};", kDepth));
}

TEST(Write, write_whenInitHasNoConstructorFlag_writesItAsADirectMethod)
{
    Dex dex = valid();
    method(dex).name = "<init>";
    method(dex).access = AccessFlags::Public;

    raw::ClassDataItem data = class_data_of(written(dex), "LT;");

    EXPECT_EQ(data.direct_methods.size(), 1u);
    EXPECT_EQ(data.virtual_methods.size(), 0u);
}

TEST(Write, write_whenMethodsAreStaticPrivateOrVirtual_splitsThemIntoDirectAndVirtual)
{
    Dex dex = valid();
    MethodDef priv = method(dex);
    priv.name = "p";
    priv.access = AccessFlags::Private;
    MethodDef virt = method(dex);
    virt.name = "v";
    virt.access = AccessFlags::Public;
    cls(dex).methods.push_back(priv);
    cls(dex).methods.push_back(virt);

    raw::ClassDataItem data = class_data_of(written(dex), "LT;");

    EXPECT_EQ(data.direct_methods.size(), 2u);
    EXPECT_EQ(data.virtual_methods.size(), 1u);
}

} // namespace
} // namespace dexsplit::model
