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

TEST(Write, write_whenFieldsAreStaticAndInstance_splitsThemIntoTwoLists)
{
    Dex dex = valid();
    FieldDef instance = static_field("i", "I");
    instance.access = AccessFlags::Private;
    cls(dex).fields = {static_field("s", "I"), instance, static_field("t", "J")};

    raw::ClassDataItem data = class_data_of(written(dex), "LT;");

    EXPECT_EQ(data.static_fields.size(), 2u);
    EXPECT_EQ(data.instance_fields.size(), 1u);
    EXPECT_EQ(data.instance_fields[0].access_flags, static_cast<uint32_t>(AccessFlags::Private));
}

TEST(Write, write_whenAMethodHasNoCode_writesAZeroCodeOffset)
{
    Dex dex = valid();
    cls(dex).access = AccessFlags::Public | AccessFlags::Abstract;
    method(dex).access = AccessFlags::Public | AccessFlags::Abstract;
    method(dex).code.reset();

    Bytes bytes = written(dex);
    raw::ClassDataItem data = class_data_of(bytes, "LT;");

    ASSERT_EQ(data.virtual_methods.size(), 1u);
    EXPECT_EQ(data.virtual_methods[0].code_off, 0u);
    EXPECT_EQ(map_count(bytes, raw::TYPE_CODE_ITEM), 0u);
}

TEST(Write, write_whenAStaticFieldBeforeASetOneHasNoValue_writesItsDefault)
{
    Dex dex;
    dex.classes.push_back(class_def("LS;"));
    dex.classes[0].fields = {static_field("a", "I"), static_field("b", "I", Value{Value::Int{5}}),
                             static_field("c", "I")};

    Dex back = reread(written(dex));

    EXPECT_EQ(back.classes[0].find_field("a", "I")->initial_value, Value{Value::Int{0}});
    EXPECT_EQ(back.classes[0].find_field("b", "I")->initial_value, Value{Value::Int{5}});
}

TEST(Write, write_whenTheLastStaticFieldsHaveNoValue_leavesThemOut)
{
    Dex dex;
    dex.classes.push_back(class_def("LS;"));
    dex.classes[0].fields = {static_field("a", "I"), static_field("b", "I", Value{Value::Int{5}}),
                             static_field("c", "I")};

    Dex back = reread(written(dex));

    EXPECT_FALSE(back.classes[0].find_field("c", "I")->initial_value.has_value());
}

TEST(Write, write_whenNoStaticFieldHasAValue_writesNoStaticValues)
{
    Dex dex;
    dex.classes.push_back(class_def("LS;"));
    dex.classes[0].fields = {static_field("a", "I"), static_field("b", "J")};

    Bytes bytes = written(dex);

    EXPECT_EQ(class_def_of(parsed(bytes), "LS;").static_values_off, 0u);
    EXPECT_EQ(map_count(bytes, raw::TYPE_ENCODED_ARRAY_ITEM), 0u);
}

TEST(Write, write_whenAGapIsAReferenceField_writesNull)
{
    Dex dex;
    dex.classes.push_back(class_def("LS;"));
    dex.classes[0].fields = {static_field("a", "Ljava/lang/String;"),
                             static_field("b", "I", Value{Value::Int{5}})};

    Dex back = reread(written(dex));

    EXPECT_EQ(back.classes[0].find_field("a", "Ljava/lang/String;")->initial_value,
              Value{Value::Null{}});
}

TEST(Write, write_whenTwoClassesHaveEqualStaticValues_sharesOneEncodedArray)
{
    Dex dex;
    for (const char *type : {"LA;", "LB;"}) {
        dex.classes.push_back(class_def(type));
        dex.classes.back().fields = {static_field("f", "I", Value{Value::Int{5}})};
    }

    Bytes bytes = written(dex);
    raw::DexFile file = parsed(bytes);

    EXPECT_EQ(map_count(bytes, raw::TYPE_ENCODED_ARRAY_ITEM), 1u);
    EXPECT_EQ(class_def_of(file, "LA;").static_values_off,
              class_def_of(file, "LB;").static_values_off);
}

TEST(Write, write_whenTheSameModelIsWrittenTwice_writesTheSameBytes)
{
    Dex dex = read_fixture("inherit.dex");
    Dex copy = dex;

    EXPECT_EQ(written(dex), written(copy));
}

TEST(Write, write_whenMembersAndAnnotationsAreOutOfOrder_readsBackSorted)
{
    Dex dex;
    ClassDef &c = dex.classes.emplace_back(class_def("LT;"));
    c.annotations = {annotation("LZ;"), annotation("LA;"), annotation("LM;")};
    for (const char *name : {"z", "b", "a"}) {
        FieldDef &f = c.fields.emplace_back();
        f.name = name;
        f.type = "I";
        f.annotations = {annotation(std::string("LF") + name + ";"), annotation("LA;")};
    }

    Dex back = reread(written(dex));

    EXPECT_NE(back, dex);
    EXPECT_EQ(back.classes[0].fields[0].name, "a");
    EXPECT_EQ(back.classes[0].annotations[0].annotation.type, "LA;");
}

TEST(Write, write_whenMembersAndAnnotationsAreOutOfOrder_isAFixpoint)
{
    Dex dex;
    ClassDef &c = dex.classes.emplace_back(class_def("LT;"));
    c.annotations = {annotation("LZ;"), annotation("LA;"), annotation("LM;")};
    for (const char *name : {"z", "b", "a"}) {
        FieldDef &f = c.fields.emplace_back();
        f.name = name;
        f.type = "I";
        f.annotations = {annotation(std::string("LF") + name + ";"), annotation("LA;")};
    }

    Bytes first = written(dex);

    EXPECT_EQ(written(reread(first)), first);
}

TEST(Write, write_whenModelWasReadFromAFixture_passesTheFormatChecks)
{
    for (const std::string &name : kFixtures) {
        auto bytes = write(read_fixture(name));

        ASSERT_TRUE(bytes.has_value()) << name << ": " << describe(bytes.error());
        EXPECT_EQ(check_dex(*bytes), Strings{}) << name;
    }
}

TEST(Write, write_whenModelWasReadFromAFixture_readsBackToAnEqualModel)
{
    for (const std::string &name : kFixtures) {
        Dex dex = read_fixture(name);

        EXPECT_TRUE(reread(written(dex)) == dex) << name;
    }
}

TEST(Write, write_whenTheOutputIsReadAndWrittenAgain_writesTheSameBytes)
{
    for (const std::string &name : kFixtures) {
        Bytes first = written(read_fixture(name));

        EXPECT_TRUE(written(reread(first)) == first) << name;
    }
}

TEST(Write, write_whenEachClassOfAFixtureIsWrittenAlone_readsBackAsThatClass)
{
    for (const char *name : {"inherit.dex", "shapes.dex"}) {
        Dex dex = read_fixture(name);
        ASSERT_GT(dex.classes.size(), 1u);

        for (const ClassDef &c : dex.classes) {
            const Dex piece{dex.version, {c}};

            EXPECT_TRUE(reread(written(piece)) == piece) << name << " " << c.type;
        }
    }
}

TEST(Write, write_whenVersionIsADexVersion_writesItInTheMagic)
{
    for (uint32_t version : {35u, 37u, 38u, 39u, 40u}) {
        Dex dex = valid();
        dex.version = version;
        const std::string magic = std::format("dex\n0{}", version) + '\0';

        Bytes bytes = written(dex);

        EXPECT_EQ(std::string(bytes.begin(), bytes.begin() + 8), magic);
    }
}

TEST(Write, write_whenCalled_writesTheAdler32ChecksumOfTheFile)
{
    Bytes bytes = written(hello_world());

    EXPECT_EQ(parsed(bytes).header().checksum, raw::parser::compute_checksum(bytes).value());
}

TEST(Write, write_whenCalled_writesTheSha1SignatureOfTheFile)
{
    Bytes bytes = written(hello_world());
    const raw::Header header = parsed(bytes).header();

    auto signature = raw::parser::compute_signature(bytes).value();

    EXPECT_TRUE(std::equal(signature.begin(), signature.end(), header.signature));
}

TEST(Write, write_whenCalled_writesTheSizeOfTheFile)
{
    Bytes bytes = written(hello_world());

    EXPECT_EQ(parsed(bytes).header().file_size, bytes.size());
}

TEST(Write, write_whenCalled_writesTheHeaderSizeAndTheLittleEndianTag)
{
    raw::Header header = header_of(hello_world());

    EXPECT_EQ(header.header_size, kHeaderSize);
    EXPECT_EQ(header.endian_tag, raw::ENDIAN_CONSTANT);
}

TEST(Write, write_whenCalled_writesNoLinkSection)
{
    raw::Header header = header_of(hello_world());

    EXPECT_EQ(header.link_size, 0u);
    EXPECT_EQ(header.link_off, 0u);
}

TEST(Write, write_whenCalled_writesTheSizeOfEachIdTable)
{
    // Hello world: 13 strings, 7 types, 2 prototypes, 1 field, 2 methods, 1 class.
    raw::Header header = header_of(hello_world());

    EXPECT_EQ(header.string_ids_size, 13u);
    EXPECT_EQ(header.type_ids_size, 7u);
    EXPECT_EQ(header.proto_ids_size, 2u);
    EXPECT_EQ(header.field_ids_size, 1u);
    EXPECT_EQ(header.method_ids_size, 2u);
    EXPECT_EQ(header.class_defs_size, 1u);
}

TEST(Write, write_whenCalled_laysTheIdTablesOutInOrderAfterTheHeader)
{
    raw::Header header = header_of(hello_world());

    EXPECT_EQ(header.string_ids_off, kHeaderSize);
    EXPECT_EQ(header.type_ids_off, kHeaderSize + 13 * 4);
    EXPECT_EQ(header.proto_ids_off, kHeaderSize + 13 * 4 + 7 * 4);
    EXPECT_EQ(header.field_ids_off, kHeaderSize + 13 * 4 + 7 * 4 + 2 * 12);
    EXPECT_EQ(header.method_ids_off, kHeaderSize + 13 * 4 + 7 * 4 + 2 * 12 + 1 * 8);
    EXPECT_EQ(header.class_defs_off, kHeaderSize + 13 * 4 + 7 * 4 + 2 * 12 + 1 * 8 + 2 * 8);
    EXPECT_EQ(header.data_off, kHeaderSize + 13 * 4 + 7 * 4 + 2 * 12 + 1 * 8 + 2 * 8 + 1 * 32);
}

TEST(Write, write_whenCalled_endsTheDataSectionAtTheEndOfTheFile)
{
    Bytes bytes = written(hello_world());
    const raw::Header header = parsed(bytes).header();

    EXPECT_EQ(header.data_off + header.data_size, bytes.size());
}

TEST(Write, write_whenModelHasCallSitesAndMethodHandles_putsTheirTablesBeforeTheData)
{
    Bytes bytes = written(call_sites());
    raw::DexFile file = parsed(bytes);
    const raw::Header &header = file.header();
    const uint32_t tables_end = header.class_defs_off + header.class_defs_size * 32;

    // 3 call site ids of 4 bytes, then 1 method handle of 8 bytes.
    EXPECT_EQ(header.data_off, tables_end + 3 * 4 + 1 * 8);
    ASSERT_EQ(file.method_handles().size(), 1u);
    EXPECT_EQ(file.method_handles()[0].method_handle_type,
              static_cast<uint16_t>(MethodHandleKind::InvokeStatic));
}

TEST(Write, write_whenDexHasNoClasses_writesOnlyTheHeaderAndTheMapList)
{
    Bytes bytes = written(Dex{});
    const raw::Header header = parsed(bytes).header();

    // The header, then a map list of two 12-byte items after its 4-byte size.
    EXPECT_EQ(bytes.size(), kHeaderSize + 4 + 2 * 12);
    EXPECT_EQ(header.string_ids_size, 0u);
    EXPECT_EQ(header.string_ids_off, 0u);
    EXPECT_EQ(header.class_defs_size, 0u);
    EXPECT_EQ(header.class_defs_off, 0u);
    EXPECT_EQ(header.map_off, kHeaderSize);
    EXPECT_EQ(map_types(bytes), (std::vector<uint16_t>{raw::TYPE_HEADER_ITEM, raw::TYPE_MAP_LIST}));
}

TEST(Write, write_whenCalled_startsTheMapListWithTheHeaderItem)
{
    raw::MapList map = parsed(written(hello_world())).map_list();

    ASSERT_FALSE(map.items.empty());
    EXPECT_EQ(map.items[0].type, raw::TYPE_HEADER_ITEM);
    EXPECT_EQ(map.items[0].size, 1u);
    EXPECT_EQ(map.items[0].offset, 0u);
}

TEST(Write, write_whenCalled_listsTheMapListItselfAtTheOffsetInTheHeader)
{
    raw::DexFile file = parsed(written(hello_world()));
    const raw::MapItem &last = file.map_list().items.back();

    EXPECT_EQ(last.type, raw::TYPE_MAP_LIST);
    EXPECT_EQ(last.size, 1u);
    EXPECT_EQ(last.offset, file.header().map_off);
}

TEST(Write, write_whenCalled_listsEachIdTableInTheMapAsInTheHeader)
{
    raw::DexFile file = parsed(written(hello_world()));
    const raw::Header &header = file.header();
    const std::vector<std::tuple<uint16_t, uint32_t, uint32_t>> expected{
        {raw::TYPE_STRING_ID_ITEM, header.string_ids_size, header.string_ids_off},
        {raw::TYPE_TYPE_ID_ITEM, header.type_ids_size, header.type_ids_off},
        {raw::TYPE_PROTO_ID_ITEM, header.proto_ids_size, header.proto_ids_off},
        {raw::TYPE_FIELD_ID_ITEM, header.field_ids_size, header.field_ids_off},
        {raw::TYPE_METHOD_ID_ITEM, header.method_ids_size, header.method_ids_off},
        {raw::TYPE_CLASS_DEF_ITEM, header.class_defs_size, header.class_defs_off},
    };

    for (const auto &[type, size, offset] : expected) {
        bool found = false;
        for (const raw::MapItem &item : file.map_list().items)
            found = found || (item.type == type && item.size == size && item.offset == offset);

        EXPECT_TRUE(found) << "map item of type " << type;
    }
}

TEST(Write, write_whenModelIsMinimal_listsOnlyTheSectionsItNeeds)
{
    Bytes bytes = written(valid());

    EXPECT_EQ(map_types(bytes), (std::vector<uint16_t>{
                                    raw::TYPE_HEADER_ITEM,
                                    raw::TYPE_STRING_ID_ITEM,
                                    raw::TYPE_TYPE_ID_ITEM,
                                    raw::TYPE_PROTO_ID_ITEM,
                                    raw::TYPE_METHOD_ID_ITEM,
                                    raw::TYPE_CLASS_DEF_ITEM,
                                    raw::TYPE_CODE_ITEM,
                                    raw::TYPE_STRING_DATA_ITEM,
                                    raw::TYPE_CLASS_DATA_ITEM,
                                    raw::TYPE_MAP_LIST,
                                }));
}

TEST(Write, write_whenModelUsesEveryFeature_listsEverySectionInTheMap)
{
    std::vector<uint16_t> types = map_types(written(every_section()));
    std::sort(types.begin(), types.end());

    EXPECT_EQ(types, (std::vector<uint16_t>{
                         raw::TYPE_HEADER_ITEM,         raw::TYPE_STRING_ID_ITEM,
                         raw::TYPE_TYPE_ID_ITEM,        raw::TYPE_PROTO_ID_ITEM,
                         raw::TYPE_FIELD_ID_ITEM,       raw::TYPE_METHOD_ID_ITEM,
                         raw::TYPE_CLASS_DEF_ITEM,      raw::TYPE_CALL_SITE_ID_ITEM,
                         raw::TYPE_METHOD_HANDLE_ITEM,  raw::TYPE_MAP_LIST,
                         raw::TYPE_TYPE_LIST,           raw::TYPE_ANNOTATION_SET_REF_LIST,
                         raw::TYPE_ANNOTATION_SET_ITEM, raw::TYPE_CLASS_DATA_ITEM,
                         raw::TYPE_CODE_ITEM,           raw::TYPE_STRING_DATA_ITEM,
                         raw::TYPE_DEBUG_INFO_ITEM,     raw::TYPE_ANNOTATION_ITEM,
                         raw::TYPE_ENCODED_ARRAY_ITEM,  raw::TYPE_ANNOTATIONS_DIRECTORY_ITEM,
                     }));
}

TEST(Write, write_whenModelUsesEveryFeature_readsBackEqual)
{
    Dex dex = every_section();

    EXPECT_EQ(reread(written(dex)), dex);
}

TEST(Write, write_whenAnAnnotationIsUsedInSeveralPlaces_writesItOnce)
{
    Bytes bytes = written(every_section());

    EXPECT_EQ(map_count(bytes, raw::TYPE_ANNOTATION_ITEM), 1u);
    EXPECT_EQ(map_count(bytes, raw::TYPE_ANNOTATION_SET_ITEM), 1u);
}

TEST(Write, write_whenTwoClassesHaveTheSameClassAnnotations_sharesOneDirectory)
{
    Dex dex;
    for (const char *type : {"LA;", "LB;"}) {
        dex.classes.push_back(class_def(type));
        dex.classes.back().annotations = {annotation("LAnno;")};
    }

    Bytes bytes = written(dex);
    raw::DexFile file = parsed(bytes);

    EXPECT_EQ(map_count(bytes, raw::TYPE_ANNOTATIONS_DIRECTORY_ITEM), 1u);
    EXPECT_EQ(class_def_of(file, "LA;").annotations_off, class_def_of(file, "LB;").annotations_off);
}

TEST(Write, write_whenAnnotationsDifferInVisibility_writesBoth)
{
    Dex dex;
    for (const char *type : {"LA;", "LB;"})
        dex.classes.push_back(class_def(type));
    dex.classes[0].annotations = {annotation("LAnno;")};
    dex.classes[1].annotations = {annotation("LAnno;")};
    dex.classes[1].annotations[0].visibility = AnnotationVisibility::Build;

    Bytes bytes = written(dex);

    EXPECT_EQ(map_count(bytes, raw::TYPE_ANNOTATION_ITEM), 2u);
    EXPECT_EQ(reread(bytes), dex);
}

TEST(Write, write_whenPrototypesAndInterfacesUseTheSameTypes_sharesOneTypeList)
{
    Dex dex = valid();
    cls(dex).interfaces = {"LI;"};
    code(dex).items = {Insn{ConstMethodType{0, "(LI;)V"}}, Insn{ConstMethodType{0, "(LI;)I"}},
                       Insn{ReturnVoid{}}};
    dex.version = 39;

    Bytes bytes = written(dex);

    EXPECT_EQ(map_count(bytes, raw::TYPE_TYPE_LIST), 1u);
}

TEST(Write, write_whenAClassHasNoMembers_writesNoClassData)
{
    Dex dex;
    dex.classes.push_back(class_def("LEmpty;"));

    Bytes bytes = written(dex);

    EXPECT_EQ(class_def_of(parsed(bytes), "LEmpty;").class_data_off, 0u);
    EXPECT_EQ(map_count(bytes, raw::TYPE_CLASS_DATA_ITEM), 0u);
}

TEST(Write, write_whenAClassHasNoSuperclassAndNoSourceFile_writesNoIndexForBoth)
{
    Dex dex;
    ClassDef object;
    object.type = "Ljava/lang/Object;";
    dex.classes.push_back(object);

    raw::DexFile file = parsed(written(dex));
    const raw::ClassDefItem &cd = class_def_of(file, "Ljava/lang/Object;");

    EXPECT_EQ(cd.superclass_idx, raw::NO_INDEX);
    EXPECT_EQ(cd.source_file_idx, raw::NO_INDEX);
    EXPECT_EQ(cd.interfaces_off, 0u);
    EXPECT_EQ(cd.annotations_off, 0u);
}

TEST(Write, write_whenAClassHasFlagsASuperclassAndASourceFile_writesThemInItsClassDef)
{
    raw::DexFile file = parsed(written(hello_world()));
    const raw::ClassDefItem &cd = class_def_of(file, "LHello;");

    EXPECT_EQ(cd.access_flags, static_cast<uint32_t>(AccessFlags::Public));
    EXPECT_EQ(file.strings()[file.type_ids()[cd.superclass_idx]], "Ljava/lang/Object;");
    EXPECT_EQ(file.strings()[cd.source_file_idx], "Hello.java");
}

TEST(Write, write_whenAClassHasInterfaces_writesThemInModelOrder)
{
    Dex dex;
    dex.classes.push_back(class_def("LT;"));
    dex.classes[0].interfaces = {"LZ;", "LA;"};

    Bytes bytes = written(dex);
    raw::DexFile file = parsed(bytes);
    raw::TypeList list =
        raw::parser::parse_type_list(bytes, class_def_of(file, "LT;").interfaces_off).value();

    Strings names;
    for (uint16_t type : list.type_ids)
        names.push_back(file.strings()[file.type_ids()[type]]);
    EXPECT_EQ(names, (Strings{"LZ;", "LA;"}));
}

TEST(Write, write_whenCodeHasATryRangeAndAnOddNumberOfUnits_readsBackEqual)
{
    Dex dex = valid();
    code(dex).items = {Label{0},           Insn{Nop{}}, Label{1},
                       Insn{ReturnVoid{}}, Label{2},    Insn{ReturnVoid{}}};
    code(dex).tries = {TryRange{Label{0}, Label{1}, {Catch{"LE;", Label{2}}}, std::nullopt}};

    Bytes bytes = written(dex);
    raw::CodeItem item = written_code(bytes, "LT;", "m");

    EXPECT_EQ(item.insns_size, 3u);
    ASSERT_EQ(item.tries.size(), 1u);
    EXPECT_EQ(item.tries[0].start_addr, 0u);
    EXPECT_EQ(item.tries[0].insn_count, 1u);
    EXPECT_EQ(reread(bytes), dex);
}

TEST(Write, write_whenTwoMethodsHaveTheSameDebugInfo_sharesOneDebugInfoItem)
{
    Dex dex = with_code({LineNumber{7}, Insn{ReturnVoid{}}});
    MethodDef other = method(dex);
    other.name = "other";
    cls(dex).methods.push_back(other);

    Bytes bytes = written(dex);

    EXPECT_EQ(map_count(bytes, raw::TYPE_DEBUG_INFO_ITEM), 1u);
    EXPECT_EQ(written_code(bytes, "LT;", "m").debug_info_off,
              written_code(bytes, "LT;", "other").debug_info_off);
}

TEST(Write, write_whenDebugInfoIsOn_writesTheDebugInfoOfTheCode)
{
    Dex dex = with_code({LineNumber{7}, Insn{ReturnVoid{}}});

    Bytes bytes = written(dex);

    EXPECT_NE(written_code(bytes, "LT;", "m").debug_info_off, 0u);
    EXPECT_EQ(reread(bytes), dex);
}

TEST(Write, write_whenDebugInfoIsOff_writesNoDebugInfoItem)
{
    Dex dex = with_code({LineNumber{7}, Insn{ReturnVoid{}}});

    Bytes bytes = written(dex, kNoDebugInfo);

    EXPECT_EQ(written_code(bytes, "LT;", "m").debug_info_off, 0u);
    EXPECT_EQ(map_count(bytes, raw::TYPE_DEBUG_INFO_ITEM), 0u);
}

TEST(Write, write_whenDebugInfoIsOff_leavesTheDebugNamesOutOfTheStrings)
{
    Dex dex = with_code({LocalStart{0, LocalVariable{"local", "I", std::nullopt}},
                         SetSourceFile{"Other.java"}, Insn{ReturnVoid{}}});
    method(dex).proto = "(I)V";
    code(dex).parameter_names = {std::string("argument")};

    raw::DexFile with_debug = parsed(written(dex));
    raw::DexFile without_debug = parsed(written(dex, kNoDebugInfo));

    for (const char *name : {"local", "Other.java", "argument"}) {
        EXPECT_EQ(std::count(with_debug.strings().begin(), with_debug.strings().end(), name), 1);
        EXPECT_EQ(std::count(without_debug.strings().begin(), without_debug.strings().end(), name),
                  0);
    }
}

TEST(Write, write_whenDebugInfoIsOff_readsBackWithoutMarkersAndParameterNames)
{
    Dex dex = with_code({LineNumber{10}, PrologueEnd{}, Insn{Const{0, 1}},
                         LocalStart{0, LocalVariable{"x", "I", std::nullopt}}, LineNumber{200},
                         Insn{ReturnVoid{}}});
    method(dex).proto = "(I)V";
    code(dex).parameter_names = {std::string("count")};

    Dex back = reread(written(dex, kNoDebugInfo));

    const Code &plain = code(back);
    EXPECT_TRUE(plain.parameter_names.empty());
    EXPECT_EQ(plain.items, (std::vector<Item>{Insn{Const{0, 1}}, Insn{ReturnVoid{}}}));
}

TEST(Write, write_whenCodeHasEveryDebugMarker_readsBackEqual)
{
    Dex dex = with_code({
        LineNumber{10},
        PrologueEnd{},
        LineNumber{11},
        Insn{Const{0, 1}},
        LocalStart{0, LocalVariable{"x", "I", std::nullopt}},
        LineNumber{200},
        Insn{Const{0, 2}},
        LocalEnd{0},
        SetSourceFile{"Other.java"},
        LineNumber{3},
        LocalRestart{0},
        EpilogueBegin{},
        LineNumber{4},
        Insn{ReturnVoid{}},
        LocalStart{0, LocalVariable{"list", "Ljava/util/List;", "Ljava/util/List<TT;>;"}},
    });
    method(dex).proto = "(I)V";
    code(dex).parameter_names = {std::string("count")};

    EXPECT_EQ(reread(written(dex)), dex);
}

TEST(Write, write_whenCodeMixesConstantEncodings_readsBackEqual)
{
    Dex dex =
        with_code({Insn{Const{0, 5}}, Insn{Const{0, -8}}, Insn{Const{0, 100}}, Insn{Const{20, 5}},
                   Insn{Const{0, 0x10000}}, Insn{Const{0, 0x12345}}, Insn{ConstWide{0, 7}},
                   Insn{ConstWide{0, int64_t{1} << 48}}, Insn{ConstWide{0, 0x12345678}},
                   Insn{ConstWide{0, 0x123456789}}, Insn{ReturnVoid{}}},
                  22);

    EXPECT_EQ(reread(written(dex)), dex);
}

TEST(Write, write_whenCodeMixesMoveAndBinaryForms_readsBackEqual)
{
    Dex dex = with_code(
        {Insn{Move{ValueKind::Normal, 1, 2}}, Insn{Move{ValueKind::Normal, 1, 300}},
         Insn{Move{ValueKind::Normal, 300, 1}}, Insn{Binary{BinaryOp::AddInt, 1, 1, 2}},
         Insn{Binary{BinaryOp::AddInt, 1, 2, 3}}, Insn{Binary{BinaryOp::AddInt, 20, 20, 2}},
         Insn{BinaryLiteral{LiteralOp::Add, 1, 2, 5}},
         Insn{BinaryLiteral{LiteralOp::Add, 1, 2, 1000}}, Insn{ReturnVoid{}}},
        301);

    EXPECT_EQ(reread(written(dex)), dex);
}

TEST(Write, write_whenAGotoTargetsItself_readsBackEqual)
{
    Dex dex = with_code({Label{0}, Insn{Goto{Label{0}}}});

    EXPECT_EQ(reread(written(dex)), dex);
}

TEST(Write, write_whenAnIfTargetsItself_readsBackWithTheNopItBranchesTo)
{
    Dex dex = with_code({Label{0}, Insn{IfZero{Condition::Eq, 0, Label{0}}}, Insn{ReturnVoid{}}});

    Dex back = reread(written(dex));

    EXPECT_EQ(code(back).items,
              (std::vector<Item>{Label{0}, Insn{Nop{}}, Insn{IfZero{Condition::Eq, 0, Label{0}}},
                                 Insn{ReturnVoid{}}}));
}

TEST(Write, write_whenCodeHasAFarBranch_readsBackWithTheConditionTurnedAround)
{
    Dex back = reread(written(far_branch()));

    ASSERT_TRUE(std::holds_alternative<Insn>(code(back).items[0]));
    EXPECT_EQ(std::get<Insn>(code(back).items[0]), Insn{(IfZero{Condition::Ne, 0, Label{0}})});
}

TEST(Write, write_whenCodeHasAFarBranch_isAFixpoint)
{
    Bytes first = written(far_branch());

    EXPECT_EQ(written(reread(first)), first);
}

TEST(Write, write_whenDenseSwitchCasesAreOutOfOrder_readsThemBackSortedByKey)
{
    Dex dex =
        with_code({Insn{Switch{0, {{3, Label{0}}, {1, Label{1}}, {2, Label{0}}}}},
                   Insn{ReturnVoid{}}, Label{0}, Insn{ReturnVoid{}}, Label{1}, Insn{ReturnVoid{}}});

    Dex back = reread(written(dex));

    const Switch &sw = std::get<Switch>(std::get<Insn>(code(back).items[0]));
    EXPECT_EQ(sw.cases, (std::vector<Switch::Case>{{1, Label{1}}, {2, Label{0}}, {3, Label{0}}}));
}

TEST(Write, write_whenSparseSwitchCasesAreOutOfOrder_readsThemBackSortedByKey)
{
    Dex dex =
        with_code({Insn{Switch{0, {{1, Label{0}}, {1000, Label{1}}, {-7, Label{0}}}}},
                   Insn{ReturnVoid{}}, Label{0}, Insn{ReturnVoid{}}, Label{1}, Insn{ReturnVoid{}}});

    Dex back = reread(written(dex));

    const Switch &sw = std::get<Switch>(std::get<Insn>(code(back).items[0]));
    EXPECT_EQ(sw.cases,
              (std::vector<Switch::Case>{{-7, Label{0}}, {1, Label{0}}, {1000, Label{1}}}));
}

TEST(Write, write_whenAPackedSwitchHasAGap_readsBackWithoutACaseForTheGap)
{
    Dex dex = with_code({Insn{Switch{0, {{1, Label{0}}, {3, Label{0}}}}}, Insn{ReturnVoid{}},
                         Label{0}, Insn{ReturnVoid{}}});

    EXPECT_EQ(reread(written(dex)), dex);
}

TEST(Write, write_whenCodeFillsArrays_readsBackEqual)
{
    Dex dex =
        with_code({Insn{Const{0, 3}}, Insn{NewArray{1, 0, "[B"}},
                   Insn{FillArrayData{1, 1, {1, 2, 3}}}, Insn{NewArray{2, 0, "[J"}},
                   Insn{FillArrayData{2, 8, std::vector<uint8_t>(24, 0xAB)}}, Insn{ReturnVoid{}}});

    EXPECT_EQ(reread(written(dex)), dex);
}

TEST(Write, write_whenATryRangeIsNestedInAnother_readsBackAsThreeFlatRanges)
{
    const Insn call{Invoke{Invoke::Kind::Static, {}, MethodId{"LT;", "m", "()V"}}};
    Dex dex = with_code({Label{0}, call, Label{1}, call, Label{2}, call, Label{3},
                         Insn{ReturnVoid{}}, Label{4}, Insn{MoveException{0}}, Insn{ReturnVoid{}},
                         Label{5}, Insn{MoveException{0}}, Insn{ReturnVoid{}}});
    code(dex).tries = {
        TryRange{Label{1}, Label{2}, {Catch{"Ljava/io/IOException;", Label{5}}}, std::nullopt},
        TryRange{Label{0}, Label{3}, {Catch{"Ljava/lang/Exception;", Label{4}}}, std::nullopt},
    };

    Dex back = reread(written(dex));

    const std::vector<TryRange> &tries = code(back).tries;
    ASSERT_EQ(tries.size(), 3u);
    ASSERT_EQ(tries[0].catches.size(), 1u);
    EXPECT_EQ(tries[0].catches[0].type, "Ljava/lang/Exception;");
    ASSERT_EQ(tries[1].catches.size(), 2u);
    EXPECT_EQ(tries[1].catches[0].type, "Ljava/io/IOException;");
    EXPECT_EQ(tries[1].catches[1].type, "Ljava/lang/Exception;");
    ASSERT_EQ(tries[2].catches.size(), 1u);
    EXPECT_EQ(tries[2].catches[0].type, "Ljava/lang/Exception;");
}

TEST(Write, write_whenATryRangeIsLongerThan65535Units_writesAFileThatReadsBackToTheSameBytes)
{
    Dex dex = valid();
    std::vector<Item> &items = code(dex).items;
    items = {Label{0}, Insn{Nop{}}};
    items.insert(items.end(), 30000, Item{Insn{ConstWide{0, 0x123456789}}});
    items.push_back(Label{1});
    items.push_back(Insn{ReturnVoid{}});
    code(dex).tries = {TryRange{Label{0}, Label{1}, {}, Label{1}}};

    Bytes first = written(dex);

    EXPECT_EQ(written(reread(first)), first);
}

TEST(Write, write_whenAMethodHandleIsWritten_namesItsKindAndItsMember)
{
    raw::DexFile file = parsed(written(call_sites()));

    ASSERT_EQ(file.method_handles().size(), 1u);
    const raw::MethodHandleItem &handle = file.method_handles()[0];
    EXPECT_EQ(handle.method_handle_type, static_cast<uint16_t>(MethodHandleKind::InvokeStatic));
    EXPECT_EQ(file.strings()[file.method_ids()[handle.field_or_method_id].name_idx], "bootstrap");
}

TEST(Write, write_whenACallSiteIsWritten_writesItsHandleItsNameAndItsMethodType)
{
    Bytes bytes = written(call_sites());
    raw::DexFile file = parsed(bytes);
    uint32_t offset = file.call_site_ids()[0].call_site_off;

    std::vector<raw::EncodedValue> values = raw::parser::parse_encoded_array(bytes, offset).value();

    ASSERT_EQ(values.size(), 3u);
    EXPECT_EQ(values[0].type, raw::EncodedValue::Type::MethodHandle);
    EXPECT_EQ(std::get<uint32_t>(values[0].value), 0u);
    EXPECT_EQ(values[1].type, raw::EncodedValue::Type::String);
    EXPECT_EQ(file.strings()[std::get<uint32_t>(values[1].value)], "run");
    EXPECT_EQ(values[2].type, raw::EncodedValue::Type::MethodType);
    EXPECT_EQ(file.proto_ids()[std::get<uint32_t>(values[2].value)].parameters_off, 0u);
}

TEST(Write, write_whenAParameterHasNoAnnotation_readsBackWithItsEmptySet)
{
    Dex dex = valid();
    method(dex).proto = "(II)V";
    method(dex).parameter_annotations = {{}, {annotation("LA;")}};

    EXPECT_EQ(reread(written(dex)), dex);
}

TEST(Write, write_whenModelUsesInvokeCustomAtVersion37_returnsVersionTooLow)
{
    Dex dex = call_sites();
    dex.version = 37;

    Error error = write_error(dex);

    EXPECT_EQ(error.kind, Error::Kind::VersionTooLow);
    EXPECT_EQ(error.message,
              "the model needs DEX 038 (LT;->m()V, item 0: invoke-custom), but its version is 037");
    EXPECT_TRUE(error.problems.empty());
}

TEST(Write, write_whenAnInterfaceHasADefaultMethodAtVersion35_returnsVersionTooLow)
{
    Dex dex = valid();
    cls(dex).access = AccessFlags::Public | AccessFlags::Interface | AccessFlags::Abstract;
    method(dex).access = AccessFlags::Public;

    Error error = write_error(dex);

    EXPECT_EQ(error.kind, Error::Kind::VersionTooLow);
    EXPECT_TRUE(contains(error.message, "the model needs DEX 037"));
    EXPECT_TRUE(contains(error.message, "but its version is 035"));
}

TEST(Write, write_whenAnInterfaceHasADefaultMethodAtVersion37_writesIt)
{
    Dex dex = valid();
    dex.version = 37;
    cls(dex).access = AccessFlags::Public | AccessFlags::Interface | AccessFlags::Abstract;
    method(dex).access = AccessFlags::Public;

    EXPECT_EQ(reread(written(dex)), dex);
}

TEST(Write, write_whenModelUsesConstMethodHandleAtVersion38_returnsVersionTooLow)
{
    const MethodHandle handle{MethodHandleKind::InvokeStatic, MethodId{"LT;", "m", "()V"}};
    Dex dex = with_code({Insn{ConstMethodHandle{0, handle}}, Insn{ReturnVoid{}}});
    dex.version = 38;

    Error error = write_error(dex);

    EXPECT_EQ(error.kind, Error::Kind::VersionTooLow);
    EXPECT_TRUE(contains(error.message, "the model needs DEX 039"));
}

TEST(Write, write_whenTheVersionIsTooLowAndTheModelIsInvalid_reportsTheVersionFirst)
{
    Dex dex = call_sites();
    dex.version = 37;
    method(dex).name = "<foo>";

    EXPECT_EQ(write_error(dex).kind, Error::Kind::VersionTooLow);
}

TEST(Write, write_whenTheVersionDoesNotExist_returnsInvalidEvenIfAFeatureNeedsALaterOne)
{
    Dex dex = call_sites();
    dex.version = 36;

    Error error = write_error(dex);

    EXPECT_EQ(error.kind, Error::Kind::Invalid);
    EXPECT_EQ(error.message,
              "the model is not valid: unsupported DEX version 36 (use 35, 37, 38, 39 or 40)");
}

TEST(Write, write_whenTheVersionIs41_returnsInvalid)
{
    Dex dex = valid();
    dex.version = 41;

    EXPECT_EQ(write_error(dex).kind, Error::Kind::Invalid);
}

TEST(Write, write_whenModelBreaksTwoRules_listsEveryProblemOfValidate)
{
    Dex dex = valid();
    method(dex).name = "<foo>";
    cls(dex).interfaces = {"bad"};
    std::vector<Problem> expected = validate(dex);

    Error error = write_error(dex);

    EXPECT_EQ(error.kind, Error::Kind::Invalid);
    ASSERT_EQ(error.problems.size(), 2u);
    ASSERT_EQ(expected.size(), 2u);
    for (std::size_t i = 0; i < 2; ++i) {
        EXPECT_EQ(error.problems[i].where, expected[i].where);
        EXPECT_EQ(error.problems[i].message, expected[i].message);
    }
}

TEST(Write, write_whenModelBreaksTwoRules_namesTheFirstProblemAndCountsTheRest)
{
    Dex dex = valid();
    method(dex).name = "<foo>";
    cls(dex).interfaces = {"bad"};
    std::vector<Problem> problems = validate(dex);
    ASSERT_EQ(problems.size(), 2u);

    Error error = write_error(dex);

    EXPECT_EQ(error.message, "the model is not valid: " + problems[0].where + ": " +
                                 problems[0].message + " (and 1 more)");
}

TEST(Write, write_whenModelBreaksOneRule_namesItWithoutACount)
{
    Dex dex = valid();
    method(dex).name = "<foo>";
    std::vector<Problem> problems = validate(dex);
    ASSERT_EQ(problems.size(), 1u);

    Error error = write_error(dex);

    EXPECT_EQ(error.message,
              "the model is not valid: " + problems[0].where + ": " + problems[0].message);
}

TEST(Write, write_whenModelHasMoreThan65535Types_returnsTooLarge)
{
    Dex dex = with_many_insns(35, 65536,
                              [](std::size_t i) { return ConstClass{0, std::format("LT{};", i)}; });

    Error error = write_error(dex);

    EXPECT_EQ(error.kind, Error::Kind::TooLarge);
    EXPECT_TRUE(contains(error.message, "types; a DEX file holds at most 65535"));
    EXPECT_TRUE(error.problems.empty());
}

TEST(Write, write_whenModelHasMoreThan65535Prototypes_returnsTooLarge)
{
    Dex dex = with_many_insns(39, 65536, [](std::size_t i) {
        return ConstMethodType{0, std::format("(LT{};LT{};)V", i / 256, i % 256)};
    });

    Error error = write_error(dex);

    EXPECT_EQ(error.kind, Error::Kind::TooLarge);
    EXPECT_TRUE(contains(error.message, "prototypes; a DEX file holds at most 65535"));
}

TEST(Write, write_whenModelHasMoreThan65536Fields_returnsTooLarge)
{
    Dex dex = with_many_insns(35, 65537, [](std::size_t i) {
        return StaticGet{ValueKind::Normal, 0, FieldId{"LO;", std::format("f{}", i), "I"}};
    });

    Error error = write_error(dex);

    EXPECT_EQ(error.kind, Error::Kind::TooLarge);
    EXPECT_EQ(error.message, "65537 field references; a DEX file holds at most 65536");
}

TEST(Write, write_whenModelHasMoreThan65536Methods_returnsTooLarge)
{
    Dex dex = with_many_insns(35, 65536, [](std::size_t i) {
        return Invoke{Invoke::Kind::Static, {}, MethodId{"LO;", std::format("m{}", i), "()V"}};
    });

    Error error = write_error(dex);

    EXPECT_EQ(error.kind, Error::Kind::TooLarge);
    EXPECT_EQ(error.message, "65537 method references; a DEX file holds at most 65536");
}

TEST(Write, write_whenModelHasMoreThan65536MethodHandles_returnsTooLarge)
{
    Dex dex = with_many_insns(39, 65537, [](std::size_t i) {
        return ConstMethodHandle{0, MethodHandle{static_cast<MethodHandleKind>(i % 4),
                                                 FieldId{"LO;", std::format("f{}", i / 4), "I"}}};
    });

    Error error = write_error(dex);

    EXPECT_EQ(error.kind, Error::Kind::TooLarge);
    EXPECT_EQ(error.message, "65537 method handles; a DEX file holds at most 65536");
}

TEST(Write, write_whenModelHasMoreThan65536CallSites_returnsTooLarge)
{
    Dex dex =
        with_many_insns(38, 65537, [](std::size_t) { return InvokeCustom{{}, call_site(0)}; });

    Error error = write_error(dex);

    EXPECT_EQ(error.kind, Error::Kind::TooLarge);
    EXPECT_EQ(error.message, "65537 call sites; a DEX file holds at most 65536");
}

TEST(Write, write_whenModelHas65536CallSites_writesThemAll)
{
    Dex dex =
        with_many_insns(38, 65536, [](std::size_t) { return InvokeCustom{{}, call_site(0)}; });

    raw::DexFile file = parsed(written(dex));

    EXPECT_EQ(file.call_site_ids().size(), 65536u);
}

TEST(Write, writeFile_whenPathIsWritable_writesTheBytesOfWrite)
{
    const std::string path = temp_path("dexsplit_write_file.dex");
    Dex dex = hello_world();

    auto result = write_file(dex, path);
    Bytes on_disk = result.has_value() ? file_bytes(path) : Bytes{};
    std::filesystem::remove(path);

    ASSERT_TRUE(result.has_value()) << describe(result.error());
    EXPECT_EQ(on_disk, written(dex));
}

TEST(Write, writeFile_whenGivenOptions_writesTheBytesOfWriteWithThoseOptions)
{
    const std::string path = temp_path("dexsplit_write_file_options.dex");
    Dex dex = with_code({LineNumber{7}, Insn{ReturnVoid{}}});

    auto result = write_file(dex, path, kNoDebugInfo);
    Bytes on_disk = result.has_value() ? file_bytes(path) : Bytes{};
    std::filesystem::remove(path);

    ASSERT_TRUE(result.has_value()) << describe(result.error());
    EXPECT_EQ(on_disk, written(dex, kNoDebugInfo));
    EXPECT_NE(on_disk, written(dex));
}

TEST(Write, writeFile_whenTheFileExists_replacesItsContents)
{
    const std::string path = temp_path("dexsplit_write_file_existing.dex");
    {
        std::ofstream old(path, std::ios::binary);
        old << std::string(100000, 'x');
    }
    Dex dex = valid();

    auto result = write_file(dex, path);
    Bytes on_disk = result.has_value() ? file_bytes(path) : Bytes{};
    std::filesystem::remove(path);

    ASSERT_TRUE(result.has_value()) << describe(result.error());
    EXPECT_EQ(on_disk, written(dex));
}

TEST(Write, writeFile_whenTheDirectoryDoesNotExist_returnsAnIoError)
{
    const std::string path = temp_path("dexsplit-no-such-directory/out.dex");

    auto result = write_file(valid(), path);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().kind, Error::Kind::Io);
    EXPECT_EQ(result.error().message, "cannot create " + path);
}

TEST(Write, writeFile_whenTheModelIsInvalid_returnsTheErrorOfWriteAndCreatesNoFile)
{
    const std::string path = temp_path("dexsplit_write_file_invalid.dex");
    Dex dex = valid();
    method(dex).name = "<foo>";

    auto result = write_file(dex, path);
    const bool created = std::filesystem::exists(path);
    std::filesystem::remove(path);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().kind, Error::Kind::Invalid);
    EXPECT_EQ(result.error().problems.size(), 1u);
    EXPECT_FALSE(created);
}

TEST(Write, writeFile_whenTheDeviceIsFull_returnsAnIoError)
{
    if (!std::filesystem::exists("/dev/full"))
        GTEST_SKIP() << "no /dev/full on this system";

    auto result = write_file(valid(), "/dev/full");

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().kind, Error::Kind::Io);
    EXPECT_EQ(result.error().message, "cannot write /dev/full");
}

TEST(Write, writeFile_whenTheDeviceIsFullAndTheFileIsLarge_returnsAnIoError)
{
    if (!std::filesystem::exists("/dev/full"))
        GTEST_SKIP() << "no /dev/full on this system";
    Dex dex = with_many_insns(35, 30000, [](std::size_t i) {
        return ConstString{0, std::format("a long string constant, number {}", i)};
    });

    auto result = write_file(dex, "/dev/full");

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().kind, Error::Kind::Io);
    EXPECT_EQ(result.error().message, "cannot write /dev/full");
}

TEST(Write, poolStats_whenDexHasNoClasses_returnsZeroForEveryPool)
{
    EXPECT_TRUE(pool_stats(Dex{}) == PoolStats{});
}

TEST(Write, poolStats_whenModelIsHelloWorld_countsEachPool)
{
    PoolStats stats = pool_stats(hello_world());

    EXPECT_EQ(stats.strings, 13u);
    EXPECT_EQ(stats.types, 7u);
    EXPECT_EQ(stats.protos, 2u);
    EXPECT_EQ(stats.fields, 1u);
    EXPECT_EQ(stats.methods, 2u);
    EXPECT_EQ(stats.method_handles, 0u);
    EXPECT_EQ(stats.call_sites, 0u);
}

TEST(Write, poolStats_whenCallSitesShareAKey_countsThemOnce)
{
    PoolStats stats = pool_stats(call_sites());

    EXPECT_EQ(stats.call_sites, 3u);
    EXPECT_EQ(stats.method_handles, 1u);
}

TEST(Write, poolStats_whenAStringIsSpelledInTwoWays_countsItOnce)
{
    Dex dex = with_code({Insn{ConstString{0, kUnpairedSurrogate}}, Insn{ConstString{0, kSplitPair}},
                         Insn{ConstString{0, kJoinedPair}}, Insn{ReturnVoid{}}});

    EXPECT_EQ(pool_stats(dex).strings, pool_stats(reread(written(dex))).strings);
    EXPECT_EQ(pool_stats(dex).strings, pool_stats(valid()).strings + 2);
}

TEST(Write, poolStats_whenCodeHasDebugNames_countsThem)
{
    Dex dex =
        with_code({LocalStart{0, LocalVariable{"local", "I", std::nullopt}}, Insn{ReturnVoid{}}});

    EXPECT_EQ(pool_stats(dex).strings, pool_stats(valid()).strings + 2);
    EXPECT_EQ(pool_stats(dex).types, pool_stats(valid()).types + 1);
}

TEST(Write, poolStats_whenModelHasTooManyTypes_stillCountsThem)
{
    Dex dex = with_many_insns(35, 65536,
                              [](std::size_t i) { return ConstClass{0, std::format("LT{};", i)}; });

    EXPECT_EQ(pool_stats(dex).types, 65536u + 3);
}

TEST(Write, poolStats_whenModelWasReadFromAFixture_matchesTheTablesOfTheWrittenFile)
{
    for (const std::string &name : kFixtures) {
        Dex dex = read_fixture(name);

        EXPECT_TRUE(pool_stats(dex) == table_sizes(written(dex))) << name;
    }
}

// Every fixture holds one string nothing refers to, the marker D8 adds; the model drops it.
TEST(Write, poolStats_whenModelWasReadFromAFixture_matchesTheTablesOfTheFixtureButItsUnusedString)
{
    for (const std::string &name : kFixtures) {
        Bytes fixture = load_fixture(name);
        PoolStats expected = table_sizes(fixture);
        expected.strings -= 1;

        EXPECT_TRUE(pool_stats(reread(fixture)) == expected) << name;
    }
}

} // namespace
} // namespace dexsplit::model
