// Tests for the pools of the DEX writer: what is collected, how it is ordered and numbered.

#include "model/pools.hpp"

#include <cstddef>
#include <cstdint>
#include <format>
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#include "common/ids.hpp"
#include "model/io.hpp"
#include "model/types.hpp"
#include "support/models.hpp"

namespace dexsplit::model::detail {
namespace {

using support::call_site;
using support::write_failure;

// U+1F600 as a surrogate pair in two 3-byte sequences, and as one 4-byte sequence.
const std::string kSplitPair = "\xED\xA0\xBD\xED\xB8\x80";
const std::string kJoinedPair = "\xF0\x9F\x98\x80";
const std::string kUnpairedSurrogate = "a\xED\xA0\x80";

using Strings = std::vector<std::string>;

Strings proto_descriptors(const Pools &pools)
{
    Strings out;
    for (const Pools::ProtoEntry &entry : pools.protos())
        out.push_back(entry.descriptor);
    return out;
}

MethodHandle field_handle(MethodHandleKind kind, FieldId field)
{
    return MethodHandle{kind, std::move(field)};
}

MethodHandle method_handle(MethodHandleKind kind, MethodId method)
{
    return MethodHandle{kind, std::move(method)};
}

AnnotationItem annotation(std::string type, std::vector<NamedValue> elements = {})
{
    AnnotationItem a;
    a.annotation.type = std::move(type);
    a.annotation.elements = std::move(elements);
    return a;
}

ClassDef class_def()
{
    ClassDef c;
    c.type = "LT;";
    return c;
}

FieldDef field_def(std::string name, std::string type)
{
    FieldDef f;
    f.name = std::move(name);
    f.type = std::move(type);
    return f;
}

MethodDef method_def(std::string name, std::string proto)
{
    MethodDef m;
    m.name = std::move(name);
    m.proto = std::move(proto);
    return m;
}

Code code_of(std::vector<Item> items)
{
    Code code;
    code.items = std::move(items);
    return code;
}

Pools collected(const Value &value)
{
    Pools pools;
    pools.add_value(value);
    pools.finish();
    return pools;
}

Pools collected(const ClassDef &c, bool debug_info = true)
{
    Pools pools;
    pools.add_class(c, debug_info);
    pools.finish();
    return pools;
}

Pools collected(const Code &code, bool debug_info = true)
{
    Pools pools;
    pools.add_code(code, debug_info);
    pools.finish();
    return pools;
}

bool has(const Strings &list, std::string_view value)
{
    for (const std::string &item : list)
        if (item == value)
            return true;
    return false;
}

Pools pools_with_types(std::size_t count)
{
    Pools pools;
    for (std::size_t i = 0; i < count; ++i)
        pools.add_type(std::format("LT{};", i));
    return pools;
}

// Prototypes "(LTa;LTb;)V" over 256 parameter types, so the type pool stays small.
Pools pools_with_protos(std::size_t count)
{
    Pools pools;
    for (std::size_t i = 0; i < count; ++i)
        pools.add_proto(std::format("(LT{};LT{};)V", i / 256, i % 256));
    return pools;
}

Pools pools_with_fields(std::size_t count)
{
    Pools pools;
    for (std::size_t i = 0; i < count; ++i)
        pools.add_field(FieldId{"LA;", std::format("f{}", i), "I"});
    return pools;
}

Pools pools_with_methods(std::size_t count)
{
    Pools pools;
    for (std::size_t i = 0; i < count; ++i)
        pools.add_method(MethodId{"LA;", std::format("m{}", i), "()V"});
    return pools;
}

// The four field kinds over count / 4 fields, so the field pool stays small.
Pools pools_with_method_handles(std::size_t count)
{
    Pools pools;
    for (std::size_t i = 0; i < count; ++i)
        pools.add_method_handle(field_handle(static_cast<MethodHandleKind>(i % 4),
                                             {"LA;", std::format("f{}", i / 4), "I"}));
    return pools;
}

TEST(Pools, fail_whenCalled_throwsAWriteFailureWithTheKindAndTheMessage)
{
    Error error = write_failure([] { fail(Error::Kind::TooLarge, "too many things"); });

    EXPECT_EQ(error.kind, Error::Kind::TooLarge);
    EXPECT_EQ(error.message, "too many things");
    EXPECT_TRUE(error.problems.empty());
}

TEST(Pools, stringHash_whenGivenAStringAndItsView_returnsTheSameHash)
{
    const std::string text = "Ljava/lang/Object;";

    EXPECT_EQ(StringHash{}(text), StringHash{}(std::string_view(text)));
}

TEST(Pools, canon_whenStringIsCanonical_viewsTheGivenBytes)
{
    const std::string text = "plain";

    Canon canon(text);

    EXPECT_EQ(canon.view().data(), text.data());
    EXPECT_EQ(canon.view(), "plain");
}

TEST(Pools, canon_whenStringIsEmpty_viewsAnEmptyString)
{
    Canon canon("");

    EXPECT_TRUE(canon.view().empty());
}

TEST(Pools, canon_whenStringHasASplitSurrogatePair_viewsTheJoinedForm)
{
    Canon canon(kSplitPair);

    EXPECT_EQ(canon.view(), kJoinedPair);
}

TEST(Pools, canon_whenStringHasAnUnpairedSurrogate_keepsIt)
{
    Canon canon(kUnpairedSurrogate);

    EXPECT_EQ(canon.view(), kUnpairedSurrogate);
}

TEST(Pools, isCanonical_whenEveryPartOfAFieldIsCanonical_returnsTrue)
{
    EXPECT_TRUE(is_canonical(FieldId{"LA;", kJoinedPair, "I"}));
}

TEST(Pools, isCanonical_whenAPartOfAFieldHasASplitPair_returnsFalse)
{
    EXPECT_FALSE(is_canonical(FieldId{"L" + kSplitPair + ";", "f", "I"}));
    EXPECT_FALSE(is_canonical(FieldId{"LA;", kSplitPair, "I"}));
    EXPECT_FALSE(is_canonical(FieldId{"LA;", "f", "L" + kSplitPair + ";"}));
}

TEST(Pools, isCanonical_whenEveryPartOfAMethodIsCanonical_returnsTrue)
{
    EXPECT_TRUE(is_canonical(MethodId{"LA;", kJoinedPair, "()V"}));
}

TEST(Pools, isCanonical_whenAPartOfAMethodHasASplitPair_returnsFalse)
{
    EXPECT_FALSE(is_canonical(MethodId{"L" + kSplitPair + ";", "m", "()V"}));
    EXPECT_FALSE(is_canonical(MethodId{"LA;", kSplitPair, "()V"}));
    EXPECT_FALSE(is_canonical(MethodId{"LA;", "m", "(L" + kSplitPair + ";)V"}));
}

TEST(Pools, canonical_whenFieldIsCanonical_returnsItUnchanged)
{
    const FieldId field{"LA;", "f", "I"};

    EXPECT_EQ(canonical(field), field);
}

TEST(Pools, canonical_whenFieldHasSplitPairs_joinsThemInEveryPart)
{
    const FieldId field{"L" + kSplitPair + ";", kSplitPair, "[L" + kSplitPair + ";"};

    EXPECT_EQ(canonical(field),
              (FieldId{"L" + kJoinedPair + ";", kJoinedPair, "[L" + kJoinedPair + ";"}));
}

TEST(Pools, canonical_whenMethodIsCanonical_returnsItUnchanged)
{
    const MethodId method{"LA;", "m", "(I)V"};

    EXPECT_EQ(canonical(method), method);
}

TEST(Pools, canonical_whenMethodHasSplitPairs_joinsThemInEveryPart)
{
    const MethodId method{"L" + kSplitPair + ";", kSplitPair, "(L" + kSplitPair + ";)V"};

    EXPECT_EQ(canonical(method),
              (MethodId{"L" + kJoinedPair + ";", kJoinedPair, "(L" + kJoinedPair + ";)V"}));
}

TEST(Pools, methodHandleHash_whenHandlesAreEqual_returnsEqualHashes)
{
    const MethodHandle a = method_handle(MethodHandleKind::InvokeStatic, {"LA;", "m", "()V"});
    const MethodHandle b = method_handle(MethodHandleKind::InvokeStatic, {"LA;", "m", "()V"});

    EXPECT_EQ(MethodHandleHash{}(a), MethodHandleHash{}(b));
}

TEST(Pools, methodHandleHash_whenOnlyTheKindDiffers_returnsDifferentHashes)
{
    const MethodHandle get = field_handle(MethodHandleKind::StaticGet, {"LA;", "f", "I"});
    const MethodHandle put = field_handle(MethodHandleKind::StaticPut, {"LA;", "f", "I"});

    EXPECT_NE(MethodHandleHash{}(get), MethodHandleHash{}(put));
}

TEST(Pools, addString_whenStringIsNew_addsIt)
{
    Pools pools;
    pools.add_string("text");
    pools.finish();

    EXPECT_EQ(pools.strings(), (Strings{"text"}));
}

TEST(Pools, addString_whenStringIsEmpty_addsTheEmptyString)
{
    Pools pools;
    pools.add_string("");
    pools.finish();

    EXPECT_EQ(pools.strings(), (Strings{""}));
}

TEST(Pools, addString_whenStringWasAddedBefore_keepsOneEntry)
{
    Pools pools;
    pools.add_string("text");
    pools.add_string("text");

    EXPECT_EQ(pools.string_count(), 1u);
}

TEST(Pools, addString_whenStringHasASplitPair_storesTheJoinedForm)
{
    Pools pools;
    pools.add_string(kSplitPair);
    pools.finish();

    EXPECT_EQ(pools.strings(), (Strings{kJoinedPair}));
}

TEST(Pools, addString_whenBothSpellingsOfAPairAreAdded_keepsOneEntry)
{
    Pools pools;
    pools.add_string(kSplitPair);
    pools.add_string(kJoinedPair);

    EXPECT_EQ(pools.string_count(), 1u);
}

TEST(Pools, addString_whenStringHasAnUnpairedSurrogate_storesItUnchanged)
{
    Pools pools;
    pools.add_string(kUnpairedSurrogate);
    pools.finish();

    EXPECT_EQ(pools.strings(), (Strings{kUnpairedSurrogate}));
}

TEST(Pools, addType_whenTypeIsNew_addsItAndItsDescriptorString)
{
    Pools pools;
    pools.add_type("LA;");
    pools.finish();

    EXPECT_EQ(pools.types(), (Strings{"LA;"}));
    EXPECT_EQ(pools.strings(), (Strings{"LA;"}));
}

TEST(Pools, addType_whenTypeIsAnArray_addsOnlyTheArrayType)
{
    Pools pools;
    pools.add_type("[LA;");
    pools.finish();

    EXPECT_EQ(pools.types(), (Strings{"[LA;"}));
    EXPECT_EQ(pools.strings(), (Strings{"[LA;"}));
}

TEST(Pools, addType_whenTypeWasAddedBefore_keepsOneEntry)
{
    Pools pools;
    pools.add_type("LA;");
    pools.add_type("LA;");

    EXPECT_EQ(pools.type_count(), 1u);
    EXPECT_EQ(pools.string_count(), 1u);
}

TEST(Pools, addType_whenTypeHasASplitPair_storesTheJoinedForm)
{
    Pools pools;
    pools.add_type("L" + kSplitPair + ";");
    pools.finish();

    EXPECT_EQ(pools.types(), (Strings{"L" + kJoinedPair + ";"}));
    EXPECT_EQ(pools.strings(), (Strings{"L" + kJoinedPair + ";"}));
}

TEST(Pools, addProto_whenProtoIsNew_addsItsReturnAndParameterTypes)
{
    Pools pools;
    pools.add_proto("(ILjava/lang/String;[J)V");
    pools.finish();

    EXPECT_EQ(proto_descriptors(pools), (Strings{"(ILjava/lang/String;[J)V"}));
    EXPECT_EQ(pools.types(), (Strings{"I", "Ljava/lang/String;", "V", "[J"}));
}

TEST(Pools, addProto_whenProtoIsNew_addsItsShortyButNotItsDescriptorToTheStrings)
{
    Pools pools;
    pools.add_proto("(ILjava/lang/String;[J)V");
    pools.finish();

    EXPECT_EQ(pools.strings(), (Strings{"I", "Ljava/lang/String;", "V", "VILL", "[J"}));
}

TEST(Pools, addProto_whenProtoTakesNoParameters_addsOnlyTheReturnType)
{
    Pools pools;
    pools.add_proto("()V");
    pools.finish();

    EXPECT_EQ(pools.types(), (Strings{"V"}));
    EXPECT_EQ(pools.strings(), (Strings{"V"}));
}

TEST(Pools, addProto_whenProtoWasAddedBefore_keepsOneEntry)
{
    Pools pools;
    pools.add_proto("(I)V");
    pools.add_proto("(I)V");

    EXPECT_EQ(pools.proto_count(), 1u);
}

TEST(Pools, addProto_whenProtoCannotBeParsed_countsItAndAddsNothingElse)
{
    Pools pools;
    pools.add_proto("not a prototype");

    EXPECT_EQ(pools.proto_count(), 1u);
    EXPECT_EQ(pools.type_count(), 0u);
    EXPECT_EQ(pools.string_count(), 0u);
}

TEST(Pools, addProto_whenProtoHasASplitPair_storesTheJoinedForm)
{
    Pools pools;
    pools.add_proto("(L" + kSplitPair + ";)V");
    pools.finish();

    EXPECT_EQ(proto_descriptors(pools), (Strings{"(L" + kJoinedPair + ";)V"}));
    EXPECT_EQ(pools.types(), (Strings{"L" + kJoinedPair + ";", "V"}));
}

TEST(Pools, addField_whenFieldIsNew_addsItsClassItsNameAndItsType)
{
    Pools pools;
    pools.add_field(FieldId{"LA;", "count", "I"});
    pools.finish();

    EXPECT_EQ(pools.fields(), (std::vector<FieldId>{{"LA;", "count", "I"}}));
    EXPECT_EQ(pools.types(), (Strings{"I", "LA;"}));
    EXPECT_EQ(pools.strings(), (Strings{"I", "LA;", "count"}));
}

TEST(Pools, addField_whenFieldWasAddedBefore_keepsOneEntry)
{
    Pools pools;
    pools.add_field(FieldId{"LA;", "count", "I"});
    pools.add_field(FieldId{"LA;", "count", "I"});

    EXPECT_EQ(pools.field_count(), 1u);
}

TEST(Pools, addField_whenFieldsDifferOnlyInType_keepsBoth)
{
    Pools pools;
    pools.add_field(FieldId{"LA;", "count", "I"});
    pools.add_field(FieldId{"LA;", "count", "J"});

    EXPECT_EQ(pools.field_count(), 2u);
}

TEST(Pools, addField_whenFieldHasASplitPair_storesTheJoinedForm)
{
    Pools pools;
    pools.add_field(FieldId{"LA;", kSplitPair, "I"});
    pools.add_field(FieldId{"LA;", kJoinedPair, "I"});
    pools.finish();

    EXPECT_EQ(pools.fields(), (std::vector<FieldId>{{"LA;", kJoinedPair, "I"}}));
    EXPECT_EQ(pools.strings(), (Strings{"I", "LA;", kJoinedPair}));
}

TEST(Pools, addMethod_whenMethodIsNew_addsItsClassItsNameAndItsPrototype)
{
    Pools pools;
    pools.add_method(MethodId{"LA;", "run", "(I)V"});
    pools.finish();

    EXPECT_EQ(pools.methods(), (std::vector<MethodId>{{"LA;", "run", "(I)V"}}));
    EXPECT_EQ(proto_descriptors(pools), (Strings{"(I)V"}));
    EXPECT_EQ(pools.types(), (Strings{"I", "LA;", "V"}));
    EXPECT_EQ(pools.strings(), (Strings{"I", "LA;", "V", "VI", "run"}));
}

TEST(Pools, addMethod_whenMethodWasAddedBefore_keepsOneEntry)
{
    Pools pools;
    pools.add_method(MethodId{"LA;", "run", "()V"});
    pools.add_method(MethodId{"LA;", "run", "()V"});

    EXPECT_EQ(pools.method_count(), 1u);
}

TEST(Pools, addMethod_whenMethodsDifferOnlyInPrototype_keepsBoth)
{
    Pools pools;
    pools.add_method(MethodId{"LA;", "run", "()V"});
    pools.add_method(MethodId{"LA;", "run", "(I)V"});

    EXPECT_EQ(pools.method_count(), 2u);
    EXPECT_EQ(pools.proto_count(), 2u);
}

TEST(Pools, addMethod_whenMethodHasASplitPair_storesTheJoinedForm)
{
    Pools pools;
    pools.add_method(MethodId{"LA;", kSplitPair, "()V"});
    pools.add_method(MethodId{"LA;", kJoinedPair, "()V"});
    pools.finish();

    EXPECT_EQ(pools.methods(), (std::vector<MethodId>{{"LA;", kJoinedPair, "()V"}}));
}

TEST(Pools, addMethodHandle_whenHandleNamesAField_addsTheHandleAndTheField)
{
    const MethodHandle handle = field_handle(MethodHandleKind::StaticGet, {"LA;", "f", "I"});
    Pools pools;
    pools.add_method_handle(handle);
    pools.finish();

    EXPECT_EQ(pools.method_handles(), (std::vector<MethodHandle>{handle}));
    EXPECT_EQ(pools.fields(), (std::vector<FieldId>{{"LA;", "f", "I"}}));
    EXPECT_TRUE(pools.methods().empty());
}

TEST(Pools, addMethodHandle_whenHandleNamesAMethod_addsTheHandleAndTheMethod)
{
    const MethodHandle handle = method_handle(MethodHandleKind::InvokeStatic, {"LA;", "m", "()V"});
    Pools pools;
    pools.add_method_handle(handle);
    pools.finish();

    EXPECT_EQ(pools.method_handles(), (std::vector<MethodHandle>{handle}));
    EXPECT_EQ(pools.methods(), (std::vector<MethodId>{{"LA;", "m", "()V"}}));
    EXPECT_TRUE(pools.fields().empty());
}

TEST(Pools, addMethodHandle_whenHandleWasAddedBefore_keepsOneEntry)
{
    Pools pools;
    pools.add_method_handle(field_handle(MethodHandleKind::StaticGet, {"LA;", "f", "I"}));
    pools.add_method_handle(field_handle(MethodHandleKind::StaticGet, {"LA;", "f", "I"}));

    EXPECT_EQ(pools.method_handle_count(), 1u);
}

TEST(Pools, addMethodHandle_whenHandlesDifferOnlyInKind_keepsBothAndOneField)
{
    Pools pools;
    pools.add_method_handle(field_handle(MethodHandleKind::StaticGet, {"LA;", "f", "I"}));
    pools.add_method_handle(field_handle(MethodHandleKind::StaticPut, {"LA;", "f", "I"}));

    EXPECT_EQ(pools.method_handle_count(), 2u);
    EXPECT_EQ(pools.field_count(), 1u);
}

TEST(Pools, addMethodHandle_whenMemberHasASplitPair_storesTheJoinedForm)
{
    Pools pools;
    pools.add_method_handle(
        method_handle(MethodHandleKind::InvokeStatic, {"LA;", kSplitPair, "()V"}));
    pools.add_method_handle(
        method_handle(MethodHandleKind::InvokeStatic, {"LA;", kJoinedPair, "()V"}));
    pools.finish();

    EXPECT_EQ(pools.method_handles(),
              (std::vector<MethodHandle>{
                  method_handle(MethodHandleKind::InvokeStatic, {"LA;", kJoinedPair, "()V"})}));
    EXPECT_EQ(pools.methods(), (std::vector<MethodId>{{"LA;", kJoinedPair, "()V"}}));
}

TEST(Pools, addValue_whenValueIsNullOrANumber_addsNothing)
{
    const std::vector<Value> values{
        Value{Value::Null{}},    Value{Value::Boolean{true}}, Value{Value::Byte{1}},
        Value{Value::Short{2}},  Value{Value::Char{u'c'}},    Value{Value::Int{3}},
        Value{Value::Long{4}},   Value{Value::Float{5.0f}},   Value{Value::Double{6.0}},
        Value{Value::Array{{}}},
    };
    Pools pools;

    for (const Value &value : values)
        pools.add_value(value);

    EXPECT_EQ(pools.string_count(), 0u);
    EXPECT_EQ(pools.type_count(), 0u);
    EXPECT_EQ(pools.proto_count(), 0u);
    EXPECT_EQ(pools.field_count(), 0u);
    EXPECT_EQ(pools.method_count(), 0u);
    EXPECT_EQ(pools.method_handle_count(), 0u);
}

TEST(Pools, addValue_whenValueIsAString_addsTheStringAndNoType)
{
    Pools pools = collected(Value{Value::String{"text"}});

    EXPECT_EQ(pools.strings(), (Strings{"text"}));
    EXPECT_TRUE(pools.types().empty());
}

TEST(Pools, addValue_whenValueIsAType_addsTheType)
{
    Pools pools = collected(Value{Value::Type{"[I"}});

    EXPECT_EQ(pools.types(), (Strings{"[I"}));
}

TEST(Pools, addValue_whenValueIsAField_addsTheField)
{
    Pools pools = collected(Value{Value::Field{FieldId{"LA;", "f", "I"}}});

    EXPECT_EQ(pools.fields(), (std::vector<FieldId>{{"LA;", "f", "I"}}));
}

TEST(Pools, addValue_whenValueIsAnEnum_addsItsField)
{
    Pools pools = collected(Value{Value::Enum{FieldId{"LE;", "ONE", "LE;"}}});

    EXPECT_EQ(pools.fields(), (std::vector<FieldId>{{"LE;", "ONE", "LE;"}}));
}

TEST(Pools, addValue_whenValueIsAMethod_addsTheMethod)
{
    Pools pools = collected(Value{Value::Method{MethodId{"LA;", "m", "()V"}}});

    EXPECT_EQ(pools.methods(), (std::vector<MethodId>{{"LA;", "m", "()V"}}));
}

TEST(Pools, addValue_whenValueIsAMethodType_addsThePrototype)
{
    Pools pools = collected(Value{Value::MethodType{"(I)V"}});

    EXPECT_EQ(proto_descriptors(pools), (Strings{"(I)V"}));
    EXPECT_TRUE(pools.methods().empty());
}

TEST(Pools, addValue_whenValueIsAMethodHandle_addsTheHandle)
{
    const MethodHandle handle = method_handle(MethodHandleKind::InvokeStatic, {"LA;", "m", "()V"});

    Pools pools = collected(Value{handle});

    EXPECT_EQ(pools.method_handles(), (std::vector<MethodHandle>{handle}));
}

TEST(Pools, addValue_whenValueIsAnArray_addsEveryElement)
{
    Pools pools = collected(Value{Value::Array{
        {Value{Value::String{"one"}}, Value{Value::Int{1}}, Value{Value::Type{"LA;"}}}}});

    EXPECT_EQ(pools.strings(), (Strings{"LA;", "one"}));
    EXPECT_EQ(pools.types(), (Strings{"LA;"}));
}

TEST(Pools, addValue_whenArraysAreNested_addsTheInnerElements)
{
    Pools pools =
        collected(Value{Value::Array{{Value{Value::Array{{Value{Value::String{"deep"}}}}}}}});

    EXPECT_EQ(pools.strings(), (Strings{"deep"}));
}

TEST(Pools, addValue_whenValueIsAnAnnotation_addsItsTypeItsNamesAndItsValues)
{
    const EncodedAnnotation inner{"LInner;", {NamedValue{"name", Value{Value::String{"text"}}}}};

    Pools pools = collected(Value{Shared<EncodedAnnotation>(inner)});

    EXPECT_EQ(pools.types(), (Strings{"LInner;"}));
    EXPECT_EQ(pools.strings(), (Strings{"LInner;", "name", "text"}));
}

TEST(Pools, addAnnotation_whenAnnotationHasNoElements_addsOnlyItsType)
{
    Pools pools;
    pools.add_annotation(EncodedAnnotation{"LAnno;", {}});
    pools.finish();

    EXPECT_EQ(pools.types(), (Strings{"LAnno;"}));
    EXPECT_EQ(pools.strings(), (Strings{"LAnno;"}));
}

TEST(Pools, addAnnotation_whenAnnotationHasElements_addsEachNameAndEachValue)
{
    Pools pools;
    pools.add_annotation(EncodedAnnotation{"LAnno;",
                                           {NamedValue{"count", Value{Value::Int{1}}},
                                            NamedValue{"kind", Value{Value::Type{"LKind;"}}}}});
    pools.finish();

    EXPECT_EQ(pools.types(), (Strings{"LAnno;", "LKind;"}));
    EXPECT_EQ(pools.strings(), (Strings{"LAnno;", "LKind;", "count", "kind"}));
}

TEST(Pools, addCallSite_whenCalled_addsTheBootstrapHandleTheNameAndTheMethodType)
{
    CallSite site;
    site.bootstrap = method_handle(MethodHandleKind::InvokeStatic, {"LBoot;", "boot", "()V"});
    site.method_name = "run";
    site.method_type = "(I)J";
    Pools pools;
    pools.add_call_site(site);
    pools.finish();

    EXPECT_EQ(pools.method_handles(), (std::vector<MethodHandle>{site.bootstrap}));
    EXPECT_EQ(pools.methods(), (std::vector<MethodId>{{"LBoot;", "boot", "()V"}}));
    EXPECT_EQ(proto_descriptors(pools), (Strings{"(I)J", "()V"}));
    EXPECT_TRUE(has(pools.strings(), "run"));
}

TEST(Pools, addCallSite_whenSiteHasExtraArguments_addsThem)
{
    CallSite site = call_site(0);
    site.extra_args = {Value{Value::String{"extra"}}, Value{Value::Type{"LArg;"}}};
    Pools pools;
    pools.add_call_site(site);
    pools.finish();

    EXPECT_TRUE(has(pools.strings(), "extra"));
    EXPECT_TRUE(has(pools.types(), "LArg;"));
}

TEST(Pools, addClass_whenClassHasOnlyAType_addsOnlyTheType)
{
    Pools pools = collected(class_def());

    EXPECT_EQ(pools.types(), (Strings{"LT;"}));
    EXPECT_EQ(pools.strings(), (Strings{"LT;"}));
}

TEST(Pools, addClass_whenClassHasASuperclass_addsItsType)
{
    ClassDef c = class_def();
    c.superclass = "LSuper;";

    Pools pools = collected(c);

    EXPECT_EQ(pools.types(), (Strings{"LSuper;", "LT;"}));
}

TEST(Pools, addClass_whenClassHasInterfaces_addsTheirTypes)
{
    ClassDef c = class_def();
    c.interfaces = {"LSecond;", "LFirst;"};

    Pools pools = collected(c);

    EXPECT_EQ(pools.types(), (Strings{"LFirst;", "LSecond;", "LT;"}));
}

TEST(Pools, addClass_whenClassHasASourceFile_addsItAsAStringOnly)
{
    ClassDef c = class_def();
    c.source_file = "T.java";

    Pools pools = collected(c);

    EXPECT_EQ(pools.strings(), (Strings{"LT;", "T.java"}));
    EXPECT_EQ(pools.types(), (Strings{"LT;"}));
}

TEST(Pools, addClass_whenClassHasAnAnnotation_addsTheAnnotation)
{
    ClassDef c = class_def();
    c.annotations = {annotation("LAnno;", {{"name", Value{Value::String{"text"}}}})};

    Pools pools = collected(c);

    EXPECT_EQ(pools.types(), (Strings{"LAnno;", "LT;"}));
    EXPECT_EQ(pools.strings(), (Strings{"LAnno;", "LT;", "name", "text"}));
}

TEST(Pools, addClass_whenClassHasAField_addsTheFieldOfThatClass)
{
    ClassDef c = class_def();
    c.fields = {field_def("f", "I")};

    Pools pools = collected(c);

    EXPECT_EQ(pools.fields(), (std::vector<FieldId>{{"LT;", "f", "I"}}));
}

TEST(Pools, addClass_whenAFieldHasAnInitialValue_addsTheValue)
{
    ClassDef c = class_def();
    c.fields = {field_def("f", "Ljava/lang/String;")};
    c.fields[0].initial_value = Value{Value::String{"initial"}};

    Pools pools = collected(c);

    EXPECT_TRUE(has(pools.strings(), "initial"));
}

TEST(Pools, addClass_whenAFieldHasAnAnnotation_addsTheAnnotation)
{
    ClassDef c = class_def();
    c.fields = {field_def("f", "I")};
    c.fields[0].annotations = {annotation("LOnField;")};

    Pools pools = collected(c);

    EXPECT_TRUE(has(pools.types(), "LOnField;"));
}

TEST(Pools, addClass_whenClassHasAMethod_addsTheMethodOfThatClass)
{
    ClassDef c = class_def();
    c.methods = {method_def("m", "(I)V")};

    Pools pools = collected(c);

    EXPECT_EQ(pools.methods(), (std::vector<MethodId>{{"LT;", "m", "(I)V"}}));
}

TEST(Pools, addClass_whenAMethodHasAnAnnotation_addsTheAnnotation)
{
    ClassDef c = class_def();
    c.methods = {method_def("m", "()V")};
    c.methods[0].annotations = {annotation("LOnMethod;")};

    Pools pools = collected(c);

    EXPECT_TRUE(has(pools.types(), "LOnMethod;"));
}

TEST(Pools, addClass_whenAMethodHasParameterAnnotations_addsEveryOne)
{
    ClassDef c = class_def();
    c.methods = {method_def("m", "(II)V")};
    c.methods[0].parameter_annotations = {{annotation("LOnFirst;")},
                                          {annotation("LOnSecond;"), annotation("LAlso;")}};

    Pools pools = collected(c);

    EXPECT_TRUE(has(pools.types(), "LOnFirst;"));
    EXPECT_TRUE(has(pools.types(), "LOnSecond;"));
    EXPECT_TRUE(has(pools.types(), "LAlso;"));
}

TEST(Pools, addClass_whenAMethodHasCode_addsWhatTheCodeRefersTo)
{
    ClassDef c = class_def();
    c.methods = {method_def("m", "()V")};
    c.methods[0].code = code_of({Insn{ConstString{0, "in code"}}});

    Pools pools = collected(c);

    EXPECT_TRUE(has(pools.strings(), "in code"));
}

TEST(Pools, addClass_whenDebugInfoIsAskedFor_addsTheDebugNamesOfTheCode)
{
    ClassDef c = class_def();
    c.methods = {method_def("m", "(I)V")};
    c.methods[0].code = code_of({Insn{ReturnVoid{}}});
    c.methods[0].code->parameter_names = {std::string("argument")};

    Pools pools = collected(c, true);

    EXPECT_TRUE(has(pools.strings(), "argument"));
}

TEST(Pools, addClass_whenDebugInfoIsNotAskedFor_leavesTheDebugNamesOut)
{
    ClassDef c = class_def();
    c.methods = {method_def("m", "(I)V")};
    c.methods[0].code = code_of({Insn{ReturnVoid{}}});
    c.methods[0].code->parameter_names = {std::string("argument")};

    Pools pools = collected(c, false);

    EXPECT_FALSE(has(pools.strings(), "argument"));
}

TEST(Pools, addCode_whenInstructionsReferToNothing_addsNothing)
{
    const Code code = code_of({Label{0}, Insn{Nop{}}, Insn{Const{0, 1}}, Insn{ConstWide{0, 2}},
                               Insn{Move{ValueKind::Normal, 0, 1}}, Insn{Goto{Label{0}}},
                               Insn{Switch{0, {{1, Label{0}}}}}, Insn{FillArrayData{0, 1, {7}}},
                               Insn{Binary{BinaryOp::AddInt, 0, 1, 2}}, Insn{ReturnVoid{}}});
    Pools pools;

    pools.add_code(code, true);

    EXPECT_EQ(pools.string_count(), 0u);
    EXPECT_EQ(pools.type_count(), 0u);
    EXPECT_EQ(pools.proto_count(), 0u);
    EXPECT_EQ(pools.field_count(), 0u);
    EXPECT_EQ(pools.method_count(), 0u);
    EXPECT_EQ(pools.method_handle_count(), 0u);
}

TEST(Pools, addCode_whenCodeLoadsAStringConstant_addsTheStringAndNoType)
{
    Pools pools = collected(code_of({Insn{ConstString{0, "text"}}}));

    EXPECT_EQ(pools.strings(), (Strings{"text"}));
    EXPECT_TRUE(pools.types().empty());
}

TEST(Pools, addCode_whenAnInstructionNamesAType_addsTheType)
{
    const std::vector<Insn> insns{
        ConstClass{0, "LA;"},  CheckCast{0, "LB;"},    InstanceOf{0, 1, "LC;"},
        NewInstance{0, "LD;"}, NewArray{0, 1, "[LE;"}, FilledNewArray{{0, 1}, "[LF;"},
    };
    Pools pools;
    for (const Insn &insn : insns)
        pools.add_code(code_of({insn}), true);
    pools.finish();

    EXPECT_EQ(pools.types(), (Strings{"LA;", "LB;", "LC;", "LD;", "[LE;", "[LF;"}));
}

TEST(Pools, addCode_whenCodeLoadsAMethodType_addsThePrototype)
{
    Pools pools = collected(code_of({Insn{ConstMethodType{0, "(I)V"}}}));

    EXPECT_EQ(proto_descriptors(pools), (Strings{"(I)V"}));
}

TEST(Pools, addCode_whenCodeLoadsAMethodHandle_addsTheHandle)
{
    const MethodHandle handle = field_handle(MethodHandleKind::InstanceGet, {"LA;", "f", "I"});

    Pools pools = collected(code_of({Insn{ConstMethodHandle{0, handle}}}));

    EXPECT_EQ(pools.method_handles(), (std::vector<MethodHandle>{handle}));
}

TEST(Pools, addCode_whenAnInstructionNamesAField_addsTheField)
{
    const std::vector<Insn> insns{
        InstanceGet{ValueKind::Normal, 0, 1, FieldId{"LA;", "a", "I"}},
        InstancePut{ValueKind::Normal, 0, 1, FieldId{"LA;", "b", "I"}},
        StaticGet{ValueKind::Normal, 0, FieldId{"LA;", "c", "I"}},
        StaticPut{ValueKind::Normal, 0, FieldId{"LA;", "d", "I"}},
    };
    Pools pools;
    for (const Insn &insn : insns)
        pools.add_code(code_of({insn}), true);
    pools.finish();

    EXPECT_EQ(pools.fields(),
              (std::vector<FieldId>{
                  {"LA;", "a", "I"}, {"LA;", "b", "I"}, {"LA;", "c", "I"}, {"LA;", "d", "I"}}));
}

TEST(Pools, addCode_whenCodeInvokesAMethod_addsTheMethod)
{
    Pools pools =
        collected(code_of({Insn{Invoke{Invoke::Kind::Static, {}, MethodId{"LA;", "m", "()V"}}}}));

    EXPECT_EQ(pools.methods(), (std::vector<MethodId>{{"LA;", "m", "()V"}}));
}

TEST(Pools, addCode_whenCodeInvokesPolymorphically_addsTheMethodAndTheCallPrototype)
{
    const MethodId invoke{"Ljava/lang/invoke/MethodHandle;", "invoke",
                          "([Ljava/lang/Object;)Ljava/lang/Object;"};

    Pools pools = collected(code_of({Insn{InvokePolymorphic{{0, 1}, invoke, "(I)V"}}}));

    EXPECT_EQ(pools.methods(), (std::vector<MethodId>{invoke}));
    EXPECT_TRUE(has(proto_descriptors(pools), "(I)V"));
}

TEST(Pools, addCode_whenCodeInvokesACallSite_addsWhatTheCallSiteRefersTo)
{
    const CallSite site = call_site(0);

    Pools pools = collected(code_of({Insn{InvokeCustom{{}, site}}}));

    EXPECT_EQ(pools.method_handles(), (std::vector<MethodHandle>{site.bootstrap}));
    EXPECT_TRUE(has(pools.strings(), "run"));
    EXPECT_TRUE(has(proto_descriptors(pools), "()V"));
}

TEST(Pools, addCode_whenTwoInstructionsShareAnOperand_keepsOneEntry)
{
    const Shared<std::string> text = "text";
    Pools pools;

    pools.add_code(code_of({Insn{ConstString{0, text}}, Insn{ConstString{1, text}}}), true);

    EXPECT_EQ(pools.string_count(), 1u);
}

TEST(Pools, addCode_whenOneSharedStringIsAConstantAndAType_addsItToBothPools)
{
    const Shared<std::string> shared = "LA;";

    Pools pools = collected(code_of({Insn{ConstString{0, shared}}, Insn{ConstClass{1, shared}}}));

    EXPECT_EQ(pools.strings(), (Strings{"LA;"}));
    EXPECT_EQ(pools.types(), (Strings{"LA;"}));
}

TEST(Pools, addCode_whenATryRangeHasCatches_addsTheirTypes)
{
    Code code = code_of({Label{0}, Insn{Nop{}}, Label{1}, Insn{ReturnVoid{}}});
    code.tries = {TryRange{Label{0},
                           Label{1},
                           {Catch{"LFirst;", Label{1}}, Catch{"LSecond;", Label{1}}},
                           std::nullopt}};

    Pools pools = collected(code);

    EXPECT_EQ(pools.types(), (Strings{"LFirst;", "LSecond;"}));
}

TEST(Pools, addCode_whenATryRangeHasOnlyACatchAll_addsNothing)
{
    Code code = code_of({Label{0}, Insn{Nop{}}, Label{1}, Insn{ReturnVoid{}}});
    code.tries = {TryRange{Label{0}, Label{1}, {}, Label{1}}};

    Pools pools = collected(code);

    EXPECT_TRUE(pools.types().empty());
}

TEST(Pools, addCode_whenALocalStarts_addsItsNameItsTypeAndItsSignature)
{
    const LocalVariable local{"list", "Ljava/util/List;", "Ljava/util/List<TT;>;"};

    Pools pools = collected(code_of({LocalStart{0, local}, Insn{ReturnVoid{}}}));

    EXPECT_EQ(pools.strings(), (Strings{"Ljava/util/List;", "Ljava/util/List<TT;>;", "list"}));
    EXPECT_EQ(pools.types(), (Strings{"Ljava/util/List;"}));
}

TEST(Pools, addCode_whenALocalHasNoNameTypeOrSignature_addsNothing)
{
    const LocalVariable local{std::nullopt, std::nullopt, std::nullopt};
    Pools pools;

    pools.add_code(code_of({LocalStart{0, local}, Insn{ReturnVoid{}}}), true);

    EXPECT_EQ(pools.string_count(), 0u);
    EXPECT_EQ(pools.type_count(), 0u);
}

TEST(Pools, addCode_whenTheSourceFileChanges_addsTheFileName)
{
    Pools pools = collected(code_of({SetSourceFile{"Other.java"}, Insn{ReturnVoid{}}}));

    EXPECT_EQ(pools.strings(), (Strings{"Other.java"}));
}

TEST(Pools, addCode_whenTheSourceFileIsUnknown_addsNothing)
{
    Pools pools;

    pools.add_code(code_of({SetSourceFile{std::nullopt}, Insn{ReturnVoid{}}}), true);

    EXPECT_EQ(pools.string_count(), 0u);
}

TEST(Pools, addCode_whenParametersHaveNames_addsTheNamesThatAreSet)
{
    Code code = code_of({Insn{ReturnVoid{}}});
    code.parameter_names = {std::string("first"), std::nullopt, std::string("third")};

    Pools pools = collected(code);

    EXPECT_EQ(pools.strings(), (Strings{"first", "third"}));
}

TEST(Pools, addCode_whenMarkersHoldNoString_addsNothing)
{
    Pools pools;

    pools.add_code(code_of({LineNumber{7}, PrologueEnd{}, EpilogueBegin{}, LocalEnd{0},
                            LocalRestart{0}, Insn{ReturnVoid{}}}),
                   true);

    EXPECT_EQ(pools.string_count(), 0u);
}

TEST(Pools, addCode_whenDebugInfoIsNotAskedFor_leavesLocalsFilesAndParameterNamesOut)
{
    Code code = code_of({LocalStart{0, LocalVariable{"x", "I", "sig"}}, SetSourceFile{"F.java"},
                         Insn{ReturnVoid{}}});
    code.parameter_names = {std::string("argument")};
    Pools pools;

    pools.add_code(code, false);

    EXPECT_EQ(pools.string_count(), 0u);
    EXPECT_EQ(pools.type_count(), 0u);
}

TEST(Pools, addCode_whenDebugInfoIsNotAskedFor_stillAddsWhatInstructionsAndCatchesReferTo)
{
    Code code = code_of({Label{0}, Insn{ConstString{0, "text"}}, Label{1}, Insn{ReturnVoid{}}});
    code.tries = {TryRange{Label{0}, Label{1}, {Catch{"LCaught;", Label{1}}}, std::nullopt}};

    Pools pools = collected(code, false);

    EXPECT_EQ(pools.strings(), (Strings{"LCaught;", "text"}));
    EXPECT_EQ(pools.types(), (Strings{"LCaught;"}));
}

TEST(Pools, stringCount_whenAMethodAndAFieldWereAdded_countsTheirStringsBeforeFinish)
{
    Pools pools;
    pools.add_method(MethodId{"LA;", "m", "(I)V"});
    pools.add_field(FieldId{"LA;", "f", "J"});

    EXPECT_EQ(pools.string_count(), 7u);
}

TEST(Pools, typeCount_whenAMethodAndAFieldWereAdded_countsTheirTypesBeforeFinish)
{
    Pools pools;
    pools.add_method(MethodId{"LA;", "m", "(I)V"});
    pools.add_field(FieldId{"LA;", "f", "J"});

    EXPECT_EQ(pools.type_count(), 4u);
}

TEST(Pools, protoCount_whenTwoMethodsShareAPrototype_countsItOnce)
{
    Pools pools;
    pools.add_method(MethodId{"LA;", "m", "(I)V"});
    pools.add_method(MethodId{"LA;", "n", "(I)V"});

    EXPECT_EQ(pools.proto_count(), 1u);
}

TEST(Pools, fieldCount_whenFieldsWereAdded_countsThemBeforeFinish)
{
    Pools pools;
    pools.add_field(FieldId{"LA;", "f", "J"});
    pools.add_field(FieldId{"LA;", "g", "J"});

    EXPECT_EQ(pools.field_count(), 2u);
}

TEST(Pools, methodCount_whenMethodsWereAdded_countsThemBeforeFinish)
{
    Pools pools;
    pools.add_method(MethodId{"LA;", "m", "(I)V"});
    pools.add_method(MethodId{"LA;", "n", "(I)V"});

    EXPECT_EQ(pools.method_count(), 2u);
}

TEST(Pools, methodHandleCount_whenHandlesWereAdded_countsThemBeforeFinish)
{
    Pools pools;
    pools.add_method_handle(field_handle(MethodHandleKind::StaticGet, {"LA;", "f", "J"}));
    pools.add_method_handle(field_handle(MethodHandleKind::StaticPut, {"LA;", "f", "J"}));

    EXPECT_EQ(pools.method_handle_count(), 2u);
}

TEST(Pools, finish_whenNothingWasAdded_leavesEveryListEmpty)
{
    Pools pools;

    pools.finish();

    EXPECT_TRUE(pools.strings().empty());
    EXPECT_TRUE(pools.types().empty());
    EXPECT_TRUE(pools.protos().empty());
    EXPECT_TRUE(pools.fields().empty());
    EXPECT_TRUE(pools.methods().empty());
    EXPECT_TRUE(pools.method_handles().empty());
}

TEST(Pools, finish_whenStringsWereAdded_sortsThemByCodeUnit)
{
    Pools pools;
    for (const char *text : {"b", "a", "B", "~", "0"})
        pools.add_string(text);

    pools.finish();

    EXPECT_EQ(pools.strings(), (Strings{"0", "B", "a", "b", "~"}));
}

TEST(Pools, finish_whenAStringIsAPrefixOfAnother_putsTheShorterOneFirst)
{
    Pools pools;
    for (const char *text : {"ab", "a", "", "abc"})
        pools.add_string(text);

    pools.finish();

    EXPECT_EQ(pools.strings(), (Strings{"", "a", "ab", "abc"}));
}

TEST(Pools, finish_whenAStringHasASupplementaryCharacter_sortsItByItsSurrogates)
{
    // U+10000 is the code units D800 DC00, which come before U+E000 and U+FFFF.
    const std::string supplementary = "\xF0\x90\x80\x80";
    const std::string private_use = "\xEE\x80\x80";
    const std::string last_bmp = "\xEF\xBF\xBF";
    Pools pools;
    for (const std::string &text : {last_bmp, supplementary, private_use})
        pools.add_string(text);

    pools.finish();

    EXPECT_EQ(pools.strings(), (Strings{supplementary, private_use, last_bmp}));
}

TEST(Pools, finish_whenAStringHasAnUnpairedSurrogate_sortsItByThatCodeUnit)
{
    const std::string below_surrogates = "\xED\x9F\xBF";
    const std::string lone_high = "\xED\xA0\x80";
    const std::string pair = "\xF0\x90\x80\x80";
    const std::string lone_low = "\xED\xB0\x80";
    const std::string above_surrogates = "\xEE\x80\x80";
    Pools pools;
    for (const std::string &text : {above_surrogates, lone_low, pair, lone_high, below_surrogates})
        pools.add_string(text);

    pools.finish();

    EXPECT_EQ(pools.strings(),
              (Strings{below_surrogates, lone_high, pair, lone_low, above_surrogates}));
}

TEST(Pools, finish_whenTypesWereAdded_sortsThemByTheIndexOfTheirString)
{
    const std::string supplementary = "L\xF0\x90\x80\x80;";
    const std::string private_use = "L\xEE\x80\x80;";
    Pools pools;
    for (const std::string &type : {private_use, std::string("[I"), std::string("LB;"),
                                    supplementary, std::string("LA;"), std::string("I")})
        pools.add_type(type);
    pools.add_string("K");

    pools.finish();

    EXPECT_EQ(pools.types(), (Strings{"I", "LA;", "LB;", supplementary, private_use, "[I"}));
}

TEST(Pools, finish_whenPrototypesWereAdded_sortsThemByReturnTypeThenParameters)
{
    Pools pools;
    for (const char *proto : {"(J)V", "()V", "(LA;)I", "(II)V", "()I", "(I)V", "(IJ)V"})
        pools.add_proto(proto);

    pools.finish();

    EXPECT_EQ(proto_descriptors(pools),
              (Strings{"()I", "(LA;)I", "()V", "(I)V", "(II)V", "(IJ)V", "(J)V"}));
}

TEST(Pools, finish_whenAPrototypeWasAdded_recordsItsShortyItsReturnTypeAndItsParameters)
{
    Pools pools;
    pools.add_proto("(ILA;)J");

    pools.finish();

    ASSERT_EQ(pools.strings(), (Strings{"I", "J", "JIL", "LA;"}));
    ASSERT_EQ(pools.types(), (Strings{"I", "J", "LA;"}));
    ASSERT_EQ(pools.protos().size(), 1u);
    const Pools::ProtoEntry &entry = pools.protos()[0];
    EXPECT_EQ(entry.descriptor, "(ILA;)J");
    EXPECT_EQ(entry.shorty, 2u);
    EXPECT_EQ(entry.return_type, 1u);
    EXPECT_EQ(entry.params, (std::vector<uint16_t>{0, 2}));
}

TEST(Pools, finish_whenFieldsWereAdded_sortsThemByClassThenNameThenType)
{
    Pools pools;
    pools.add_field(FieldId{"LB;", "a", "I"});
    pools.add_field(FieldId{"LA;", "b", "I"});
    pools.add_field(FieldId{"LA;", "a", "J"});
    pools.add_field(FieldId{"LA;", "a", "I"});

    pools.finish();

    EXPECT_EQ(pools.fields(),
              (std::vector<FieldId>{
                  {"LA;", "a", "I"}, {"LA;", "a", "J"}, {"LA;", "b", "I"}, {"LB;", "a", "I"}}));
}

TEST(Pools, finish_whenMethodsWereAdded_sortsThemByClassThenNameThenPrototype)
{
    Pools pools;
    pools.add_method(MethodId{"LB;", "a", "()V"});
    pools.add_method(MethodId{"LA;", "b", "()V"});
    pools.add_method(MethodId{"LA;", "a", "(I)V"});
    pools.add_method(MethodId{"LA;", "a", "()V"});
    pools.add_method(MethodId{"LA;", "<init>", "()V"});

    pools.finish();

    EXPECT_EQ(pools.methods(), (std::vector<MethodId>{{"LA;", "<init>", "()V"},
                                                      {"LA;", "a", "()V"},
                                                      {"LA;", "a", "(I)V"},
                                                      {"LA;", "b", "()V"},
                                                      {"LB;", "a", "()V"}}));
}

TEST(Pools, finish_whenMethodHandlesWereAdded_sortsThemByKindThenMember)
{
    const MethodHandle put_b = field_handle(MethodHandleKind::StaticPut, {"LA;", "b", "I"});
    const MethodHandle get_a = field_handle(MethodHandleKind::StaticGet, {"LA;", "a", "I"});
    const MethodHandle get_b = field_handle(MethodHandleKind::StaticGet, {"LA;", "b", "I"});
    const MethodHandle call_a = method_handle(MethodHandleKind::InvokeStatic, {"LA;", "a", "()V"});
    const MethodHandle call_b = method_handle(MethodHandleKind::InvokeStatic, {"LA;", "b", "()V"});
    Pools pools;
    for (const MethodHandle &handle : {call_b, get_b, put_b, call_a, get_a})
        pools.add_method_handle(handle);

    pools.finish();

    EXPECT_EQ(pools.method_handles(),
              (std::vector<MethodHandle>{put_b, get_a, get_b, call_a, call_b}));
}

TEST(Pools, string_whenStringWasCollected_returnsItsPositionInTheSortedList)
{
    Pools pools;
    for (const char *text : {"c", "a", "b"})
        pools.add_string(text);
    pools.finish();

    EXPECT_EQ(pools.string("a"), 0u);
    EXPECT_EQ(pools.string("b"), 1u);
    EXPECT_EQ(pools.string("c"), 2u);
}

TEST(Pools, string_whenGivenTheSplitSpellingOfAPair_returnsTheIndexOfTheJoinedOne)
{
    Pools pools;
    pools.add_string("a");
    pools.add_string(kJoinedPair);
    pools.finish();

    EXPECT_EQ(pools.string(kSplitPair), 1u);
    EXPECT_EQ(pools.string(kJoinedPair), 1u);
}

TEST(Pools, string_whenStringWasNotCollected_failsWithAnInternalError)
{
    Pools pools;
    pools.finish();

    Error error = write_failure([&] { (void)pools.string("missing"); });

    EXPECT_EQ(error.kind, Error::Kind::Invalid);
    EXPECT_EQ(error.message, "internal error: a string was not collected");
}

TEST(Pools, type_whenTypeWasCollected_returnsItsPositionInTheSortedList)
{
    Pools pools;
    for (const char *type : {"LB;", "I", "LA;"})
        pools.add_type(type);
    pools.finish();

    EXPECT_EQ(pools.type("I"), 0u);
    EXPECT_EQ(pools.type("LA;"), 1u);
    EXPECT_EQ(pools.type("LB;"), 2u);
}

TEST(Pools, type_whenGivenTheSplitSpellingOfAPair_returnsTheIndexOfTheJoinedOne)
{
    Pools pools;
    pools.add_type("I");
    pools.add_type("L" + kJoinedPair + ";");
    pools.finish();

    EXPECT_EQ(pools.type("L" + kSplitPair + ";"), 1u);
}

TEST(Pools, type_whenOnlyTheStringWasCollected_failsWithAnInternalError)
{
    Pools pools;
    pools.add_string("LA;");
    pools.finish();

    Error error = write_failure([&] { (void)pools.type("LA;"); });

    EXPECT_EQ(error.kind, Error::Kind::Invalid);
    EXPECT_EQ(error.message, "internal error: a type was not collected");
}

TEST(Pools, proto_whenPrototypeWasCollected_returnsItsPositionInTheSortedList)
{
    Pools pools;
    for (const char *proto : {"(I)V", "()V", "()I"})
        pools.add_proto(proto);
    pools.finish();

    EXPECT_EQ(pools.proto("()I"), 0u);
    EXPECT_EQ(pools.proto("()V"), 1u);
    EXPECT_EQ(pools.proto("(I)V"), 2u);
}

TEST(Pools, proto_whenGivenTheSplitSpellingOfAPair_returnsTheIndexOfTheJoinedOne)
{
    Pools pools;
    pools.add_proto("()V");
    pools.add_proto("(L" + kJoinedPair + ";)V");
    pools.finish();

    EXPECT_EQ(pools.proto("(L" + kSplitPair + ";)V"), 1u);
}

TEST(Pools, proto_whenPrototypeWasNotCollected_failsWithAnInternalError)
{
    Pools pools;
    pools.finish();

    Error error = write_failure([&] { (void)pools.proto("()V"); });

    EXPECT_EQ(error.kind, Error::Kind::Invalid);
    EXPECT_EQ(error.message, "internal error: a prototype was not collected");
}

TEST(Pools, field_whenFieldWasCollected_returnsItsPositionInTheSortedList)
{
    Pools pools;
    pools.add_field(FieldId{"LA;", "b", "I"});
    pools.add_field(FieldId{"LA;", "a", "I"});
    pools.finish();

    EXPECT_EQ(pools.field(FieldId{"LA;", "a", "I"}), 0u);
    EXPECT_EQ(pools.field(FieldId{"LA;", "b", "I"}), 1u);
}

TEST(Pools, field_whenGivenTheSplitSpellingOfAPair_returnsTheIndexOfTheJoinedOne)
{
    Pools pools;
    pools.add_field(FieldId{"LA;", "a", "I"});
    pools.add_field(FieldId{"LA;", kJoinedPair, "I"});
    pools.finish();

    EXPECT_EQ(pools.field(FieldId{"LA;", kSplitPair, "I"}), 1u);
}

TEST(Pools, field_whenFieldWasNotCollected_failsWithAnInternalError)
{
    Pools pools;
    pools.add_field(FieldId{"LA;", "a", "I"});
    pools.finish();

    Error error = write_failure([&] { (void)pools.field(FieldId{"LA;", "a", "J"}); });

    EXPECT_EQ(error.kind, Error::Kind::Invalid);
    EXPECT_EQ(error.message, "internal error: a field was not collected");
}

TEST(Pools, method_whenMethodWasCollected_returnsItsPositionInTheSortedList)
{
    Pools pools;
    pools.add_method(MethodId{"LA;", "b", "()V"});
    pools.add_method(MethodId{"LA;", "a", "()V"});
    pools.finish();

    EXPECT_EQ(pools.method(MethodId{"LA;", "a", "()V"}), 0u);
    EXPECT_EQ(pools.method(MethodId{"LA;", "b", "()V"}), 1u);
}

TEST(Pools, method_whenGivenTheSplitSpellingOfAPair_returnsTheIndexOfTheJoinedOne)
{
    Pools pools;
    pools.add_method(MethodId{"LA;", "a", "()V"});
    pools.add_method(MethodId{"LA;", kJoinedPair, "()V"});
    pools.finish();

    EXPECT_EQ(pools.method(MethodId{"LA;", kSplitPair, "()V"}), 1u);
}

TEST(Pools, method_whenMethodWasNotCollected_failsWithAnInternalError)
{
    Pools pools;
    pools.add_method(MethodId{"LA;", "a", "()V"});
    pools.finish();

    Error error = write_failure([&] { (void)pools.method(MethodId{"LA;", "a", "(I)V"}); });

    EXPECT_EQ(error.kind, Error::Kind::Invalid);
    EXPECT_EQ(error.message, "internal error: a method was not collected");
}

TEST(Pools, methodHandle_whenHandleWasCollected_returnsItsPositionInTheSortedList)
{
    const MethodHandle put = field_handle(MethodHandleKind::StaticPut, {"LA;", "f", "I"});
    const MethodHandle get = field_handle(MethodHandleKind::StaticGet, {"LA;", "f", "I"});
    Pools pools;
    pools.add_method_handle(get);
    pools.add_method_handle(put);
    pools.finish();

    EXPECT_EQ(pools.method_handle(put), 0u);
    EXPECT_EQ(pools.method_handle(get), 1u);
}

TEST(Pools, methodHandle_whenGivenTheSplitSpellingOfAPair_returnsTheIndexOfTheJoinedOne)
{
    Pools pools;
    pools.add_method_handle(field_handle(MethodHandleKind::StaticPut, {"LA;", "f", "I"}));
    pools.add_method_handle(field_handle(MethodHandleKind::StaticGet, {"LA;", kJoinedPair, "I"}));
    pools.finish();

    EXPECT_EQ(
        pools.method_handle(field_handle(MethodHandleKind::StaticGet, {"LA;", kSplitPair, "I"})),
        1u);
}

TEST(Pools, methodHandle_whenHandleWasNotCollected_failsWithAnInternalError)
{
    Pools pools;
    pools.add_method_handle(field_handle(MethodHandleKind::StaticGet, {"LA;", "f", "I"}));
    pools.finish();

    Error error = write_failure([&] {
        (void)pools.method_handle(field_handle(MethodHandleKind::StaticPut, {"LA;", "f", "I"}));
    });

    EXPECT_EQ(error.kind, Error::Kind::Invalid);
    EXPECT_EQ(error.message, "internal error: a method handle was not collected");
}

TEST(Pools, finish_whenThereAre65535Types_numbersThemAll)
{
    Pools pools = pools_with_types(65535);

    pools.finish();

    EXPECT_EQ(pools.types().size(), 65535u);
}

TEST(Pools, finish_whenThereAre65536Types_failsWithTooLarge)
{
    Pools pools = pools_with_types(65536);

    Error error = write_failure([&] { pools.finish(); });

    EXPECT_EQ(error.kind, Error::Kind::TooLarge);
    EXPECT_EQ(error.message, "65536 types; a DEX file holds at most 65535");
}

TEST(Pools, finish_whenThereAre65535Prototypes_numbersThemAll)
{
    Pools pools = pools_with_protos(65535);

    pools.finish();

    EXPECT_EQ(pools.protos().size(), 65535u);
}

TEST(Pools, finish_whenThereAre65536Prototypes_failsWithTooLarge)
{
    Pools pools = pools_with_protos(65536);

    Error error = write_failure([&] { pools.finish(); });

    EXPECT_EQ(error.kind, Error::Kind::TooLarge);
    EXPECT_EQ(error.message, "65536 prototypes; a DEX file holds at most 65535");
}

TEST(Pools, finish_whenThereAre65536Fields_numbersThemAll)
{
    Pools pools = pools_with_fields(65536);

    pools.finish();

    EXPECT_EQ(pools.fields().size(), 65536u);
}

TEST(Pools, finish_whenThereAre65537Fields_failsWithTooLarge)
{
    Pools pools = pools_with_fields(65537);

    Error error = write_failure([&] { pools.finish(); });

    EXPECT_EQ(error.kind, Error::Kind::TooLarge);
    EXPECT_EQ(error.message, "65537 field references; a DEX file holds at most 65536");
}

TEST(Pools, finish_whenThereAre65536Methods_numbersThemAll)
{
    Pools pools = pools_with_methods(65536);

    pools.finish();

    EXPECT_EQ(pools.methods().size(), 65536u);
}

TEST(Pools, finish_whenThereAre65537Methods_failsWithTooLarge)
{
    Pools pools = pools_with_methods(65537);

    Error error = write_failure([&] { pools.finish(); });

    EXPECT_EQ(error.kind, Error::Kind::TooLarge);
    EXPECT_EQ(error.message, "65537 method references; a DEX file holds at most 65536");
}

TEST(Pools, finish_whenThereAre65536MethodHandles_numbersThemAll)
{
    Pools pools = pools_with_method_handles(65536);

    pools.finish();

    EXPECT_EQ(pools.method_handles().size(), 65536u);
}

TEST(Pools, finish_whenThereAre65537MethodHandles_failsWithTooLarge)
{
    Pools pools = pools_with_method_handles(65537);

    Error error = write_failure([&] { pools.finish(); });

    EXPECT_EQ(error.kind, Error::Kind::TooLarge);
    EXPECT_EQ(error.message, "65537 method handles; a DEX file holds at most 65536");
}

TEST(Pools, finish_whenThereAreMoreThan65536Strings_numbersThemAll)
{
    Pools pools;
    for (int i = 0; i < 70000; ++i)
        pools.add_string(std::format("s{:05}", i));

    pools.finish();

    EXPECT_EQ(pools.strings().size(), 70000u);
    EXPECT_EQ(pools.string("s69999"), 69999u);
}

TEST(Pools, finish_whenAProtoCannotBeParsed_failsWithInvalid)
{
    Pools pools;
    pools.add_proto("not a prototype");

    Error error = write_failure([&] { pools.finish(); });

    EXPECT_EQ(error.kind, Error::Kind::Invalid);
    EXPECT_EQ(error.message, "\"not a prototype\" is not a prototype");
}

TEST(Pools, sortByKey_whenGivenASet_fillsTheOutputInKeyOrder)
{
    const std::unordered_set<int> set{3, 1, 2};
    std::vector<int> out;

    Pools::sort_by_key(out, set, [](const int &x) { return -x; });

    EXPECT_EQ(out, (std::vector<int>{3, 2, 1}));
}

TEST(Pools, sortByKey_whenTheOutputHoldsItems_replacesThem)
{
    const std::unordered_set<int> set{5};
    std::vector<int> out{7, 8, 9};

    Pools::sort_by_key(out, set, [](const int &x) { return x; });

    EXPECT_EQ(out, (std::vector<int>{5}));
}

TEST(Pools, memo_whenAValueIsLookedUpTwice_callsTheLookupOnce)
{
    const Shared<std::string> text = "text";
    Pools pools;
    int calls = 0;
    auto lookup = [&](const std::string &) {
        ++calls;
        return 42u;
    };

    uint32_t first = pools.memo(Pools::kString, text, lookup);
    uint32_t second = pools.memo(Pools::kString, text, lookup);

    EXPECT_EQ(first, 42u);
    EXPECT_EQ(second, 42u);
    EXPECT_EQ(calls, 1);
}

TEST(Pools, memo_whenCopiesShareOneAllocation_callsTheLookupOnce)
{
    const Shared<std::string> text = "text";
    const Shared<std::string> copy = text;
    Pools pools;
    int calls = 0;
    auto lookup = [&](const std::string &) {
        ++calls;
        return 42u;
    };

    pools.memo(Pools::kString, text, lookup);
    pools.memo(Pools::kString, copy, lookup);

    EXPECT_EQ(calls, 1);
}

TEST(Pools, memo_whenTheSameValueIsLookedUpInAnotherPool_callsTheLookupAgain)
{
    const Shared<std::string> shared = "LA;";
    Pools pools;

    uint32_t as_string = pools.memo(Pools::kString, shared, [](const std::string &) { return 1u; });
    uint32_t as_type = pools.memo(Pools::kType, shared, [](const std::string &) { return 2u; });

    EXPECT_EQ(as_string, 1u);
    EXPECT_EQ(as_type, 2u);
}

TEST(Pools, memo_whenEqualValuesAreSeparateAllocations_looksUpEach)
{
    const Shared<std::string> one = "text";
    const Shared<std::string> other = "text";
    Pools pools;
    int calls = 0;
    auto lookup = [&](const std::string &) {
        ++calls;
        return 42u;
    };

    pools.memo(Pools::kString, one, lookup);
    pools.memo(Pools::kString, other, lookup);

    EXPECT_EQ(calls, 2);
}

TEST(Pools, id_whenSitesHaveNoShareKey_numbersThemInOrderOfFirstUse)
{
    const CallSite first = call_site(0);
    const CallSite second = call_site(0);
    CallSites sites;

    EXPECT_EQ(sites.id(first), 0u);
    EXPECT_EQ(sites.id(second), 1u);
}

TEST(Pools, id_whenTheSameSiteWithoutAShareKeyIsUsedTwice_returnsANewIdEachTime)
{
    const CallSite site = call_site(0);
    CallSites sites;

    EXPECT_EQ(sites.id(site), 0u);
    EXPECT_EQ(sites.id(site), 1u);
}

TEST(Pools, id_whenSitesHaveTheSameShareKeyAndContents_returnsOneId)
{
    const CallSite first = call_site(7);
    const CallSite second = call_site(7);
    CallSites sites;

    EXPECT_EQ(sites.id(first), 0u);
    EXPECT_EQ(sites.id(second), 0u);
    EXPECT_EQ(sites.list().size(), 1u);
}

TEST(Pools, id_whenSitesHaveTheSameShareKeyButOtherContents_returnsTwoIds)
{
    const CallSite first = call_site(7);
    CallSite second = call_site(7);
    second.method_name = "other";
    CallSites sites;

    EXPECT_EQ(sites.id(first), 0u);
    EXPECT_EQ(sites.id(second), 1u);
}

TEST(Pools, id_whenSitesHaveTheSameContentsButOtherShareKeys_returnsTwoIds)
{
    const CallSite first = call_site(7);
    const CallSite second = call_site(8);
    CallSites sites;

    EXPECT_EQ(sites.id(first), 0u);
    EXPECT_EQ(sites.id(second), 1u);
}

TEST(Pools, id_whenASharedSiteIsUsedAgainAfterOthers_returnsItsFirstId)
{
    const CallSite shared = call_site(7);
    const CallSite other = call_site(0);
    CallSites sites;
    sites.id(other);
    sites.id(shared);
    sites.id(other);

    EXPECT_EQ(sites.id(shared), 1u);
    EXPECT_EQ(sites.list().size(), 3u);
}

TEST(Pools, id_whenTwoSitesShareAKeyWithDifferentContents_findsEachAgain)
{
    const CallSite first = call_site(7);
    CallSite second = call_site(7);
    second.method_name = "other";
    CallSites sites;
    sites.id(first);
    sites.id(second);

    EXPECT_EQ(sites.id(first), 0u);
    EXPECT_EQ(sites.id(second), 1u);
}

TEST(Pools, list_whenNoSiteWasNumbered_isEmpty)
{
    CallSites sites;

    EXPECT_TRUE(sites.list().empty());
}

TEST(Pools, list_whenSitesWereNumbered_holdsThemInIdOrder)
{
    const CallSite first = call_site(0);
    const CallSite second = call_site(5);
    CallSites sites;
    sites.id(first);
    sites.id(second);

    EXPECT_EQ(sites.list(), (std::vector<const CallSite *>{&first, &second}));
}

} // namespace
} // namespace dexsplit::model::detail
