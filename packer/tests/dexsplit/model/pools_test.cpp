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

} // namespace
} // namespace dexsplit::model::detail
