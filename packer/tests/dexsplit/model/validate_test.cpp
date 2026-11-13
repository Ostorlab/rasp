// Tests for validate() and required_version().

#include "model/io.hpp"

#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <ios>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "common/access_flags.hpp"
#include "common/annotation_visibility.hpp"
#include "common/ids.hpp"
#include "model/rules.hpp"
#include "model/types.hpp"
#include "support/fixtures.hpp"

namespace dexsplit::model {
namespace {

constexpr AccessFlags kNoFlags{};
const AccessFlags kPublicStaticFinal =
    AccessFlags::Public | AccessFlags::Static | AccessFlags::Final;
const char *const kInvalidUtf8 = "\xC3";

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

Dex valid_interface(uint32_t version)
{
    Dex dex = valid();
    dex.version = version;
    cls(dex).access = AccessFlags::Public | AccessFlags::Interface | AccessFlags::Abstract;
    return dex;
}

FieldDef field(std::string name, std::string type, AccessFlags access)
{
    FieldDef f;
    f.name = std::move(name);
    f.type = std::move(type);
    f.access = access;
    return f;
}

Dex with_field(FieldDef f)
{
    Dex dex = valid();
    cls(dex).fields.push_back(std::move(f));
    return dex;
}

Dex with_static_field(std::string type, Value initial_value)
{
    FieldDef f = field("x", std::move(type), AccessFlags::Static);
    f.initial_value = std::move(initial_value);
    return with_field(std::move(f));
}

AnnotationItem annotation(std::string type, std::vector<NamedValue> elements = {})
{
    AnnotationItem a;
    a.annotation.type = std::move(type);
    a.annotation.elements = std::move(elements);
    return a;
}

Dex with_annotation_value(Value value)
{
    Dex dex = valid();
    cls(dex).annotations = {annotation("LA;", {{"x", std::move(value)}})};
    return dex;
}

Value nested_arrays(int depth)
{
    Value value{Value::Int{1}};
    for (int i = 0; i < depth; ++i)
        value = Value{Value::Array{{std::move(value)}}};
    return value;
}

bool reports(const Dex &dex, std::string_view text)
{
    for (const Problem &p : validate(dex))
        if (p.message.find(text) != std::string::npos)
            return true;
    return false;
}

std::vector<std::string> where_reported(const Dex &dex, std::string_view text)
{
    std::vector<std::string> out;
    for (const Problem &p : validate(dex))
        if (p.message.find(text) != std::string::npos)
            out.push_back(p.where);
    return out;
}

TEST(Validate, validate_whenModelIsValid_returnsNoProblems)
{
    EXPECT_TRUE(validate(valid()).empty());
}

TEST(Validate, validate_whenDexHasNoClasses_returnsNoProblems)
{
    EXPECT_TRUE(validate(Dex{}).empty());
}

TEST(Validate, validate_whenVersionIsADexVersion_returnsNoProblems)
{
    for (uint32_t version : {35u, 37u, 38u, 39u, 40u}) {
        Dex dex = valid();
        dex.version = version;

        EXPECT_TRUE(validate(dex).empty()) << "version " << version;
    }
}

TEST(Validate, validate_whenVersionIsNotADexVersion_reportsItForTheWholeFile)
{
    Dex dex = valid();
    dex.version = 36;

    std::vector<Problem> problems = validate(dex);

    ASSERT_EQ(problems.size(), 1u);
    EXPECT_EQ(problems[0].where, "");
    EXPECT_EQ(problems[0].message, "unsupported DEX version 36 (use 35, 37, 38, 39 or 40)");
}

TEST(Validate, validate_whenVersionIs41_reportsTheVersion)
{
    Dex dex = valid();
    dex.version = 41;

    EXPECT_TRUE(reports(dex, "unsupported DEX version 41"));
}

TEST(Validate, validate_whenVersionIsNotADexVersion_appliesTheStrictRules)
{
    Dex dex = valid();
    dex.version = 36;
    method(dex).name = "<clinit>";
    method(dex).access = AccessFlags::Public | AccessFlags::Constructor;

    EXPECT_TRUE(reports(dex, "<clinit> must be static"));
}

TEST(Validate, validate_whenModelBreaksTwoRules_reportsBoth)
{
    Dex dex = valid();
    method(dex).name = "<foo>";
    cls(dex).interfaces = {"bad"};

    std::vector<Problem> problems = validate(dex);

    EXPECT_EQ(problems.size(), 2u);
}

TEST(Validate, requiredVersion_whenModelUsesNoNewerFeature_returns35)
{
    EXPECT_EQ(required_version(valid()), 35u);
}

TEST(Validate, requiredVersion_whenTheModelVersionIsHigher_stillReturnsTheLowestVersion)
{
    Dex dex = valid();
    dex.version = 39;

    EXPECT_EQ(required_version(dex), 35u);
}

TEST(Validate, check_whenModelUsesNoNewerFeature_returnsNoReason)
{
    detail::Checked checked = detail::check(valid());

    EXPECT_TRUE(checked.problems.empty());
    EXPECT_EQ(checked.needed_version, 35u);
    EXPECT_EQ(checked.needed_reason, "");
}

TEST(Validate, check_whenModelBreaksARule_returnsTheProblemsOfValidate)
{
    Dex dex = valid();
    cls(dex).interfaces = {"bad"};

    detail::Checked checked = detail::check(dex);

    ASSERT_EQ(checked.problems.size(), 1u);
    EXPECT_EQ(checked.problems[0].where, "LT;");
    EXPECT_EQ(checked.problems[0].message, "invalid class descriptor \"bad\"");
}

TEST(Validate, check_whenAMemberNeedsANewerVersion_returnsWhereAndWhy)
{
    Dex dex = valid_interface(35);
    method(dex).access = AccessFlags::Public;

    detail::Checked checked = detail::check(dex);

    EXPECT_EQ(checked.needed_version, 37u);
    EXPECT_EQ(checked.needed_reason, "LT;->m()V: a private or default interface method");
}

TEST(Validate, validate_whenAClassIsDefinedTwice_reportsIt)
{
    Dex dex = valid();
    ClassDef copy = cls(dex);
    dex.classes.push_back(copy);

    EXPECT_EQ(where_reported(dex, "the class is defined twice"), (std::vector<std::string>{"LT;"}));
}

TEST(Validate, validate_whenAClassTypeIsNotAClassDescriptor_reportsIt)
{
    Dex dex = valid();
    cls(dex).type = "T";

    EXPECT_TRUE(reports(dex, "invalid class descriptor \"T\""));
}

TEST(Validate, validate_whenAClassTypeIsAnArray_reportsIt)
{
    Dex dex = valid();
    cls(dex).type = "[LT;";

    EXPECT_TRUE(reports(dex, "invalid class descriptor \"[LT;\""));
}

TEST(Validate, validate_whenAClassNameHasASpace_returnsNoProblems)
{
    Dex dex = valid();
    cls(dex).type = "Lwith space;";

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenClassAccessFlagsHaveABitAboveTheJavaFlags_reportsThem)
{
    Dex dex = valid();
    cls(dex).access = static_cast<AccessFlags>(0x10000);

    EXPECT_TRUE(reports(dex, "invalid class access flags 0x10000"));
}

TEST(Validate, validate_whenAClassOtherThanObjectHasNoSuperclass_reportsIt)
{
    Dex dex = valid();
    cls(dex).superclass.reset();

    EXPECT_TRUE(reports(dex, "only java.lang.Object may have no superclass"));
}

TEST(Validate, validate_whenObjectHasNoSuperclass_returnsNoProblems)
{
    Dex dex = valid();
    cls(dex).type = "Ljava/lang/Object;";
    cls(dex).superclass.reset();

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenASuperclassIsNotAClassDescriptor_reportsIt)
{
    Dex dex = valid();
    cls(dex).superclass = "[I";

    EXPECT_TRUE(reports(dex, "invalid class descriptor \"[I\""));
}

TEST(Validate, validate_whenAClassIsItsOwnSuperclass_reportsIt)
{
    Dex dex = valid();
    cls(dex).superclass = "LT;";

    EXPECT_TRUE(reports(dex, "the class is its own superclass"));
}

TEST(Validate, validate_whenAnInterfaceIsNotAClassDescriptor_reportsIt)
{
    Dex dex = valid();
    cls(dex).interfaces = {"bad"};

    EXPECT_TRUE(reports(dex, "invalid class descriptor \"bad\""));
}

TEST(Validate, validate_whenAClassImplementsItself_reportsIt)
{
    Dex dex = valid();
    cls(dex).interfaces = {"LT;"};

    EXPECT_TRUE(reports(dex, "the class implements itself"));
}

TEST(Validate, validate_whenAnInterfaceIsListedTwice_reportsIt)
{
    Dex dex = valid();
    cls(dex).interfaces = {"LI;", "LI;"};

    EXPECT_TRUE(reports(dex, "interface LI; is listed twice"));
}

TEST(Validate, validate_whenAClassImplementsTwoInterfaces_returnsNoProblems)
{
    Dex dex = valid();
    cls(dex).interfaces = {"LI;", "LJ;"};

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenTheSourceFileNameIsNotValidUtf8_reportsIt)
{
    Dex dex = valid();
    cls(dex).source_file = kInvalidUtf8;

    EXPECT_TRUE(reports(dex, "the source file name is not valid UTF-8 / WTF-8"));
}

TEST(Validate, validate_whenAClassHasASourceFileName_returnsNoProblems)
{
    Dex dex = valid();
    cls(dex).source_file = "T.java";

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenAClassBreaksARule_namesTheClassInWhere)
{
    Dex dex = valid();
    cls(dex).superclass.reset();

    EXPECT_EQ(where_reported(dex, "may have no superclass"), (std::vector<std::string>{"LT;"}));
}

TEST(Validate, validate_whenTwoClassesExtendEachOther_reportsACycleForBoth)
{
    Dex dex = valid();
    ClassDef other = cls(dex);
    other.type = "LU;";
    other.superclass = "LT;";
    cls(dex).superclass = "LU;";
    dex.classes.push_back(other);

    EXPECT_EQ(where_reported(dex, "the class is part of an inheritance cycle"),
              (std::vector<std::string>{"LT;", "LU;"}));
}

TEST(Validate, validate_whenACycleGoesThroughAnInterface_reportsIt)
{
    Dex dex = valid();
    ClassDef other = cls(dex);
    other.type = "LU;";
    other.interfaces = {"LT;"};
    cls(dex).interfaces = {"LU;"};
    dex.classes.push_back(other);

    EXPECT_EQ(where_reported(dex, "the class is part of an inheritance cycle"),
              (std::vector<std::string>{"LT;", "LU;"}));
}

TEST(Validate, validate_whenThreeClassesFormACycle_reportsAllThree)
{
    Dex dex = valid();
    ClassDef second = cls(dex);
    ClassDef third = cls(dex);
    second.type = "LU;";
    third.type = "LV;";
    cls(dex).superclass = "LU;";
    second.superclass = "LV;";
    third.superclass = "LT;";
    dex.classes.push_back(second);
    dex.classes.push_back(third);

    EXPECT_EQ(where_reported(dex, "the class is part of an inheritance cycle"),
              (std::vector<std::string>{"LT;", "LU;", "LV;"}));
}

TEST(Validate, validate_whenAClassIsItsOwnSuperclass_reportsACycleOfOne)
{
    Dex dex = valid();
    cls(dex).superclass = "LT;";

    EXPECT_EQ(where_reported(dex, "the class is part of an inheritance cycle"),
              (std::vector<std::string>{"LT;"}));
}

TEST(Validate, validate_whenAClassExtendsACycleFromOutside_reportsOnlyTheClassesInTheCycle)
{
    Dex dex = valid();
    ClassDef other = cls(dex);
    ClassDef outside = cls(dex);
    other.type = "LU;";
    other.superclass = "LT;";
    outside.type = "LV;";
    outside.superclass = "LT;";
    cls(dex).superclass = "LU;";
    dex.classes.push_back(other);
    dex.classes.push_back(outside);

    EXPECT_EQ(where_reported(dex, "the class is part of an inheritance cycle"),
              (std::vector<std::string>{"LT;", "LU;"}));
}

TEST(Validate, validate_whenTwoPathsLeadToTheSameSupertype_reportsNoCycle)
{
    Dex dex = valid();
    ClassDef left = cls(dex);
    ClassDef right = cls(dex);
    ClassDef top = cls(dex);
    left.type = "LL;";
    right.type = "LR;";
    top.type = "LTop;";
    left.interfaces = {"LTop;"};
    right.interfaces = {"LTop;"};
    cls(dex).interfaces = {"LL;", "LR;"};
    dex.classes.push_back(left);
    dex.classes.push_back(right);
    dex.classes.push_back(top);

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenAFieldIsDefinedTwice_reportsIt)
{
    Dex dex = valid();
    cls(dex).fields = {field("x", "I", kNoFlags), field("x", "I", kNoFlags)};

    EXPECT_TRUE(reports(dex, "field x:I is defined twice"));
}

TEST(Validate, validate_whenTwoFieldsShareANameButNotAType_returnsNoProblems)
{
    Dex dex = valid();
    cls(dex).fields = {field("x", "I", kNoFlags), field("x", "J", kNoFlags)};

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenAFieldNameIsNotAMemberName_reportsIt)
{
    Dex dex = with_field(field("a.b", "I", kNoFlags));

    EXPECT_TRUE(reports(dex, "invalid member name \"a.b\""));
}

TEST(Validate, validate_whenAFieldTypeIsVoid_reportsIt)
{
    Dex dex = with_field(field("x", "V", kNoFlags));

    EXPECT_TRUE(reports(dex, "invalid field type \"V\""));
}

TEST(Validate, validate_whenAFieldBreaksARule_namesTheFieldInWhere)
{
    Dex dex = with_field(field("x", "V", kNoFlags));

    EXPECT_EQ(where_reported(dex, "invalid field type"), (std::vector<std::string>{"LT;->x:V"}));
}

TEST(Validate, validate_whenFieldAccessFlagsHaveABitAboveTheJavaFlags_reportsThem)
{
    Dex dex = with_field(field("x", "I", AccessFlags::Constructor));

    EXPECT_TRUE(reports(dex, "invalid field access flags 0x10000"));
}

TEST(Validate, validate_whenAFieldHasTwoVisibilities_reportsIt)
{
    Dex dex = with_field(field("x", "I", AccessFlags::Public | AccessFlags::Private));

    EXPECT_TRUE(reports(dex, "more than one of public, protected and private"));
}

TEST(Validate, validate_whenAFieldIsVolatileAndFinal_reportsIt)
{
    Dex dex = with_field(field("x", "I", AccessFlags::Volatile | AccessFlags::Final));

    EXPECT_TRUE(reports(dex, "a field cannot be both volatile and final"));
}

TEST(Validate, validate_whenAnInstanceFieldHasAnInitialValue_reportsIt)
{
    FieldDef f = field("x", "I", kNoFlags);
    f.initial_value = Value{Value::Int{1}};
    Dex dex = with_field(f);

    EXPECT_TRUE(reports(dex, "only a static field can have an initial value"));
}

TEST(Validate, validate_whenAnInitialValueHasAnotherTypeThanItsField_reportsIt)
{
    Dex dex = with_static_field("I", Value{Value::Long{1}});

    EXPECT_TRUE(reports(dex, "the initial value's type does not match the field's type"));
}

TEST(Validate, validate_whenAnInitialValueHasTheTypeOfItsField_returnsNoProblems)
{
    const std::vector<std::pair<std::string, Value>> matching{
        {"Z", Value{Value::Boolean{true}}},
        {"B", Value{Value::Byte{1}}},
        {"S", Value{Value::Short{1}}},
        {"C", Value{Value::Char{u'a'}}},
        {"I", Value{Value::Int{1}}},
        {"J", Value{Value::Long{1}}},
        {"F", Value{Value::Float{1.0f}}},
        {"D", Value{Value::Double{1.0}}},
        {"Ljava/lang/String;", Value{Value::String{"text"}}},
        {"Ljava/lang/Class;", Value{Value::Type{"LT;"}}},
        {"Ljava/lang/Object;", Value{Value::Null{}}},
        {"[I", Value{Value::Null{}}},
    };
    for (const auto &[type, value] : matching) {
        Dex dex = with_static_field(type, value);

        EXPECT_TRUE(validate(dex).empty()) << "field type " << type;
    }
}

TEST(Validate, validate_whenAPrimitiveFieldHasANullInitialValue_reportsIt)
{
    Dex dex = with_static_field("I", Value{Value::Null{}});

    EXPECT_TRUE(reports(dex, "the initial value's type does not match the field's type"));
}

TEST(Validate, validate_whenAnInitialValueIsAnArray_reportsIt)
{
    Dex dex = with_static_field("[I", Value{Value::Array{{Value{Value::Int{1}}}}});

    EXPECT_TRUE(reports(dex, "the initial value's type does not match the field's type"));
}

TEST(Validate, validate_whenAStringInitialValueIsNotValidUtf8_reportsIt)
{
    Dex dex = with_static_field("Ljava/lang/String;", Value{Value::String{kInvalidUtf8}});

    EXPECT_TRUE(reports(dex, "a string value is not valid UTF-8 / WTF-8"));
}

TEST(Validate, validate_whenAnInterfaceFieldIsNotPublicStaticFinalInVersion37_reportsIt)
{
    Dex dex = valid_interface(37);
    cls(dex).fields = {field("x", "I", AccessFlags::Public)};

    EXPECT_TRUE(reports(dex, "an interface field must be public, static and final"));
}

TEST(Validate, validate_whenAnInterfaceFieldIsNotPublicStaticFinalInVersion35_returnsNoProblems)
{
    Dex dex = valid_interface(35);
    cls(dex).fields = {field("x", "I", AccessFlags::Public)};

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenAnInterfaceFieldIsVolatileInVersion37_reportsIt)
{
    Dex dex = valid_interface(37);
    cls(dex).fields = {field("x", "I", kPublicStaticFinal | AccessFlags::Volatile)};

    EXPECT_TRUE(reports(dex, "an interface field may only be public, static, final, synthetic"));
}

TEST(Validate, validate_whenAnInterfaceFieldIsPublicStaticFinalAndSynthetic_returnsNoProblems)
{
    Dex dex = valid_interface(37);
    cls(dex).fields = {field("x", "I", kPublicStaticFinal | AccessFlags::Synthetic)};

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenAMethodIsDefinedTwice_reportsIt)
{
    Dex dex = valid();
    MethodDef copy = method(dex);
    cls(dex).methods.push_back(copy);

    EXPECT_TRUE(reports(dex, "method m()V is defined twice"));
}

TEST(Validate, validate_whenTwoMethodsShareANameButNotAPrototype_returnsNoProblems)
{
    Dex dex = valid();
    MethodDef overload = method(dex);
    overload.proto = "(I)V";
    cls(dex).methods.push_back(overload);

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenAMethodNameIsNotAMemberName_reportsIt)
{
    Dex dex = valid();
    method(dex).name = "a;b";

    EXPECT_TRUE(reports(dex, "invalid member name \"a;b\""));
}

TEST(Validate, validate_whenAMethodNameHasASpace_returnsNoProblems)
{
    Dex dex = valid();
    method(dex).name = "with space";

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, requiredVersion_whenAMethodNameHasASpace_returns35)
{
    Dex dex = valid();
    method(dex).name = "with space";

    EXPECT_EQ(required_version(dex), 35u);
}

TEST(Validate, validate_whenAMethodOtherThanAConstructorIsNamedInAngleBrackets_reportsIt)
{
    Dex dex = valid();
    method(dex).name = "<foo>";

    EXPECT_TRUE(reports(dex, "only <init> and <clinit> may be named in angle brackets"));
}

TEST(Validate, validate_whenAMethodBreaksARule_namesTheMethodInWhere)
{
    Dex dex = valid();
    method(dex).name = "<foo>";

    EXPECT_EQ(where_reported(dex, "may be named in angle brackets"),
              (std::vector<std::string>{"LT;-><foo>()V"}));
}

TEST(Validate, validate_whenAMethodPrototypeIsNotAPrototype_reportsIt)
{
    Dex dex = valid();
    method(dex).proto = "(V)V";

    EXPECT_TRUE(reports(dex, "invalid prototype \"(V)V\""));
}

TEST(Validate, validate_whenMethodAccessFlagsHaveAnUnknownBit_reportsThem)
{
    Dex dex = valid();
    method(dex).access = static_cast<AccessFlags>(0x40009);

    EXPECT_TRUE(reports(dex, "invalid method access flags 0x40009"));
}

TEST(Validate, validate_whenAMethodIsDeclaredSynchronized_returnsNoProblems)
{
    Dex dex = valid();
    method(dex).access =
        AccessFlags::Public | AccessFlags::Static | AccessFlags::DeclaredSynchronized;

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenAMethodHasTwoVisibilities_reportsIt)
{
    Dex dex = valid();
    method(dex).access = AccessFlags::Public | AccessFlags::Protected | AccessFlags::Static;

    EXPECT_TRUE(reports(dex, "more than one of public, protected and private"));
}

TEST(Validate, validate_whenAMethodOtherThanAConstructorHasTheConstructorFlag_reportsIt)
{
    Dex dex = valid();
    method(dex).access = AccessFlags::Public | AccessFlags::Constructor;

    EXPECT_TRUE(reports(dex, "only <init> and <clinit> can be marked constructor"));
}

TEST(Validate, validate_whenInitIsAPublicConstructor_returnsNoProblems)
{
    Dex dex = valid();
    method(dex).name = "<init>";
    method(dex).access = AccessFlags::Public | AccessFlags::Constructor;

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenClinitIsAStaticConstructor_returnsNoProblems)
{
    Dex dex = valid();
    dex.version = 37;
    method(dex).name = "<clinit>";
    method(dex).access = AccessFlags::Static | AccessFlags::Constructor;

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenClinitIsNotStaticInVersion37_reportsIt)
{
    Dex dex = valid();
    dex.version = 37;
    method(dex).name = "<clinit>";
    method(dex).access = AccessFlags::Public | AccessFlags::Constructor;

    EXPECT_TRUE(reports(dex, "<clinit> must be static"));
}

TEST(Validate, validate_whenClinitIsNotStaticInVersion35_returnsNoProblems)
{
    Dex dex = valid();
    method(dex).name = "<clinit>";
    method(dex).access = AccessFlags::Public | AccessFlags::Constructor;

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenInitIsStaticInVersion37_reportsIt)
{
    Dex dex = valid();
    dex.version = 37;
    method(dex).name = "<init>";

    EXPECT_TRUE(reports(dex, "<init> must not be static"));
}

TEST(Validate, validate_whenInitIsStaticInVersion35_doesNotReportTheVersion37Rule)
{
    Dex dex = valid();
    method(dex).name = "<init>";

    EXPECT_FALSE(reports(dex, "<init> must not be static"));
}

TEST(Validate, validate_whenClinitTakesAParameter_reportsIt)
{
    Dex dex = valid();
    method(dex).name = "<clinit>";
    method(dex).proto = "(I)V";

    EXPECT_TRUE(reports(dex, "<clinit> must have the prototype ()V"));
}

TEST(Validate, validate_whenInitDoesNotReturnVoid_reportsIt)
{
    Dex dex = valid();
    method(dex).name = "<init>";
    method(dex).access = AccessFlags::Public | AccessFlags::Constructor;
    method(dex).proto = "()I";

    EXPECT_TRUE(reports(dex, "<init> must return void"));
}

TEST(Validate, validate_whenInitHasAFlagAConstructorCannotHave_reportsIt)
{
    Dex dex = valid();
    method(dex).name = "<init>";
    method(dex).access = AccessFlags::Public | AccessFlags::Final | AccessFlags::Constructor;

    EXPECT_TRUE(reports(dex, "invalid access flags for <init>"));
}

TEST(Validate, validate_whenAMethodWithoutCodeIsNotAbstractOrNative_reportsIt)
{
    Dex dex = valid();
    method(dex).code.reset();

    EXPECT_TRUE(reports(dex, "a method without code must be abstract or native"));
}

TEST(Validate, validate_whenANativeMethodHasNoCode_returnsNoProblems)
{
    Dex dex = valid();
    method(dex).access = AccessFlags::Public | AccessFlags::Static | AccessFlags::Native;
    method(dex).code.reset();

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenAnAbstractMethodHasNoCode_returnsNoProblems)
{
    Dex dex = valid();
    method(dex).access = AccessFlags::Public | AccessFlags::Abstract;
    method(dex).code.reset();

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenAConstructorHasNoCodeInVersion37_reportsIt)
{
    Dex dex = valid();
    dex.version = 37;
    method(dex).name = "<init>";
    method(dex).access = AccessFlags::Public | AccessFlags::Native | AccessFlags::Constructor;
    method(dex).code.reset();

    EXPECT_TRUE(reports(dex, "a constructor must have code"));
}

TEST(Validate, validate_whenAConstructorHasNoCodeInVersion35_returnsNoProblems)
{
    Dex dex = valid();
    method(dex).name = "<init>";
    method(dex).access = AccessFlags::Public | AccessFlags::Native | AccessFlags::Constructor;
    method(dex).code.reset();

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenAnAbstractMethodHasAFlagItCannotHave_reportsIt)
{
    for (AccessFlags flag : {AccessFlags::Private, AccessFlags::Static, AccessFlags::Final,
                             AccessFlags::Native, AccessFlags::Strict, AccessFlags::Synchronized}) {
        Dex dex = valid();
        method(dex).access = AccessFlags::Abstract | flag;
        method(dex).code.reset();

        EXPECT_TRUE(reports(dex, "an abstract method cannot be private, static, final, native, "
                                 "strictfp or synchronized"))
            << "flag 0x" << std::hex << static_cast<uint32_t>(flag);
    }
}

TEST(Validate, validate_whenAnAbstractMethodHasCode_reportsIt)
{
    Dex dex = valid();
    method(dex).access = AccessFlags::Public | AccessFlags::Abstract;

    EXPECT_TRUE(reports(dex, "an abstract or native method cannot have code"));
}

TEST(Validate, validate_whenANativeMethodHasCode_reportsIt)
{
    Dex dex = valid();
    method(dex).access = AccessFlags::Public | AccessFlags::Static | AccessFlags::Native;

    EXPECT_TRUE(reports(dex, "an abstract or native method cannot have code"));
}

TEST(Validate, requiredVersion_whenAnInterfaceHasADefaultMethod_returns37)
{
    Dex dex = valid_interface(35);
    method(dex).access = AccessFlags::Public;

    EXPECT_EQ(required_version(dex), 37u);
}

TEST(Validate, requiredVersion_whenAnInterfaceHasAPrivateMethod_returns37)
{
    Dex dex = valid_interface(35);
    method(dex).access = AccessFlags::Private | AccessFlags::Static;

    EXPECT_EQ(required_version(dex), 37u);
}

TEST(Validate, requiredVersion_whenAnInterfaceHasAStaticMethod_returns35)
{
    Dex dex = valid_interface(35);

    EXPECT_EQ(required_version(dex), 35u);
}

TEST(Validate, requiredVersion_whenAnInterfaceHasOnlyAnAbstractMethod_returns35)
{
    Dex dex = valid_interface(35);
    method(dex).access = AccessFlags::Public | AccessFlags::Abstract;
    method(dex).code.reset();

    EXPECT_EQ(required_version(dex), 35u);
}

TEST(Validate, requiredVersion_whenAnInterfaceHasAPrivateStaticInitializer_returns35)
{
    Dex dex = valid_interface(35);
    method(dex).name = "<clinit>";
    method(dex).access = AccessFlags::Private | AccessFlags::Static | AccessFlags::Constructor;

    EXPECT_EQ(required_version(dex), 35u);
}

TEST(Validate, requiredVersion_whenAClassHasAPrivateMethod_returns35)
{
    Dex dex = valid();
    method(dex).access = AccessFlags::Private;

    EXPECT_EQ(required_version(dex), 35u);
}

TEST(Validate, validate_whenAnInterfaceHasADefaultMethodInVersion37_returnsNoProblems)
{
    Dex dex = valid_interface(37);
    method(dex).access = AccessFlags::Public;

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenAnInterfaceHasADefaultMethodInVersion35_returnsNoProblems)
{
    Dex dex = valid_interface(35);
    method(dex).access = AccessFlags::Public;

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenAnInterfaceHasAStaticMethodInVersion35_returnsNoProblems)
{
    Dex dex = valid_interface(35);

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenAnInterfaceMethodIsOnlyProtectedInVersion37_reportsIt)
{
    Dex dex = valid_interface(37);
    method(dex).access = AccessFlags::Protected;

    EXPECT_TRUE(reports(dex, "an interface method must be public, private or static"));
}

TEST(Validate, validate_whenAnInterfaceMethodIsOnlyProtectedInVersion35_returnsNoProblems)
{
    Dex dex = valid_interface(35);
    method(dex).access = AccessFlags::Protected;

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenAnInterfaceMethodWithoutCodeIsNotPublicInVersion37_reportsIt)
{
    Dex dex = valid_interface(37);
    method(dex).access = AccessFlags::Abstract;
    method(dex).code.reset();

    EXPECT_TRUE(reports(dex, "an interface method without code must be public and abstract"));
}

TEST(Validate, validate_whenAnInterfaceMethodWithoutCodeIsNotPublicInVersion35_returnsNoProblems)
{
    Dex dex = valid_interface(35);
    method(dex).access = AccessFlags::Abstract;
    method(dex).code.reset();

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenAnInterfaceMethodIsPublicAndAbstractInVersion37_returnsNoProblems)
{
    Dex dex = valid_interface(37);
    method(dex).access = AccessFlags::Public | AccessFlags::Abstract;
    method(dex).code.reset();

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenAnAnnotationIsWellFormed_returnsNoProblems)
{
    Dex dex = valid();
    cls(dex).annotations = {
        annotation("LA;", {{"x", Value{Value::Int{1}}}, {"y", Value{Value::String{"text"}}}}),
        annotation("LB;"),
    };

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenAnAnnotationSetsAnElementTwice_reportsIt)
{
    Dex dex = valid();
    cls(dex).annotations = {
        annotation("LA;", {{"x", Value{Value::Int{1}}}, {"x", Value{Value::Int{2}}}})};

    EXPECT_TRUE(reports(dex, "annotation LA; sets element \"x\" twice"));
}

TEST(Validate, validate_whenAnAnnotationTypeIsPresentTwice_reportsIt)
{
    Dex dex = valid();
    cls(dex).annotations = {annotation("LA;"), annotation("LA;")};

    EXPECT_TRUE(reports(dex, "annotation LA; is present twice"));
}

TEST(Validate, validate_whenAnAnnotationVisibilityIsUnknown_reportsIt)
{
    Dex dex = valid();
    AnnotationItem a = annotation("LA;");
    a.visibility = static_cast<AnnotationVisibility>(3);
    cls(dex).annotations = {a};

    EXPECT_TRUE(reports(dex, "bad annotation visibility"));
}

TEST(Validate, validate_whenAnAnnotationHasEachKnownVisibility_returnsNoProblems)
{
    Dex dex = valid();
    AnnotationItem build = annotation("LA;");
    AnnotationItem runtime = annotation("LB;");
    AnnotationItem system = annotation("LC;");
    build.visibility = AnnotationVisibility::Build;
    runtime.visibility = AnnotationVisibility::Runtime;
    system.visibility = AnnotationVisibility::System;
    cls(dex).annotations = {build, runtime, system};

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenAnAnnotationTypeIsNotAClassDescriptor_reportsIt)
{
    Dex dex = valid();
    cls(dex).annotations = {annotation("[I")};

    EXPECT_TRUE(reports(dex, "invalid class descriptor \"[I\""));
}

TEST(Validate, validate_whenAnAnnotationElementNameIsNotAMemberName_reportsIt)
{
    Dex dex = valid();
    cls(dex).annotations = {annotation("LA;", {{"a.b", Value{Value::Int{1}}}})};

    EXPECT_TRUE(reports(dex, "invalid member name \"a.b\""));
}

TEST(Validate, validate_whenAFieldAnnotationBreaksARule_namesTheFieldInWhere)
{
    FieldDef f = field("x", "I", kNoFlags);
    f.annotations = {annotation("LA;"), annotation("LA;")};
    Dex dex = with_field(f);

    EXPECT_EQ(where_reported(dex, "annotation LA; is present twice"),
              (std::vector<std::string>{"LT;->x:I"}));
}

TEST(Validate, validate_whenAMethodAnnotationBreaksARule_namesTheMethodInWhere)
{
    Dex dex = valid();
    method(dex).annotations = {annotation("LA;"), annotation("LA;")};

    EXPECT_EQ(where_reported(dex, "annotation LA; is present twice"),
              (std::vector<std::string>{"LT;->m()V"}));
}

TEST(Validate, validate_whenAParameterAnnotationBreaksARule_namesTheMethodInWhere)
{
    Dex dex = valid();
    method(dex).parameter_annotations = {{}, {annotation("LA;"), annotation("LA;")}};

    EXPECT_EQ(where_reported(dex, "annotation LA; is present twice"),
              (std::vector<std::string>{"LT;->m()V"}));
}

TEST(Validate, validate_whenTwoParametersCarryTheSameAnnotationType_returnsNoProblems)
{
    Dex dex = valid();
    method(dex).parameter_annotations = {{annotation("LA;")}, {annotation("LA;")}};

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenAStringValueIsNotValidUtf8_reportsIt)
{
    Dex dex = with_annotation_value(Value{Value::String{kInvalidUtf8}});

    EXPECT_TRUE(reports(dex, "a string value is not valid UTF-8 / WTF-8"));
}

TEST(Validate, validate_whenAStringValueHasAnUnpairedSurrogate_returnsNoProblems)
{
    Dex dex = with_annotation_value(Value{Value::String{"\xED\xA0\x80"}});

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenATypeValueIsNotATypeDescriptor_reportsIt)
{
    Dex dex = with_annotation_value(Value{Value::Type{"Q"}});

    EXPECT_TRUE(reports(dex, "invalid type descriptor \"Q\""));
}

TEST(Validate, validate_whenATypeValueIsVoid_returnsNoProblems)
{
    Dex dex = with_annotation_value(Value{Value::Type{"V"}});

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenAFieldValueNamesAnInvalidClass_reportsIt)
{
    Dex dex = with_annotation_value(Value{Value::Field{FieldId{"T", "f", "I"}}});

    EXPECT_TRUE(reports(dex, "invalid class descriptor \"T\""));
}

TEST(Validate, validate_whenAFieldValueHasAnInvalidName_reportsIt)
{
    Dex dex = with_annotation_value(Value{Value::Field{FieldId{"LT;", "a.b", "I"}}});

    EXPECT_TRUE(reports(dex, "invalid member name \"a.b\""));
}

TEST(Validate, validate_whenAFieldValueHasAnInvalidType_reportsIt)
{
    Dex dex = with_annotation_value(Value{Value::Field{FieldId{"LT;", "f", "V"}}});

    EXPECT_TRUE(reports(dex, "invalid field type \"V\""));
}

TEST(Validate, validate_whenAnEnumValueNamesAnInvalidField_reportsIt)
{
    Dex dex = with_annotation_value(Value{Value::Enum{FieldId{"LT;", "a.b", "LT;"}}});

    EXPECT_TRUE(reports(dex, "invalid member name \"a.b\""));
}

TEST(Validate, validate_whenAnEnumValueNamesAValidField_returnsNoProblems)
{
    Dex dex = with_annotation_value(Value{Value::Enum{FieldId{"LE;", "RED", "LE;"}}});

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenAMethodValueNamesAPrimitiveClass_reportsIt)
{
    Dex dex = with_annotation_value(Value{Value::Method{MethodId{"I", "m", "()V"}}});

    EXPECT_TRUE(reports(dex, "invalid method class \"I\""));
}

TEST(Validate, validate_whenAMethodValueNamesAnArrayClass_returnsNoProblems)
{
    Dex dex = with_annotation_value(
        Value{Value::Method{MethodId{"[I", "clone", "()Ljava/lang/Object;"}}});

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenAMethodValueHasAnInvalidName_reportsIt)
{
    Dex dex = with_annotation_value(Value{Value::Method{MethodId{"LT;", "a.b", "()V"}}});

    EXPECT_TRUE(reports(dex, "invalid member name \"a.b\""));
}

TEST(Validate, validate_whenAMethodValueHasAnInvalidPrototype_reportsIt)
{
    Dex dex = with_annotation_value(Value{Value::Method{MethodId{"LT;", "m", "(V)V"}}});

    EXPECT_TRUE(reports(dex, "invalid prototype \"(V)V\""));
}

TEST(Validate, validate_whenAMethodTypeValueIsNotAPrototype_reportsIt)
{
    Dex dex = with_annotation_value(Value{Value::MethodType{"(V)V"}});

    EXPECT_TRUE(reports(dex, "invalid prototype \"(V)V\""));
}

TEST(Validate, requiredVersion_whenAValueIsAMethodType_returns38)
{
    Dex dex = with_annotation_value(Value{Value::MethodType{"()V"}});

    EXPECT_EQ(required_version(dex), 38u);
}

TEST(Validate, requiredVersion_whenAValueIsAMethodHandle_returns38)
{
    Dex dex = with_annotation_value(
        Value{MethodHandle{MethodHandleKind::InvokeStatic, MethodId{"LT;", "m", "()V"}}});

    EXPECT_EQ(required_version(dex), 38u);
}

TEST(Validate, requiredVersion_whenAnInitialValueIsAMethodType_returns38)
{
    Dex dex = with_static_field("Ljava/lang/invoke/MethodType;", Value{Value::MethodType{"()V"}});

    EXPECT_EQ(required_version(dex), 38u);
}

TEST(Validate, requiredVersion_whenFeaturesNeedDifferentVersions_returnsTheHighest)
{
    Dex dex = valid_interface(35);
    method(dex).access = AccessFlags::Public;
    cls(dex).annotations = {annotation("LA;", {{"x", Value{Value::MethodType{"()V"}}}})};

    EXPECT_EQ(required_version(dex), 38u);
}

TEST(Validate, validate_whenAMethodHandleValueIsWellFormed_returnsNoProblems)
{
    Dex dex = with_annotation_value(
        Value{MethodHandle{MethodHandleKind::InvokeStatic, MethodId{"LT;", "m", "()V"}}});

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenAMethodHandleKindIsUnknown_reportsIt)
{
    Dex dex = with_annotation_value(
        Value{MethodHandle{static_cast<MethodHandleKind>(9), MethodId{"LT;", "m", "()V"}}});

    EXPECT_TRUE(reports(dex, "bad method handle kind 9"));
}

TEST(Validate, validate_whenAFieldMethodHandleNamesAMethod_reportsIt)
{
    Dex dex = with_annotation_value(
        Value{MethodHandle{MethodHandleKind::StaticGet, MethodId{"LT;", "m", "()V"}}});

    EXPECT_TRUE(reports(dex, "a field method handle names a method"));
}

TEST(Validate, validate_whenAnInvokeMethodHandleNamesAField_reportsIt)
{
    Dex dex = with_annotation_value(
        Value{MethodHandle{MethodHandleKind::InvokeStatic, FieldId{"LT;", "f", "I"}}});

    EXPECT_TRUE(reports(dex, "an invoke method handle names a field"));
}

TEST(Validate, validate_whenAMethodHandleNamesAnInvalidMethod_reportsIt)
{
    Dex dex = with_annotation_value(
        Value{MethodHandle{MethodHandleKind::InvokeStatic, MethodId{"LT;", "a.b", "()V"}}});

    EXPECT_TRUE(reports(dex, "invalid member name \"a.b\""));
}

TEST(Validate, validate_whenAMethodHandleNamesAnInvalidField_reportsIt)
{
    Dex dex = with_annotation_value(
        Value{MethodHandle{MethodHandleKind::InstanceGet, FieldId{"LT;", "f", "V"}}});

    EXPECT_TRUE(reports(dex, "invalid field type \"V\""));
}

TEST(Validate, validate_whenAnArrayValueHoldsAnInvalidValue_reportsIt)
{
    Dex dex =
        with_annotation_value(Value{Value::Array{{Value{Value::Int{1}}, Value{Value::Type{"Q"}}}}});

    EXPECT_TRUE(reports(dex, "invalid type descriptor \"Q\""));
}

TEST(Validate, validate_whenANestedAnnotationHasAnInvalidType_reportsIt)
{
    Dex dex = with_annotation_value(Value{Shared<EncodedAnnotation>(EncodedAnnotation{"[I", {}})});

    EXPECT_TRUE(reports(dex, "invalid class descriptor \"[I\""));
}

TEST(Validate, validate_whenANestedAnnotationSetsAnElementTwice_reportsIt)
{
    Dex dex = with_annotation_value(Value{Shared<EncodedAnnotation>(
        EncodedAnnotation{"LB;", {{"y", Value{Value::Int{1}}}, {"y", Value{Value::Int{2}}}}})});

    EXPECT_TRUE(reports(dex, "annotation LB; sets element \"y\" twice"));
}

TEST(Validate, validate_whenValuesNest64Levels_returnsNoProblems)
{
    Dex dex = with_annotation_value(nested_arrays(64));

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenValuesNest65Levels_reportsIt)
{
    Dex dex = with_annotation_value(nested_arrays(65));

    EXPECT_TRUE(reports(dex, "values nest too deeply"));
}

const Label kLabel{0};
const Label kOtherLabel{1};
const Label kThirdLabel{2};
const Label kUnplacedLabel{9};

Code &code(Dex &dex) { return *dex.classes[0].methods[0].code; }

Dex with_items(std::vector<Item> items, Reg registers = 4)
{
    Dex dex = valid();
    code(dex).registers = registers;
    code(dex).items = std::move(items);
    return dex;
}

Dex with_insn(Insn insn, Reg registers = 4)
{
    return with_items({std::move(insn), kLabel, Insn{ReturnVoid{}}}, registers);
}

Dex with_try(std::vector<Item> items, TryRange range)
{
    Dex dex = with_items(std::move(items));
    code(dex).tries = {std::move(range)};
    return dex;
}

CallSite call_site()
{
    CallSite site;
    site.bootstrap =
        MethodHandle{MethodHandleKind::InvokeStatic, MethodId{"LT;", "bootstrap", "()V"}};
    site.method_name = "run";
    site.method_type = "()V";
    return site;
}

TEST(Validate, validate_whenRegistersEqualTheArgumentWords_returnsNoProblems)
{
    Dex dex = valid();
    method(dex).proto = "(JJ)V";

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenRegistersAreFewerThanTheArgumentWords_reportsIt)
{
    Dex dex = valid();
    method(dex).proto = "(JJI)V";

    EXPECT_TRUE(reports(dex, "4 registers cannot hold the 5 argument words"));
}

TEST(Validate, validate_whenAnInstanceMethodHasNoRegisterForThis_reportsIt)
{
    Dex dex = valid();
    method(dex).access = AccessFlags::Public;
    code(dex).registers = 0;

    EXPECT_TRUE(reports(dex, "0 registers cannot hold the 1 argument words"));
}

TEST(Validate, validate_whenThePrototypeIsInvalid_doesNotCountItsArgumentWords)
{
    Dex dex = valid();
    method(dex).proto = "(JJI";
    code(dex).registers = 0;

    EXPECT_FALSE(reports(dex, "argument words"));
}

TEST(Validate, validate_whenCodeHasNoItems_reportsNoInstructions)
{
    Dex dex = with_items({});

    EXPECT_EQ(where_reported(dex, "the code has no instructions"),
              (std::vector<std::string>{"LT;->m()V"}));
}

TEST(Validate, validate_whenCodeHasOnlyLabelsAndDebugItems_reportsNoInstructions)
{
    Dex dex = with_items({kLabel, LineNumber{1}});

    EXPECT_TRUE(reports(dex, "the code has no instructions"));
}

TEST(Validate, validate_whenABranchTargetIsNotPlaced_reportsIt)
{
    Dex dex = with_items({Insn{Goto{kLabel}}});

    EXPECT_TRUE(reports(dex, "label 0 is not placed"));
}

TEST(Validate, validate_whenAnInstructionBreaksARule_namesItsItemInWhere)
{
    Dex dex = with_items({Insn{Nop{}}, Insn{Goto{kLabel}}});

    EXPECT_EQ(where_reported(dex, "label 0 is not placed"),
              (std::vector<std::string>{"LT;->m()V, item 1"}));
}

TEST(Validate, validate_whenALabelIsPlacedTwice_reportsIt)
{
    Dex dex = with_items({kLabel, kLabel, Insn{Goto{kLabel}}});

    EXPECT_EQ(where_reported(dex, "label 0 is placed twice"),
              (std::vector<std::string>{"LT;->m()V, item 1"}));
}

TEST(Validate, validate_whenABranchTargetIsNotFollowedByAnInstruction_reportsIt)
{
    Dex dex = with_items({Insn{Goto{kLabel}}, kLabel});

    EXPECT_TRUE(reports(dex, "label 0 is not followed by an instruction"));
}

TEST(Validate, validate_whenABranchTargetIsFollowedOnlyByDebugItems_reportsIt)
{
    Dex dex = with_items({Insn{Goto{kLabel}}, kLabel, LineNumber{1}});

    EXPECT_TRUE(reports(dex, "label 0 is not followed by an instruction"));
}

TEST(Validate, validate_whenABranchGoesBackToAPlacedLabel_returnsNoProblems)
{
    Dex dex = with_items({kLabel, Insn{Goto{kLabel}}});

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenALabelNoBranchUsesEndsTheCode_returnsNoProblems)
{
    Dex dex = with_items({Insn{ReturnVoid{}}, kLabel});

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenAnIfTargetIsNotPlaced_reportsIt)
{
    Dex dex = with_insn(Insn{If{Condition::Eq, 0, 1, kUnplacedLabel}});

    EXPECT_TRUE(reports(dex, "label 9 is not placed"));
}

TEST(Validate, validate_whenAnIfZeroTargetIsNotPlaced_reportsIt)
{
    Dex dex = with_insn(Insn{IfZero{Condition::Eq, 0, kUnplacedLabel}});

    EXPECT_TRUE(reports(dex, "label 9 is not placed"));
}

TEST(Validate, validate_whenATryRangeIsWellFormed_returnsNoProblems)
{
    Dex dex = with_try({kLabel, Insn{Nop{}}, kOtherLabel, Insn{ReturnVoid{}}, kThirdLabel,
                        Insn{MoveException{0}}, Insn{ReturnVoid{}}},
                       TryRange{kLabel, kOtherLabel, {Catch{"LE;", kThirdLabel}}, kThirdLabel});

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenATryRangeEndsAtTheEndOfTheCode_returnsNoProblems)
{
    Dex dex = with_try({kLabel, Insn{Nop{}}, kThirdLabel, Insn{ReturnVoid{}}, kOtherLabel},
                       TryRange{kLabel, kOtherLabel, {}, kThirdLabel});

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenATryRangeStartIsNotPlaced_reportsItForThatTryRange)
{
    Dex dex =
        with_try({Insn{ReturnVoid{}}, kOtherLabel}, TryRange{kUnplacedLabel, kOtherLabel, {}, {}});

    EXPECT_EQ(where_reported(dex, "a try range label is not placed"),
              (std::vector<std::string>{"LT;->m()V, try range 0"}));
}

TEST(Validate, validate_whenATryRangeEndIsNotPlaced_reportsIt)
{
    Dex dex = with_try({kLabel, Insn{ReturnVoid{}}}, TryRange{kLabel, kUnplacedLabel, {}, {}});

    EXPECT_TRUE(reports(dex, "a try range label is not placed"));
}

TEST(Validate, validate_whenATryRangeEndsBeforeItStarts_reportsIt)
{
    Dex dex =
        with_try({kOtherLabel, Insn{ReturnVoid{}}, kLabel}, TryRange{kLabel, kOtherLabel, {}, {}});

    EXPECT_TRUE(reports(dex, "the try range ends before it starts"));
}

TEST(Validate, validate_whenACatchTypeIsNotAClassDescriptor_reportsIt)
{
    Dex dex = with_try({kLabel, Insn{Nop{}}, kOtherLabel, Insn{ReturnVoid{}}},
                       TryRange{kLabel, kOtherLabel, {Catch{"I", kLabel}}, {}});

    EXPECT_TRUE(reports(dex, "invalid class descriptor \"I\""));
}

TEST(Validate, validate_whenACatchHandlerIsNotPlaced_reportsIt)
{
    Dex dex = with_try({kLabel, Insn{Nop{}}, kOtherLabel, Insn{ReturnVoid{}}},
                       TryRange{kLabel, kOtherLabel, {Catch{"LE;", kUnplacedLabel}}, {}});

    EXPECT_TRUE(reports(dex, "label 9 is not placed"));
}

TEST(Validate, validate_whenACatchHandlerIsNotFollowedByAnInstruction_reportsIt)
{
    Dex dex = with_try({kLabel, Insn{ReturnVoid{}}, kOtherLabel},
                       TryRange{kLabel, kOtherLabel, {Catch{"LE;", kOtherLabel}}, {}});

    EXPECT_TRUE(reports(dex, "label 1 is not followed by an instruction"));
}

TEST(Validate, validate_whenACatchAllHandlerIsNotPlaced_reportsIt)
{
    Dex dex = with_try({kLabel, Insn{Nop{}}, kOtherLabel, Insn{ReturnVoid{}}},
                       TryRange{kLabel, kOtherLabel, {}, kUnplacedLabel});

    EXPECT_TRUE(reports(dex, "label 9 is not placed"));
}

TEST(Validate, validate_whenDebugItemsAreWellFormed_returnsNoProblems)
{
    Dex dex = with_items({
        LineNumber{1},
        PrologueEnd{},
        LocalStart{0, LocalVariable{"a", "I", "TT;"}},
        Insn{Nop{}},
        LocalEnd{0},
        LocalRestart{0},
        EpilogueBegin{},
        SetSourceFile{"T.java"},
        Insn{ReturnVoid{}},
    });
    code(dex).parameter_names = {std::nullopt, "name"};

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenAParameterNameIsNotValidUtf8_reportsIt)
{
    Dex dex = valid();
    code(dex).parameter_names = {kInvalidUtf8};

    EXPECT_EQ(where_reported(dex, "a parameter name is not valid UTF-8 / WTF-8"),
              (std::vector<std::string>{"LT;->m()V"}));
}

TEST(Validate, validate_whenALocalVariableNameIsNotValidUtf8_reportsIt)
{
    Dex dex = with_items(
        {LocalStart{0, LocalVariable{kInvalidUtf8, "I", std::nullopt}}, Insn{ReturnVoid{}}});

    EXPECT_TRUE(reports(dex, "a local variable name is not valid UTF-8 / WTF-8"));
}

TEST(Validate, validate_whenALocalVariableTypeIsVoid_reportsIt)
{
    Dex dex =
        with_items({LocalStart{0, LocalVariable{"a", "V", std::nullopt}}, Insn{ReturnVoid{}}});

    EXPECT_TRUE(reports(dex, "invalid field type \"V\""));
}

TEST(Validate, validate_whenALocalVariableSignatureIsNotValidUtf8_reportsIt)
{
    Dex dex =
        with_items({LocalStart{0, LocalVariable{"a", "I", kInvalidUtf8}}, Insn{ReturnVoid{}}});

    EXPECT_TRUE(reports(dex, "a local variable signature is not valid UTF-8 / WTF-8"));
}

TEST(Validate, validate_whenALocalVariableHasNoNameTypeOrSignature_returnsNoProblems)
{
    Dex dex = with_items({LocalStart{0, LocalVariable{std::nullopt, std::nullopt, std::nullopt}},
                          Insn{ReturnVoid{}}});

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenASourceFileMarkerIsNotValidUtf8_reportsIt)
{
    Dex dex = with_items({SetSourceFile{kInvalidUtf8}, Insn{ReturnVoid{}}});

    EXPECT_TRUE(reports(dex, "a source file name is not valid UTF-8 / WTF-8"));
}

TEST(Validate, validate_whenARegisterIsOutsideTheFrame_reportsIt)
{
    Dex dex = with_insn(Insn{Const{4, 0}});

    EXPECT_TRUE(reports(dex, "v4 is outside the 4 registers of the frame"));
}

TEST(Validate, validate_whenTheLastRegisterOfTheFrameIsUsed_returnsNoProblems)
{
    Dex dex = with_insn(Insn{Const{3, 0}});

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenTheSecondHalfOfAPairIsOutsideTheFrame_reportsIt)
{
    Dex dex = with_insn(Insn{ConstWide{3, 0}});

    EXPECT_TRUE(reports(dex, "v3 (pair) is outside the 4 registers of the frame"));
}

TEST(Validate, validate_whenAPairEndsOnTheLastRegisterOfTheFrame_returnsNoProblems)
{
    Dex dex = with_insn(Insn{ConstWide{2, 0}});

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenAFourBitOperandIsV16_reportsIt)
{
    const FieldId some_field{"LT;", "f", "I"};
    const std::vector<Insn> insns{
        InstanceOf{16, 0, "LT;"},
        InstanceOf{0, 16, "LT;"},
        ArrayLength{16, 0},
        ArrayLength{0, 16},
        NewArray{16, 0, "[I"},
        NewArray{0, 16, "[I"},
        If{Condition::Eq, 16, 0, kLabel},
        If{Condition::Eq, 0, 16, kLabel},
        InstanceGet{ValueKind::Normal, 16, 0, some_field},
        InstanceGet{ValueKind::Normal, 0, 16, some_field},
        InstancePut{ValueKind::Normal, 16, 0, some_field},
        InstancePut{ValueKind::Normal, 0, 16, some_field},
        Unary{UnaryOp::NegInt, 16, 0},
        Unary{UnaryOp::NegInt, 0, 16},
        BinaryLiteral{LiteralOp::Add, 16, 0, 300},
        BinaryLiteral{LiteralOp::Add, 0, 16, 300},
    };
    for (std::size_t i = 0; i < insns.size(); ++i) {
        Dex dex = with_insn(insns[i], 40);

        EXPECT_TRUE(reports(dex, "v16 does not fit the instruction (needs v15 or lower)"))
            << "instruction " << i;
    }
}

TEST(Validate, validate_whenAnEightBitOperandIsV256_reportsIt)
{
    const FieldId some_field{"LT;", "f", "I"};
    const std::vector<Insn> insns{
        MoveResult{ValueKind::Normal, 256},
        MoveException{256},
        Return{ValueKind::Normal, 256},
        Const{256, 0},
        ConstWide{256, 0},
        ConstString{256, "text"},
        ConstClass{256, "LT;"},
        ConstMethodHandle{
            256, MethodHandle{MethodHandleKind::InvokeStatic, MethodId{"LT;", "m", "()V"}}},
        ConstMethodType{256, "()V"},
        MonitorEnter{256},
        MonitorExit{256},
        CheckCast{256, "LT;"},
        NewInstance{256, "LT;"},
        FillArrayData{256, 1, {}},
        Throw{256},
        Switch{256, {}},
        Compare{CompareOp::CmplFloat, 256, 0, 0},
        Compare{CompareOp::CmplFloat, 0, 256, 0},
        Compare{CompareOp::CmplFloat, 0, 0, 256},
        IfZero{Condition::Eq, 256, kLabel},
        ArrayGet{ValueKind::Normal, 256, 0, 0},
        ArrayGet{ValueKind::Normal, 0, 256, 0},
        ArrayGet{ValueKind::Normal, 0, 0, 256},
        ArrayPut{ValueKind::Normal, 256, 0, 0},
        ArrayPut{ValueKind::Normal, 0, 256, 0},
        ArrayPut{ValueKind::Normal, 0, 0, 256},
        StaticGet{ValueKind::Normal, 256, some_field},
        StaticPut{ValueKind::Normal, 256, some_field},
        Binary{BinaryOp::AddInt, 256, 0, 0},
        Binary{BinaryOp::AddInt, 0, 256, 0},
        Binary{BinaryOp::AddInt, 0, 0, 256},
        BinaryLiteral{LiteralOp::Add, 256, 0, 1},
        BinaryLiteral{LiteralOp::Add, 0, 256, 1},
    };
    for (std::size_t i = 0; i < insns.size(); ++i) {
        Dex dex = with_insn(insns[i], 300);

        EXPECT_TRUE(reports(dex, "v256 does not fit the instruction (needs v255 or lower)"))
            << "instruction " << i;
    }
}

TEST(Validate, validate_whenAMoveUsesRegistersAboveV255_returnsNoProblems)
{
    Dex dex = with_insn(Insn{Move{ValueKind::Normal, 299, 298}}, 300);

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenAnAddOfAnEightBitLiteralUsesV16_returnsNoProblems)
{
    Dex dex = with_insn(Insn{BinaryLiteral{LiteralOp::Add, 16, 17, 127}}, 40);

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenAShiftLiteralDoesNotFitEightBits_reportsIt)
{
    Dex dex = with_insn(Insn{BinaryLiteral{LiteralOp::Shl, 0, 1, 300}});

    EXPECT_TRUE(reports(dex, "a shift by a literal takes an 8-bit literal"));
}

TEST(Validate, validate_whenAMoverTakesAKindOtherThanNormalWideOrObject_reportsIt)
{
    const std::vector<Insn> insns{
        Move{ValueKind::Byte, 0, 1},
        MoveResult{ValueKind::Boolean, 0},
        Return{ValueKind::Char, 0},
    };
    for (std::size_t i = 0; i < insns.size(); ++i) {
        Dex dex = with_insn(insns[i]);

        EXPECT_TRUE(reports(dex, "this instruction only takes the Normal, Wide or Object kind"))
            << "instruction " << i;
    }
}

TEST(Validate, validate_whenAWideOperandStartsOnTheLastRegister_reportsThePair)
{
    const FieldId some_field{"LT;", "f", "J"};
    const std::vector<Insn> insns{
        Move{ValueKind::Wide, 3, 0},
        Move{ValueKind::Wide, 0, 3},
        MoveResult{ValueKind::Wide, 3},
        Return{ValueKind::Wide, 3},
        Compare{CompareOp::CmpLong, 0, 3, 0},
        Compare{CompareOp::CmpgDouble, 0, 0, 3},
        ArrayGet{ValueKind::Wide, 3, 0, 1},
        ArrayPut{ValueKind::Wide, 3, 0, 1},
        InstanceGet{ValueKind::Wide, 3, 0, some_field},
        InstancePut{ValueKind::Wide, 3, 0, some_field},
        StaticGet{ValueKind::Wide, 3, some_field},
        StaticPut{ValueKind::Wide, 3, some_field},
        Unary{UnaryOp::IntToLong, 3, 0},
        Unary{UnaryOp::LongToInt, 0, 3},
        Unary{UnaryOp::NegDouble, 3, 0},
        Binary{BinaryOp::AddLong, 3, 0, 0},
        Binary{BinaryOp::AddLong, 0, 3, 0},
        Binary{BinaryOp::AddLong, 0, 0, 3},
        Binary{BinaryOp::MulDouble, 0, 0, 3},
        Binary{BinaryOp::ShlLong, 3, 0, 0},
    };
    for (std::size_t i = 0; i < insns.size(); ++i) {
        Dex dex = with_insn(insns[i]);

        EXPECT_TRUE(reports(dex, "v3 (pair) is outside the 4 registers of the frame"))
            << "instruction " << i;
    }
}

TEST(Validate, validate_whenANarrowOperandIsTheLastRegister_returnsNoProblems)
{
    const std::vector<Insn> insns{
        Compare{CompareOp::CmplFloat, 3, 3, 3}, Compare{CompareOp::CmpLong, 3, 0, 0},
        Unary{UnaryOp::LongToInt, 3, 0},        Unary{UnaryOp::IntToLong, 0, 3},
        Binary{BinaryOp::AddInt, 3, 3, 3},      Binary{BinaryOp::ShlLong, 0, 0, 3},
        Binary{BinaryOp::UshrLong, 0, 0, 3},    ArrayGet{ValueKind::Wide, 0, 3, 3},
    };
    for (std::size_t i = 0; i < insns.size(); ++i) {
        Dex dex = with_insn(insns[i]);

        EXPECT_TRUE(validate(dex).empty()) << "instruction " << i;
    }
}

TEST(Validate, validate_whenSixArgumentRegistersAreNotARun_reportsIt)
{
    Dex dex = with_insn(
        Insn{Invoke{Invoke::Kind::Static, {1, 3, 5, 7, 9, 11}, MethodId{"LT;", "m", "()V"}}}, 40);

    EXPECT_TRUE(
        reports(dex, "argument registers must be at most five below v16, or a run of at most 255"));
}

TEST(Validate, validate_whenSixArgumentRegistersAreARun_returnsNoProblems)
{
    Dex dex = with_insn(
        Insn{Invoke{Invoke::Kind::Static, RegList::range(20, 6), MethodId{"LT;", "m", "()V"}}}, 40);

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenFiveArgumentRegistersBelowV16AreNotARun_returnsNoProblems)
{
    Dex dex = with_insn(
        Insn{Invoke{Invoke::Kind::Static, {1, 3, 5, 7, 9}, MethodId{"LT;", "m", "()V"}}}, 40);

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenAnArgumentRegisterAboveV15IsNotPartOfARun_reportsIt)
{
    Dex dex =
        with_insn(Insn{Invoke{Invoke::Kind::Static, {1, 20}, MethodId{"LT;", "m", "()V"}}}, 40);

    EXPECT_TRUE(reports(dex, "argument registers must be at most five below v16"));
}

TEST(Validate, validate_whenARunHas255ArgumentRegisters_returnsNoProblems)
{
    Dex dex = with_insn(
        Insn{Invoke{Invoke::Kind::Static, RegList::range(0, 255), MethodId{"LT;", "m", "()V"}}},
        300);

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenARunHas256ArgumentRegisters_reportsIt)
{
    Dex dex = with_insn(
        Insn{Invoke{Invoke::Kind::Static, RegList::range(0, 256), MethodId{"LT;", "m", "()V"}}},
        300);

    EXPECT_TRUE(reports(dex, "argument registers must be at most five below v16"));
}

TEST(Validate, validate_whenAnArgumentRegisterIsOutsideTheFrame_reportsIt)
{
    Dex dex = with_insn(Insn{Invoke{Invoke::Kind::Static, {5}, MethodId{"LT;", "m", "()V"}}});

    EXPECT_TRUE(reports(dex, "v5 is outside the 4 registers of the frame"));
}

TEST(Validate, validate_whenFilledNewArrayRegistersAreNotEncodable_reportsIt)
{
    Dex dex = with_insn(Insn{FilledNewArray{{1, 3, 5, 7, 9, 11}, "[I"}}, 40);

    EXPECT_TRUE(reports(dex, "argument registers must be at most five below v16"));
}

TEST(Validate, validate_whenAnInvokeKindIsUnknown_reportsIt)
{
    Dex dex =
        with_insn(Insn{Invoke{static_cast<Invoke::Kind>(5), {}, MethodId{"LT;", "m", "()V"}}});

    EXPECT_TRUE(reports(dex, "bad invoke kind"));
}

TEST(Validate, validate_whenAnInvokeNamesAPrimitiveClass_reportsIt)
{
    Dex dex = with_insn(Insn{Invoke{Invoke::Kind::Static, {}, MethodId{"I", "m", "()V"}}});

    EXPECT_TRUE(reports(dex, "invalid method class \"I\""));
}

TEST(Validate, validate_whenAnInvokeHasAnInvalidPrototype_reportsIt)
{
    Dex dex = with_insn(Insn{Invoke{Invoke::Kind::Static, {}, MethodId{"LT;", "m", "(V)V"}}});

    EXPECT_TRUE(reports(dex, "invalid prototype \"(V)V\""));
}

TEST(Validate, validate_whenAStringConstantIsNotValidUtf8_reportsIt)
{
    Dex dex = with_insn(Insn{ConstString{0, kInvalidUtf8}});

    EXPECT_TRUE(reports(dex, "the string constant is not valid UTF-8 / WTF-8"));
}

TEST(Validate, validate_whenTwoInstructionsShareAnInvalidOperand_reportsItOnce)
{
    const Shared<std::string> shared = kInvalidUtf8;
    Dex dex = with_items(
        {Insn{ConstString{0, shared}}, Insn{ConstString{1, shared}}, Insn{ReturnVoid{}}});

    EXPECT_EQ(where_reported(dex, "the string constant is not valid UTF-8 / WTF-8"),
              (std::vector<std::string>{"LT;->m()V, item 0"}));
}

TEST(Validate, validate_whenAConstClassTypeIsNotAFieldType_reportsIt)
{
    Dex dex = with_insn(Insn{ConstClass{0, "Q"}});

    EXPECT_TRUE(reports(dex, "invalid field type \"Q\""));
}

TEST(Validate, validate_whenACheckCastTypeIsNotAFieldType_reportsIt)
{
    Dex dex = with_insn(Insn{CheckCast{0, "Q"}});

    EXPECT_TRUE(reports(dex, "invalid field type \"Q\""));
}

TEST(Validate, validate_whenAnInstanceOfTypeIsNotAFieldType_reportsIt)
{
    Dex dex = with_insn(Insn{InstanceOf{0, 1, "Q"}});

    EXPECT_TRUE(reports(dex, "invalid field type \"Q\""));
}

TEST(Validate, validate_whenNewInstanceNamesAnArrayType_reportsIt)
{
    Dex dex = with_insn(Insn{NewInstance{0, "[I"}});

    EXPECT_TRUE(reports(dex, "invalid class descriptor \"[I\""));
}

TEST(Validate, validate_whenNewArrayNamesANonArrayType_reportsIt)
{
    Dex dex = with_insn(Insn{NewArray{0, 1, "I"}});

    EXPECT_TRUE(reports(dex, "invalid array type \"I\""));
}

TEST(Validate, validate_whenFilledNewArrayNamesANonArrayType_reportsIt)
{
    Dex dex = with_insn(Insn{FilledNewArray{{0}, "LT;"}});

    EXPECT_TRUE(reports(dex, "invalid array type \"LT;\""));
}

TEST(Validate, validate_whenAnInstanceFieldAccessNamesAnInvalidClass_reportsIt)
{
    Dex dex = with_insn(Insn{InstanceGet{ValueKind::Normal, 0, 1, FieldId{"T", "f", "I"}}});

    EXPECT_TRUE(reports(dex, "invalid class descriptor \"T\""));
}

TEST(Validate, validate_whenAStaticFieldAccessNamesAVoidField_reportsIt)
{
    Dex dex = with_insn(Insn{StaticPut{ValueKind::Normal, 0, FieldId{"LT;", "f", "V"}}});

    EXPECT_TRUE(reports(dex, "invalid field type \"V\""));
}

TEST(Validate, validate_whenFillArrayDataHasAnElementWidthOfThree_reportsIt)
{
    Dex dex = with_insn(Insn{FillArrayData{0, 3, {1, 2, 3}}});

    EXPECT_TRUE(reports(dex, "fill-array-data elements must be 1, 2, 4 or 8 bytes wide"));
}

TEST(Validate, validate_whenFillArrayDataHoldsAPartialElement_reportsIt)
{
    Dex dex = with_insn(Insn{FillArrayData{0, 4, {1, 2, 3, 4, 5, 6}}});

    EXPECT_TRUE(reports(dex, "fill-array-data holds a partial element"));
}

TEST(Validate, validate_whenFillArrayDataHoldsWholeElements_returnsNoProblems)
{
    Dex dex = with_insn(Insn{FillArrayData{0, 2, {1, 2, 3, 4}}});

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenASwitchIsWellFormed_returnsNoProblems)
{
    Dex dex = with_insn(Insn{Switch{0, {{1, kLabel}, {-5, kLabel}}}});

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenASwitchListsAKeyTwice_reportsIt)
{
    Dex dex = with_insn(Insn{Switch{0, {{1, kLabel}, {1, kLabel}}}});

    EXPECT_TRUE(reports(dex, "switch key 1 is listed twice"));
}

TEST(Validate, validate_whenASwitchCaseTargetIsNotPlaced_reportsIt)
{
    Dex dex = with_insn(Insn{Switch{0, {{1, kUnplacedLabel}}}});

    EXPECT_TRUE(reports(dex, "label 9 is not placed"));
}

TEST(Validate, validate_whenASwitchHas65536Cases_reportsIt)
{
    Switch big{0, {}};
    for (int32_t key = 0; key < 65536; ++key)
        big.cases.push_back({key, kLabel});
    Dex dex = with_insn(Insn{big});

    EXPECT_TRUE(reports(dex, "a switch has at most 65535 cases"));
}

TEST(Validate, requiredVersion_whenCodeHasInvokePolymorphic_returns38)
{
    Dex dex = with_insn(Insn{InvokePolymorphic{{0}, MethodId{"LT;", "m", "()V"}, "()V"}});

    EXPECT_EQ(required_version(dex), 38u);
}

TEST(Validate, validate_whenInvokePolymorphicIsWellFormed_returnsNoProblems)
{
    Dex dex = with_insn(Insn{InvokePolymorphic{{0}, MethodId{"LT;", "m", "()V"}, "()V"}});

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenInvokePolymorphicNamesAnInvalidMethod_reportsIt)
{
    Dex dex = with_insn(Insn{InvokePolymorphic{{0}, MethodId{"LT;", "a.b", "()V"}, "()V"}});

    EXPECT_TRUE(reports(dex, "invalid member name \"a.b\""));
}

TEST(Validate, validate_whenInvokePolymorphicHasAnInvalidCallPrototype_reportsIt)
{
    Dex dex = with_insn(Insn{InvokePolymorphic{{0}, MethodId{"LT;", "m", "()V"}, "(V)V"}});

    EXPECT_TRUE(reports(dex, "invalid prototype \"(V)V\""));
}

TEST(Validate, validate_whenInvokePolymorphicRegistersAreNotEncodable_reportsIt)
{
    Dex dex = with_insn(
        Insn{InvokePolymorphic{{1, 3, 5, 7, 9, 11}, MethodId{"LT;", "m", "()V"}, "()V"}}, 40);

    EXPECT_TRUE(reports(dex, "argument registers must be at most five below v16"));
}

TEST(Validate, requiredVersion_whenCodeHasInvokeCustom_returns38)
{
    Dex dex = with_insn(Insn{InvokeCustom{{}, call_site()}});

    EXPECT_EQ(required_version(dex), 38u);
}

TEST(Validate, validate_whenInvokeCustomIsWellFormed_returnsNoProblems)
{
    Dex dex = with_insn(Insn{InvokeCustom{{}, call_site()}});

    EXPECT_TRUE(validate(dex).empty());
}

TEST(Validate, validate_whenACallSiteBootstrapIsABadMethodHandle_reportsIt)
{
    CallSite site = call_site();
    site.bootstrap = MethodHandle{MethodHandleKind::StaticGet, MethodId{"LT;", "m", "()V"}};
    Dex dex = with_insn(Insn{InvokeCustom{{}, site}});

    EXPECT_TRUE(reports(dex, "a field method handle names a method"));
}

TEST(Validate, validate_whenACallSiteMethodNameIsNotAMemberName_reportsIt)
{
    CallSite site = call_site();
    site.method_name = "a.b";
    Dex dex = with_insn(Insn{InvokeCustom{{}, site}});

    EXPECT_TRUE(reports(dex, "invalid member name \"a.b\""));
}

TEST(Validate, validate_whenACallSiteMethodTypeIsNotAPrototype_reportsIt)
{
    CallSite site = call_site();
    site.method_type = "(V)V";
    Dex dex = with_insn(Insn{InvokeCustom{{}, site}});

    EXPECT_TRUE(reports(dex, "invalid prototype \"(V)V\""));
}

TEST(Validate, validate_whenACallSiteExtraArgumentIsAnInvalidValue_reportsIt)
{
    CallSite site = call_site();
    site.extra_args = {Value{Value::Type{"Q"}}};
    Dex dex = with_insn(Insn{InvokeCustom{{}, site}});

    EXPECT_TRUE(reports(dex, "invalid type descriptor \"Q\""));
}

TEST(Validate, validate_whenInvokeCustomRegistersAreNotEncodable_reportsIt)
{
    Dex dex = with_insn(Insn{InvokeCustom{{1, 3, 5, 7, 9, 11}, call_site()}}, 40);

    EXPECT_TRUE(reports(dex, "argument registers must be at most five below v16"));
}

TEST(Validate, requiredVersion_whenCodeHasConstMethodHandle_returns39)
{
    Dex dex = with_insn(Insn{ConstMethodHandle{
        0, MethodHandle{MethodHandleKind::InvokeStatic, MethodId{"LT;", "m", "()V"}}}});

    EXPECT_EQ(required_version(dex), 39u);
}

TEST(Validate, validate_whenConstMethodHandleHoldsABadMethodHandle_reportsIt)
{
    Dex dex = with_insn(Insn{ConstMethodHandle{
        0, MethodHandle{MethodHandleKind::InvokeStatic, FieldId{"LT;", "f", "I"}}}});

    EXPECT_TRUE(reports(dex, "an invoke method handle names a field"));
}

TEST(Validate, requiredVersion_whenCodeHasConstMethodType_returns39)
{
    Dex dex = with_insn(Insn{ConstMethodType{0, "()V"}});

    EXPECT_EQ(required_version(dex), 39u);
}

TEST(Validate, validate_whenConstMethodTypeIsNotAPrototype_reportsIt)
{
    Dex dex = with_insn(Insn{ConstMethodType{0, "(V)V"}});

    EXPECT_TRUE(reports(dex, "invalid prototype \"(V)V\""));
}

TEST(Validate, requiredVersion_whenCodeAndValuesNeedDifferentVersions_returnsTheHighest)
{
    Dex dex = with_insn(Insn{ConstMethodType{0, "()V"}});
    cls(dex).annotations = {annotation("LA;", {{"x", Value{Value::MethodType{"()V"}}}})};

    EXPECT_EQ(required_version(dex), 39u);
}

TEST(Validate, check_whenAnInstructionNeedsANewerVersion_returnsItsItemAndItsName)
{
    Dex dex = with_items({Insn{Nop{}}, Insn{ConstMethodType{0, "()V"}}, Insn{ReturnVoid{}}});

    detail::Checked checked = detail::check(dex);

    EXPECT_EQ(checked.needed_version, 39u);
    EXPECT_EQ(checked.needed_reason, "LT;->m()V, item 1: const-method-type");
}

TEST(Validate, check_whenTwoInstructionsNeedTheSameVersion_returnsTheFirstAsTheReason)
{
    Dex dex = with_items({Insn{InvokeCustom{{}, call_site()}},
                          Insn{InvokePolymorphic{{0}, MethodId{"LT;", "m", "()V"}, "()V"}},
                          Insn{ReturnVoid{}}});

    detail::Checked checked = detail::check(dex);

    EXPECT_EQ(checked.needed_version, 38u);
    EXPECT_EQ(checked.needed_reason, "LT;->m()V, item 0: invoke-custom");
}

class ValidateFixture : public ::testing::TestWithParam<std::string>
{
};

TEST_P(ValidateFixture, validate_whenModelIsReadFromAWellFormedFile_returnsNoProblems)
{
    auto dex = read(support::load_fixture(GetParam()));
    ASSERT_TRUE(dex.has_value()) << dex.error().message;

    std::vector<Problem> problems = validate(*dex);

    for (const Problem &p : problems)
        ADD_FAILURE() << p.where << ": " << p.message;
}

TEST_P(ValidateFixture, requiredVersion_whenModelIsReadFromAFile_isNotAboveTheFileVersion)
{
    auto dex = read(support::load_fixture(GetParam()));
    ASSERT_TRUE(dex.has_value()) << dex.error().message;

    EXPECT_LE(required_version(*dex), dex->version);
}

INSTANTIATE_TEST_SUITE_P(AllDexFiles, ValidateFixture,
                         ::testing::Values("annotated.dex", "casts.dex", "classes.dex",
                                           "fibonacci.dex", "inherit.dex", "multistring.dex",
                                           "polymorphic.dex", "shapes.dex", "trycatch.dex"),
                         [](const ::testing::TestParamInfo<ValidateFixture::ParamType> &info) {
                             return info.param.substr(0, info.param.rfind('.'));
                         });

} // namespace
} // namespace dexsplit::model
