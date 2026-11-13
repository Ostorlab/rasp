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

} // namespace
} // namespace dexsplit::model
