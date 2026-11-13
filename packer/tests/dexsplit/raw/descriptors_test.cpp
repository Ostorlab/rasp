// Tests for the syntax of names, type descriptors and method prototypes.

#include "raw/descriptors.hpp"

#include <gtest/gtest.h>
#include <string>

namespace dexsplit::raw {
namespace {

TEST(Descriptors, isValidSimpleName_whenNameUsesAllowedAsciiCharacters_returnsTrue)
{
    EXPECT_TRUE(is_valid_simple_name("abc$_-09", 35));
}

TEST(Descriptors, isValidSimpleName_whenNameHasNonAsciiLetters_returnsTrue)
{
    EXPECT_TRUE(is_valid_simple_name("\xC3\xA9t\xC3\xA9", 35));
}

TEST(Descriptors, isValidSimpleName_whenNameHasASupplementaryCharacter_returnsTrue)
{
    EXPECT_TRUE(is_valid_simple_name("\xF0\x9F\x98\x80", 35));
}

TEST(Descriptors, isValidSimpleName_whenNameIsEmpty_returnsFalse)
{
    EXPECT_FALSE(is_valid_simple_name("", 35));
}

TEST(Descriptors, isValidSimpleName_whenNameHasADot_returnsFalse)
{
    EXPECT_FALSE(is_valid_simple_name("a.b", 35));
}

TEST(Descriptors, isValidSimpleName_whenNameHasASemicolon_returnsFalse)
{
    EXPECT_FALSE(is_valid_simple_name("a;b", 35));
}

TEST(Descriptors, isValidSimpleName_whenNameIsAnUnpairedSurrogate_returnsFalse)
{
    EXPECT_FALSE(is_valid_simple_name("\xED\xA0\x80", 35));
}

TEST(Descriptors, isValidSimpleName_whenNameHasAC1ControlCharacter_returnsFalse)
{
    EXPECT_FALSE(is_valid_simple_name("\xC2\x85", 35));
}

TEST(Descriptors, isValidSimpleName_whenNameHasASpaceBeforeVersion40_returnsFalse)
{
    EXPECT_FALSE(is_valid_simple_name("a b", 39));
}

TEST(Descriptors, isValidSimpleName_whenNameHasASpaceInVersion40_returnsTrue)
{
    EXPECT_TRUE(is_valid_simple_name("a b", 40));
}

TEST(Descriptors, isValidSimpleName_whenNameHasANoBreakSpaceBeforeVersion40_returnsFalse)
{
    EXPECT_FALSE(is_valid_simple_name("a b", 39));
}

TEST(Descriptors, isValidSimpleName_whenNameHasANoBreakSpaceInVersion40_returnsTrue)
{
    EXPECT_TRUE(is_valid_simple_name("a b", 40));
}

TEST(Descriptors, isValidSimpleName_whenNameHasAZeroWidthSpace_returnsFalse)
{
    EXPECT_FALSE(is_valid_simple_name("a​b", 40));
}

TEST(Descriptors, isValidMemberName_whenNameIsInAngleBrackets_returnsTrue)
{
    EXPECT_TRUE(is_valid_member_name("<init>", 35));
    EXPECT_TRUE(is_valid_member_name("<clinit>", 35));
    EXPECT_TRUE(is_valid_member_name("<anything>", 35));
}

TEST(Descriptors, isValidMemberName_whenAngleBracketsAreEmpty_returnsFalse)
{
    EXPECT_FALSE(is_valid_member_name("<>", 35));
}

TEST(Descriptors, isValidMemberName_whenClosingBracketIsMissing_returnsFalse)
{
    EXPECT_FALSE(is_valid_member_name("<init", 35));
}

TEST(Descriptors, isValidMemberName_whenNameIsASimpleName_returnsTrue)
{
    EXPECT_TRUE(is_valid_member_name("run", 35));
}

TEST(Descriptors, isValidTypeDescriptor_whenDescriptorIsWellFormed_returnsTrue)
{
    for (const char *ok :
         {"I", "V", "J", "Ljava/lang/String;", "[I", "[[Ljava/lang/Object;", "La;"})
        EXPECT_TRUE(is_valid_type_descriptor(ok, 35)) << ok;
}

TEST(Descriptors, isValidTypeDescriptor_whenDescriptorIsMalformed_returnsFalse)
{
    for (const char *bad :
         {"", "X", "[V", "L;", "Ljava//String;", "Ljava/lang/String", "Lfoo/;", "[", "LA;B"})
        EXPECT_FALSE(is_valid_type_descriptor(bad, 35)) << bad;
}

TEST(Descriptors, isValidTypeDescriptor_whenArrayHas255Dimensions_returnsTrue)
{
    std::string deep(255, '[');

    EXPECT_TRUE(is_valid_type_descriptor(deep + "I", 35));
}

TEST(Descriptors, isValidTypeDescriptor_whenArrayHas256Dimensions_returnsFalse)
{
    std::string deep(255, '[');

    EXPECT_FALSE(is_valid_type_descriptor(deep + "[I", 35));
}

TEST(Descriptors, isValidClassDescriptor_whenDescriptorIsAClass_returnsTrue)
{
    EXPECT_TRUE(is_valid_class_descriptor("La/B;", 35));
}

TEST(Descriptors, isValidClassDescriptor_whenDescriptorIsAnArray_returnsFalse)
{
    EXPECT_FALSE(is_valid_class_descriptor("[La/B;", 35));
}

TEST(Descriptors, isValidFieldType_whenTypeIsVoid_returnsFalse)
{
    EXPECT_FALSE(is_valid_field_type("V", 35));
}

TEST(Descriptors, isValidFieldType_whenTypeIsAPrimitive_returnsTrue)
{
    EXPECT_TRUE(is_valid_field_type("Z", 35));
}

TEST(Descriptors, parseProto_whenProtoHasThreeParameters_returnsEachPart)
{
    auto parts = parse_proto("(I[Ljava/lang/String;J)V");

    ASSERT_TRUE(parts.has_value());
    ASSERT_EQ(parts->params.size(), 3u);
    EXPECT_EQ(parts->params[0], "I");
    EXPECT_EQ(parts->params[1], "[Ljava/lang/String;");
    EXPECT_EQ(parts->params[2], "J");
    EXPECT_EQ(parts->return_type, "V");
}

TEST(Descriptors, isValidProto_whenProtoHasNoParameters_returnsTrue)
{
    EXPECT_TRUE(is_valid_proto("()V", 35));
    EXPECT_TRUE(is_valid_proto("()[I", 35));
}

TEST(Descriptors, isValidProto_whenAParameterIsVoid_returnsFalse)
{
    EXPECT_FALSE(is_valid_proto("(V)V", 35));
}

TEST(Descriptors, isValidProto_whenReturnTypeIsMissing_returnsFalse)
{
    EXPECT_FALSE(is_valid_proto("()", 35));
}

TEST(Descriptors, isValidProto_whenClosingParenthesisIsMissing_returnsFalse)
{
    EXPECT_FALSE(is_valid_proto("(I", 35));
}

TEST(Descriptors, isValidProto_whenOpeningParenthesisIsMissing_returnsFalse)
{
    EXPECT_FALSE(is_valid_proto("I)V", 35));
}

TEST(Descriptors, isValidProto_whenReturnTypeIsTwoTypes_returnsFalse)
{
    EXPECT_FALSE(is_valid_proto("()II", 35));
}

TEST(Descriptors, makeProto_whenGivenParametersAndReturnType_returnsTheDescriptor)
{
    EXPECT_EQ(make_proto({"I", "Ljava/lang/String;"}, "V"), "(ILjava/lang/String;)V");
}

TEST(Descriptors, shortyOf_whenProtoHasClassAndArrayTypes_writesEachAsL)
{
    EXPECT_EQ(shorty_of("(I[JLjava/lang/String;D)Z"), "ZILLD");
}

TEST(Descriptors, shortyOf_whenProtoHasNoParameters_returnsOnlyTheReturnType)
{
    EXPECT_EQ(shorty_of("()V"), "V");
}

TEST(Descriptors, parameterWords_whenProtoHasLongAndDouble_countsTwoWordsForEach)
{
    EXPECT_EQ(parameter_words("(IJDLjava/lang/Object;)V"), 6u);
}

TEST(Descriptors, descriptorOfClass_whenClassIsTopLevel_returnsItsDescriptor)
{
    EXPECT_EQ(descriptor_of_class("java.lang.String"), "Ljava/lang/String;");
}

TEST(Descriptors, descriptorOfClass_whenClassIsNested_keepsTheDollarSign)
{
    EXPECT_EQ(descriptor_of_class("a.Outer$Inner"), "La/Outer$Inner;");
}

TEST(Descriptors, javaNameOf_whenTypeIsAClass_returnsItsBinaryName)
{
    EXPECT_EQ(java_name_of("Ljava/lang/String;"), "java.lang.String");
}

TEST(Descriptors, javaNameOf_whenTypeIsAPrimitive_returnsItsKeyword)
{
    EXPECT_EQ(java_name_of("I"), "int");
}

TEST(Descriptors, javaNameOf_whenTypeIsAnArrayOfClasses_keepsTheDescriptorForm)
{
    EXPECT_EQ(java_name_of("[Ljava/lang/String;"), "[Ljava.lang.String;");
}

} // namespace
} // namespace dexsplit::raw
