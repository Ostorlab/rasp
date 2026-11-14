// Tests for the model types: RegList, the lookups of ClassDef and Dex, Shared, Value and Code.

#include "model/types.hpp"

#include <gtest/gtest.h>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "common/access_flags.hpp"
#include "common/ids.hpp"

namespace dexsplit::model {
namespace {

std::vector<Reg> regs_of(const RegList &list) { return {list.begin(), list.end()}; }

FieldDef field(std::string name, std::string type)
{
    FieldDef f;
    f.name = std::move(name);
    f.type = std::move(type);
    return f;
}

MethodDef method(std::string name, std::string proto)
{
    MethodDef m;
    m.name = std::move(name);
    m.proto = std::move(proto);
    return m;
}

ClassDef class_def(std::string type)
{
    ClassDef c;
    c.type = std::move(type);
    return c;
}

TEST(Types, regList_whenDefaultConstructed_isEmpty)
{
    RegList list;

    EXPECT_TRUE(list.empty());
    EXPECT_EQ(list.size(), 0u);
    EXPECT_EQ(list.begin(), list.end());
}

TEST(Types, regList_whenGivenAnInitializerList_holdsTheRegistersInOrder)
{
    RegList list{1, 2, 3};

    EXPECT_EQ(regs_of(list), (std::vector<Reg>{1, 2, 3}));
}

TEST(Types, regList_whenGivenASpan_holdsTheRegistersInOrder)
{
    std::vector<Reg> regs{9, 4, 7};

    RegList list{std::span<const Reg>(regs)};

    EXPECT_EQ(regs_of(list), regs);
}

TEST(Types, regList_whenGivenMoreRegistersThanFitInline_holdsThemAll)
{
    RegList list{1, 3, 5, 7, 9, 11, 13, 15};

    EXPECT_EQ(regs_of(list), (std::vector<Reg>{1, 3, 5, 7, 9, 11, 13, 15}));
}

TEST(Types, range_whenCountIsZero_returnsAnEmptyList)
{
    RegList list = RegList::range(5, 0);

    EXPECT_TRUE(list.empty());
}

TEST(Types, range_whenCountFitsInline_returnsConsecutiveRegisters)
{
    RegList list = RegList::range(20, 4);

    EXPECT_EQ(regs_of(list), (std::vector<Reg>{20, 21, 22, 23}));
}

TEST(Types, range_whenCountNeedsTheHeap_returnsConsecutiveRegisters)
{
    RegList list = RegList::range(10, 300);

    ASSERT_EQ(list.size(), 300u);
    EXPECT_EQ(list[0], 10);
    EXPECT_EQ(list[299], 309);
    EXPECT_TRUE(list.is_run());
}

TEST(Types, pushBack_whenListIsEmpty_addsTheRegister)
{
    RegList list;

    list.push_back(42);

    EXPECT_EQ(regs_of(list), (std::vector<Reg>{42}));
}

TEST(Types, pushBack_whenInlineStorageIsFull_keepsTheEarlierRegisters)
{
    RegList list{1, 2, 3, 4, 5, 6};

    list.push_back(7);

    EXPECT_EQ(regs_of(list), (std::vector<Reg>{1, 2, 3, 4, 5, 6, 7}));
}

TEST(Types, pushBack_whenHeapStorageIsFull_keepsTheEarlierRegisters)
{
    RegList list;
    std::vector<Reg> expected;

    for (Reg r = 0; r < 100; ++r) {
        list.push_back(static_cast<Reg>(r * 3));
        expected.push_back(static_cast<Reg>(r * 3));
    }

    EXPECT_EQ(regs_of(list), expected);
}

TEST(Types, pushBack_whenListHolds65535Registers_throwsLengthError)
{
    RegList list = RegList::range(0, 65535);

    EXPECT_THROW(list.push_back(0), std::length_error);
    EXPECT_EQ(list.size(), 65535u);
}

TEST(Types, pushBack_whenListWasMovedFrom_startsANewList)
{
    RegList list = RegList::range(0, 20);
    RegList taken = std::move(list);

    list.push_back(3);

    EXPECT_EQ(regs_of(list), (std::vector<Reg>{3}));
}

TEST(Types, clear_whenListIsInline_makesItEmpty)
{
    RegList list{1, 2, 3};

    list.clear();

    EXPECT_TRUE(list.empty());
}

TEST(Types, clear_whenListIsOnTheHeap_makesItEmptyAndReusable)
{
    RegList list = RegList::range(0, 20);

    list.clear();
    list.push_back(8);

    EXPECT_EQ(regs_of(list), (std::vector<Reg>{8}));
}

TEST(Types, subscript_whenAssigned_changesThatRegister)
{
    RegList list{1, 2, 3};

    list[1] = 9;

    EXPECT_EQ(regs_of(list), (std::vector<Reg>{1, 9, 3}));
}

TEST(Types, isRun_whenListIsEmpty_returnsTrue) { EXPECT_TRUE(RegList{}.is_run()); }

TEST(Types, isRun_whenListHasOneRegister_returnsTrue) { EXPECT_TRUE(RegList{7}.is_run()); }

TEST(Types, isRun_whenRegistersAreConsecutive_returnsTrue)
{
    EXPECT_TRUE((RegList{4, 5, 6}).is_run());
}

TEST(Types, isRun_whenThereIsAGap_returnsFalse) { EXPECT_FALSE((RegList{1, 3}).is_run()); }

TEST(Types, isRun_whenRegistersDecrease_returnsFalse) { EXPECT_FALSE((RegList{3, 2, 1}).is_run()); }

TEST(Types, isRun_whenARegisterRepeats_returnsFalse) { EXPECT_FALSE((RegList{2, 2}).is_run()); }

TEST(Types, isRun_whenRegistersWrapPastV65535_returnsFalse)
{
    EXPECT_FALSE((RegList{65535, 0}).is_run());
}

TEST(Types, copyConstruct_whenSourceIsInline_copiesTheRegisters)
{
    RegList source{1, 2, 3};

    RegList copy = source;

    EXPECT_EQ(regs_of(copy), (std::vector<Reg>{1, 2, 3}));
    EXPECT_EQ(regs_of(source), (std::vector<Reg>{1, 2, 3}));
}

TEST(Types, copyConstruct_whenSourceIsOnTheHeap_copiesTheRegisters)
{
    RegList source = RegList::range(10, 300);

    RegList copy = source;

    EXPECT_EQ(regs_of(copy), regs_of(source));
    EXPECT_EQ(source.size(), 300u);
}

TEST(Types, copyConstruct_whenTheCopyIsChanged_leavesTheSourceUnchanged)
{
    RegList source = RegList::range(10, 300);
    RegList copy = source;

    copy[0] = 999;

    EXPECT_EQ(source[0], 10);
}

TEST(Types, moveConstruct_whenSourceIsInline_takesTheRegistersAndEmptiesTheSource)
{
    RegList source{1, 2, 3};

    RegList moved = std::move(source);

    EXPECT_EQ(regs_of(moved), (std::vector<Reg>{1, 2, 3}));
    EXPECT_TRUE(source.empty());
}

TEST(Types, moveConstruct_whenSourceIsOnTheHeap_takesTheRegistersAndEmptiesTheSource)
{
    RegList source = RegList::range(10, 300);

    RegList moved = std::move(source);

    EXPECT_EQ(moved, RegList::range(10, 300));
    EXPECT_TRUE(source.empty());
}

TEST(Types, copyAssign_whenTargetIsOnTheHeapAndSourceIsInline_replacesTheRegisters)
{
    RegList target = RegList::range(10, 300);
    RegList source{1, 2, 3};

    target = source;

    EXPECT_EQ(regs_of(target), (std::vector<Reg>{1, 2, 3}));
    EXPECT_EQ(regs_of(source), (std::vector<Reg>{1, 2, 3}));
}

TEST(Types, copyAssign_whenTargetIsInlineAndSourceIsOnTheHeap_replacesTheRegisters)
{
    RegList target{1, 2, 3};
    RegList source = RegList::range(10, 300);

    target = source;

    EXPECT_EQ(regs_of(target), regs_of(source));
    EXPECT_EQ(source.size(), 300u);
}

TEST(Types, copyAssign_whenAssignedToItself_keepsTheRegisters)
{
    RegList list = RegList::range(10, 300);
    const RegList &same = list;

    list = same;

    EXPECT_EQ(list, RegList::range(10, 300));
}

TEST(Types, moveAssign_whenBothListsAreOnTheHeap_takesTheRegistersAndEmptiesTheSource)
{
    RegList target = RegList::range(0, 50);
    RegList source = RegList::range(10, 300);

    target = std::move(source);

    EXPECT_EQ(target, RegList::range(10, 300));
    EXPECT_TRUE(source.empty());
}

TEST(Types, moveAssign_whenSourceIsInline_takesTheRegistersAndEmptiesTheSource)
{
    RegList target = RegList::range(0, 50);
    RegList source{1, 2, 3};

    target = std::move(source);

    EXPECT_EQ(regs_of(target), (std::vector<Reg>{1, 2, 3}));
    EXPECT_TRUE(source.empty());
}

TEST(Types, moveAssign_whenAssignedToItself_keepsTheRegisters)
{
    RegList list = RegList::range(10, 300);
    RegList &same = list;

    list = std::move(same);

    EXPECT_EQ(list, RegList::range(10, 300));
}

TEST(Types, regListEquals_whenRegistersMatch_returnsTrue)
{
    EXPECT_TRUE((RegList{1, 2, 3}) == (RegList{1, 2, 3}));
}

TEST(Types, regListEquals_whenSizesDiffer_returnsFalse)
{
    EXPECT_FALSE((RegList{1, 2, 3}) == (RegList{1, 2}));
}

TEST(Types, regListEquals_whenARegisterDiffers_returnsFalse)
{
    EXPECT_FALSE((RegList{1, 2, 3}) == (RegList{1, 2, 4}));
}

TEST(Types, regListEquals_whenBothListsAreEmpty_returnsTrue)
{
    EXPECT_TRUE(RegList{} == RegList{});
}

TEST(Types, regListEquals_whenOneListIsOnTheHeapAndTheOtherInline_comparesTheRegisters)
{
    RegList on_heap = RegList::range(0, 20);
    on_heap.clear();
    on_heap.push_back(1);
    on_heap.push_back(2);

    EXPECT_TRUE(on_heap == (RegList{1, 2}));
}

TEST(Types, findField_whenNameAndTypeMatch_returnsTheField)
{
    ClassDef c = class_def("LT;");
    c.fields = {field("a", "I"), field("b", "J")};

    EXPECT_EQ(c.find_field("b", "J"), &c.fields[1]);
}

TEST(Types, findField_whenOnlyTheNameMatches_returnsNull)
{
    ClassDef c = class_def("LT;");
    c.fields = {field("a", "I")};

    EXPECT_EQ(c.find_field("a", "J"), nullptr);
}

TEST(Types, findField_whenOnlyTheTypeMatches_returnsNull)
{
    ClassDef c = class_def("LT;");
    c.fields = {field("a", "I")};

    EXPECT_EQ(c.find_field("b", "I"), nullptr);
}

TEST(Types, findField_whenTwoFieldsShareAName_returnsTheOneWithTheType)
{
    ClassDef c = class_def("LT;");
    c.fields = {field("a", "I"), field("a", "J")};

    EXPECT_EQ(c.find_field("a", "J"), &c.fields[1]);
}

TEST(Types, findField_whenTwoFieldsMatch_returnsTheFirst)
{
    ClassDef c = class_def("LT;");
    c.fields = {field("a", "I"), field("a", "I")};

    EXPECT_EQ(c.find_field("a", "I"), &c.fields[0]);
}

TEST(Types, findField_whenClassHasNoFields_returnsNull)
{
    ClassDef c = class_def("LT;");

    EXPECT_EQ(c.find_field("a", "I"), nullptr);
}

TEST(Types, findField_whenClassIsConst_returnsTheSameField)
{
    ClassDef c = class_def("LT;");
    c.fields = {field("a", "I"), field("b", "J")};
    const ClassDef &constant = c;

    const FieldDef *found = constant.find_field("b", "J");

    EXPECT_EQ(found, &c.fields[1]);
}

TEST(Types, findField_whenClassIsConstAndNothingMatches_returnsNull)
{
    const ClassDef c = class_def("LT;");

    EXPECT_EQ(c.find_field("a", "I"), nullptr);
}

TEST(Types, findMethod_whenNameAndProtoMatch_returnsTheMethod)
{
    ClassDef c = class_def("LT;");
    c.methods = {method("a", "()V"), method("b", "(I)V")};

    EXPECT_EQ(c.find_method("b", "(I)V"), &c.methods[1]);
}

TEST(Types, findMethod_whenOnlyTheNameMatches_returnsNull)
{
    ClassDef c = class_def("LT;");
    c.methods = {method("a", "()V")};

    EXPECT_EQ(c.find_method("a", "(I)V"), nullptr);
}

TEST(Types, findMethod_whenOnlyTheProtoMatches_returnsNull)
{
    ClassDef c = class_def("LT;");
    c.methods = {method("a", "()V")};

    EXPECT_EQ(c.find_method("b", "()V"), nullptr);
}

TEST(Types, findMethod_whenMethodIsOverloaded_returnsTheOverloadWithTheProto)
{
    ClassDef c = class_def("LT;");
    c.methods = {method("f", "(Ljava/lang/String;)V"), method("f", "(Ljava/lang/Object;)V")};

    EXPECT_EQ(c.find_method("f", "(Ljava/lang/Object;)V"), &c.methods[1]);
}

TEST(Types, findMethod_whenTwoMethodsMatch_returnsTheFirst)
{
    ClassDef c = class_def("LT;");
    c.methods = {method("a", "()V"), method("a", "()V")};

    EXPECT_EQ(c.find_method("a", "()V"), &c.methods[0]);
}

TEST(Types, findMethod_whenClassHasNoMethods_returnsNull)
{
    ClassDef c = class_def("LT;");

    EXPECT_EQ(c.find_method("a", "()V"), nullptr);
}

TEST(Types, findMethod_whenClassIsConst_returnsTheSameMethod)
{
    ClassDef c = class_def("LT;");
    c.methods = {method("a", "()V"), method("b", "(I)V")};
    const ClassDef &constant = c;

    const MethodDef *found = constant.find_method("b", "(I)V");

    EXPECT_EQ(found, &c.methods[1]);
}

TEST(Types, findMethod_whenClassIsConstAndNothingMatches_returnsNull)
{
    const ClassDef c = class_def("LT;");

    EXPECT_EQ(c.find_method("a", "()V"), nullptr);
}

TEST(Types, findClass_whenTypeMatches_returnsTheClass)
{
    Dex dex;
    dex.classes = {class_def("LA;"), class_def("LB;")};

    EXPECT_EQ(dex.find_class("LB;"), &dex.classes[1]);
}

TEST(Types, findClass_whenNoClassHasTheType_returnsNull)
{
    Dex dex;
    dex.classes = {class_def("LA;")};

    EXPECT_EQ(dex.find_class("LB;"), nullptr);
}

TEST(Types, findClass_whenTypeIsOnlyAPrefixOfAClass_returnsNull)
{
    Dex dex;
    dex.classes = {class_def("LA;")};

    EXPECT_EQ(dex.find_class("LA"), nullptr);
}

TEST(Types, findClass_whenTwoClassesMatch_returnsTheFirst)
{
    Dex dex;
    dex.classes = {class_def("LA;"), class_def("LA;")};

    EXPECT_EQ(dex.find_class("LA;"), &dex.classes[0]);
}

TEST(Types, findClass_whenDexHasNoClasses_returnsNull)
{
    Dex dex;

    EXPECT_EQ(dex.find_class("LA;"), nullptr);
}

TEST(Types, findClass_whenDexIsConst_returnsTheSameClass)
{
    Dex dex;
    dex.classes = {class_def("LA;"), class_def("LB;")};
    const Dex &constant = dex;

    const ClassDef *found = constant.find_class("LB;");

    EXPECT_EQ(found, &dex.classes[1]);
}

TEST(Types, findClass_whenDexIsConstAndNothingMatches_returnsNull)
{
    const Dex dex;

    EXPECT_EQ(dex.find_class("LA;"), nullptr);
}

TEST(Types, findClass_whenTheResultIsChanged_changesTheModel)
{
    Dex dex;
    dex.classes = {class_def("LA;")};

    dex.find_class("LA;")->access = AccessFlags::Public;

    EXPECT_EQ(dex.classes[0].access, AccessFlags::Public);
}

TEST(Types, shared_whenDefaultConstructed_holdsADefaultValue)
{
    Shared<std::string> shared;

    EXPECT_EQ(shared.get(), "");
}

TEST(Types, shared_whenBuiltFromAValue_holdsThatValue)
{
    Shared<std::string> shared = "text";

    EXPECT_EQ(*shared, "text");
    EXPECT_EQ(shared->size(), 4u);
}

TEST(Types, shared_whenBuiltFromTheMembersOfAnAggregate_holdsTheAggregate)
{
    Shared<MethodId> shared{"La;", "run", "()V"};

    EXPECT_EQ(shared.get(), (MethodId{"La;", "run", "()V"}));
}

TEST(Types, shared_whenCopied_refersToTheSameValue)
{
    Shared<std::string> shared = "text";

    Shared<std::string> copy = shared;

    EXPECT_EQ(&copy.get(), &shared.get());
}

TEST(Types, sharedEquals_whenTwoAllocationsHoldEqualValues_returnsTrue)
{
    Shared<std::string> a = "text";
    Shared<std::string> b = "text";

    EXPECT_TRUE(a == b);
}

TEST(Types, sharedEquals_whenValuesDiffer_returnsFalse)
{
    Shared<std::string> a = "text";
    Shared<std::string> b = "other";

    EXPECT_FALSE(a == b);
}

TEST(Types, sharedEquals_whenOneIsDefaultConstructedAndTheOtherHoldsADefaultValue_returnsTrue)
{
    Shared<std::string> empty;
    Shared<std::string> holds_default = std::string();

    EXPECT_TRUE(empty == holds_default);
}

TEST(Types, valueEquals_whenFloatsAreTheSameNaN_returnsTrue)
{
    float nan = std::numeric_limits<float>::quiet_NaN();

    EXPECT_TRUE(Value{Value::Float{nan}} == Value{Value::Float{nan}});
}

TEST(Types, valueEquals_whenFloatsArePositiveAndNegativeZero_returnsFalse)
{
    EXPECT_FALSE(Value{Value::Float{0.0f}} == Value{Value::Float{-0.0f}});
}

TEST(Types, valueEquals_whenDoublesAreTheSameNaN_returnsTrue)
{
    double nan = std::numeric_limits<double>::quiet_NaN();

    EXPECT_TRUE(Value{Value::Double{nan}} == Value{Value::Double{nan}});
}

TEST(Types, valueEquals_whenDoublesArePositiveAndNegativeZero_returnsFalse)
{
    EXPECT_FALSE(Value{Value::Double{0.0}} == Value{Value::Double{-0.0}});
}

TEST(Types, valueEquals_whenTheSameNumberHasAnotherType_returnsFalse)
{
    EXPECT_FALSE(Value{Value::Int{1}} == Value{Value::Long{1}});
}

TEST(Types, valueEquals_whenArraysHoldEqualValues_returnsTrue)
{
    Value a{Value::Array{{Value{Value::Int{1}}, Value{Value::String{"x"}}}}};
    Value b{Value::Array{{Value{Value::Int{1}}, Value{Value::String{"x"}}}}};

    EXPECT_TRUE(a == b);
}

TEST(Types, encodedAnnotationEquals_whenAnElementValueDiffers_returnsFalse)
{
    EncodedAnnotation a{"LA;", {{"x", Value{Value::Int{1}}}}};
    EncodedAnnotation b{"LA;", {{"x", Value{Value::Int{2}}}}};

    EXPECT_FALSE(a == b);
}

TEST(Types, encodedAnnotationEquals_whenTypeAndElementsMatch_returnsTrue)
{
    EncodedAnnotation a{"LA;", {{"x", Value{Value::Int{1}}}}};
    EncodedAnnotation b{"LA;", {{"x", Value{Value::Int{1}}}}};

    EXPECT_TRUE(a == b);
}

TEST(Types, newLabel_whenCalledTwice_returnsTwoDifferentLabels)
{
    Code code;

    Label first = code.new_label();
    Label second = code.new_label();

    EXPECT_NE(first, second);
}

TEST(Types, labelCount_whenThreeLabelsWereHandedOut_returnsThree)
{
    Code code;
    code.new_label();
    code.new_label();
    code.new_label();

    EXPECT_EQ(code.label_count(), 3u);
}

TEST(Types, labelCount_whenNoLabelWasHandedOut_returnsZero)
{
    Code code;

    EXPECT_EQ(code.label_count(), 0u);
}

TEST(Types, codeEquals_whenOnlyTheLabelCounterDiffers_returnsTrue)
{
    Code a;
    Code b;
    a.items = {Insn{ReturnVoid{}}};
    b.items = {Insn{ReturnVoid{}}};

    b.new_label();

    EXPECT_TRUE(a == b);
}

TEST(Types, codeEquals_whenRegisterCountsDiffer_returnsFalse)
{
    Code a;
    Code b;
    a.registers = 1;
    b.registers = 2;

    EXPECT_FALSE(a == b);
}

TEST(Types, codeEquals_whenItemsDiffer_returnsFalse)
{
    Code a;
    Code b;
    a.items = {Insn{ReturnVoid{}}};
    b.items = {Insn{Nop{}}};

    EXPECT_FALSE(a == b);
}

TEST(Types, dexEquals_whenACopyIsCompared_returnsTrue)
{
    Dex dex;
    dex.classes = {class_def("LA;")};
    dex.classes[0].methods = {method("a", "()V")};

    Dex copy = dex;

    EXPECT_TRUE(copy == dex);
}

TEST(Types, dexEquals_whenVersionsDiffer_returnsFalse)
{
    Dex a;
    Dex b;
    b.version = 39;

    EXPECT_FALSE(a == b);
}

} // namespace
} // namespace dexsplit::model
