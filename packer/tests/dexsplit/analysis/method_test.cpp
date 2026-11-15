// Tests for Method, run on the files under fixtures/ and on copies with a patched method body.

#include "analysis/method.hpp"

#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <initializer_list>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "analysis/analysis_context.hpp"
#include "analysis/analysis_context_impl.hpp"
#include "analysis/class.hpp"
#include "analysis/instruction.hpp"
#include "common/ids.hpp"
#include "raw/parser.hpp"
#include "support/fixtures.hpp"

namespace dexsplit {
namespace {

using support::load_fixture;

// Offsets of code items, from dexdump -d.
constexpr std::size_t kCastsMakeArrayCode = 0x140;
constexpr std::size_t kClassesHelloDexCode = 0x150;
constexpr std::size_t kFibonacciClassifyCode = 0x140;
constexpr std::size_t kPolymorphicPetDescribeCode = 0x358;

// Where the class_data_item of classes.dex holds the access flags and the code offset of helloDex.
constexpr std::size_t kClassesHelloDexAccessFlags = 0x32c;
constexpr std::size_t kClassesHelloDexCodeOff = 0x32d;

constexpr std::size_t kProtoIdsOff = 0x4C;
constexpr std::size_t kProtoIdSize = 12;
constexpr std::size_t kProtoParametersOff = 8;
constexpr std::size_t kCodeInsnsSize = 12;
constexpr std::size_t kCodeInsns = 16;
constexpr uint32_t kOffsetPastTheFile = 0x00100000;

// Index of (Ljava/lang/String;)V in the proto_ids of shapes.dex.
constexpr std::size_t kShapesProtoStringToVoid = 3;

const MethodId kPrintln{"Ljava/io/PrintStream;", "println", "(Ljava/lang/String;)V"};
const MethodId kAppend{"Ljava/lang/StringBuilder;", "append",
                       "(Ljava/lang/String;)Ljava/lang/StringBuilder;"};
const MethodId kPetSound{"LPet;", "sound", "()Ljava/lang/String;"};
const FieldId kSystemOut{"Ljava/lang/System;", "out", "Ljava/io/PrintStream;"};

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

std::vector<uint8_t> with_code(std::vector<uint8_t> bytes, std::size_t code_off,
                               std::initializer_list<uint16_t> units)
{
    uint32_t insns_size = get_u32(bytes, code_off + kCodeInsnsSize);
    if (units.size() > insns_size)
        throw std::runtime_error("the new body is longer than the one it replaces");
    std::vector<uint16_t> body(units);
    body.resize(insns_size, 0x0000);
    for (std::size_t i = 0; i < body.size(); ++i)
        put_u16(bytes, code_off + kCodeInsns + 2 * i, body[i]);
    return bytes;
}

Method method_at(const std::vector<uint8_t> &bytes, std::string_view class_name, std::size_t index)
{
    auto context = AnalysisContext::from_dex_buffers({bytes});
    if (!context.has_value())
        throw std::runtime_error(context.error());
    for (const auto &cls : context->classes())
        if (cls.name() == class_name)
            return cls.methods().at(index);
    throw std::runtime_error("class not found: " + std::string(class_name));
}

Method method_of(std::string_view fixture, std::string_view class_name, std::size_t index)
{
    return method_at(load_fixture(fixture), class_name, index);
}

Method casts_make_array_with(std::initializer_list<uint16_t> units)
{
    return method_at(with_code(load_fixture("casts.dex"), kCastsMakeArrayCode, units), "LCasts;",
                     2);
}

Method pet_describe_with(std::initializer_list<uint16_t> units)
{
    return method_at(with_code(load_fixture("polymorphic.dex"), kPolymorphicPetDescribeCode, units),
                     "LPet;", 1);
}

std::vector<uint32_t> offsets_of(const std::vector<MethodCall> &calls)
{
    std::vector<uint32_t> offsets;
    for (const auto &call : calls)
        offsets.push_back(call.code_offset);
    return offsets;
}

std::vector<InvokeKind> kinds_of(const std::vector<MethodCall> &calls)
{
    std::vector<InvokeKind> kinds;
    for (const auto &call : calls)
        kinds.push_back(call.kind);
    return kinds;
}

std::vector<std::string> field_names_of(const std::vector<FieldAccess> &accesses)
{
    std::vector<std::string> names;
    for (const auto &access : accesses)
        names.push_back(access.field.name);
    return names;
}

std::shared_ptr<const detail::AnalysisContextImpl> impl_of(std::vector<uint8_t> bytes)
{
    auto impl = std::make_shared<detail::AnalysisContextImpl>();
    detail::ManagedBuffer buffer(std::move(bytes));
    auto dex = raw::parser::parse_buffer(buffer.bytes(), {.decode_strings = false});
    if (!dex.has_value())
        throw std::runtime_error(dex.error().message);
    impl->dex_files_vec.push_back(std::move(*dex));
    impl->slots.push_back(
        std::make_unique<detail::AnalysisContextImpl::DexSlot>(std::move(buffer)));
    return impl;
}

TEST(Method, constructor_whenGivenACodeOffset_readsTheCodeItemAtThatOffset)
{
    auto impl = impl_of(load_fixture("classes.dex"));

    Method method(impl, 0, 1, kClassesHelloDexCode);

    auto insns = method.instructions();
    ASSERT_EQ(insns.size(), 2u);
    EXPECT_TRUE(std::holds_alternative<ConstStringInstruction>(insns[0]));
    EXPECT_TRUE(std::holds_alternative<ReturnInstruction>(insns[1]));
}

TEST(Method, constructor_whenCodeOffsetIsZero_hasNoBody)
{
    auto impl = impl_of(load_fixture("classes.dex"));

    Method method(impl, 0, 1, 0);

    EXPECT_TRUE(method.instructions().empty());
    EXPECT_TRUE(method.calls().empty());
    EXPECT_TRUE(method.field_accesses().empty());
    EXPECT_TRUE(method.type_uses().empty());
}

TEST(Method, constructor_whenCodeOffsetIsOutOfFile_hasNoBody)
{
    auto impl = impl_of(load_fixture("classes.dex"));

    Method method(impl, 0, 1, kOffsetPastTheFile);

    EXPECT_TRUE(method.instructions().empty());
}

// helloDex is "const-string v0, string@0001" then "return-object v0".
TEST(Method, instructions_whenMethodHasCode_returnsItsDecodedBody)
{
    auto method = method_of("classes.dex", "LTestDex;", 1);

    auto insns = method.instructions();

    ASSERT_EQ(insns.size(), 2u);
    const auto *load = std::get_if<ConstStringInstruction>(&insns[0]);
    ASSERT_NE(load, nullptr);
    EXPECT_EQ(load->base.offset, 0u);
    EXPECT_EQ(load->dest, 0);
    EXPECT_EQ(load->string_index, 1u);
    const auto *ret = std::get_if<ReturnInstruction>(&insns[1]);
    ASSERT_NE(ret, nullptr);
    EXPECT_EQ(ret->base.offset, 2u);
    EXPECT_EQ(ret->base.opcode, 0x11);
    EXPECT_EQ(ret->reg, 0);
}

TEST(Method, instructions_whenMethodIsAbstract_returnsEmpty)
{
    for (std::size_t index : {0, 1}) {
        auto method = method_of("shapes.dex", "LShape;", index);

        EXPECT_TRUE(method.instructions().empty()) << index;
    }
}

// The patch declares helloDex "public static native" with no code; dexdump -i shows it so.
TEST(Method, instructions_whenMethodIsNative_returnsEmpty)
{
    auto bytes = load_fixture("classes.dex");
    bytes[kClassesHelloDexAccessFlags] = 0x89;
    bytes[kClassesHelloDexAccessFlags + 1] = 0x02;
    bytes[kClassesHelloDexAccessFlags + 2] = 0x00;
    auto method = method_at(bytes, "LTestDex;", 1);

    EXPECT_TRUE(method.instructions().empty());
}

TEST(Method, instructions_whenCalledTwice_returnsTheSameSpan)
{
    auto method = method_of("trycatch.dex", "LTryCatch;", 1);

    auto first = method.instructions();
    auto second = method.instructions();

    ASSERT_FALSE(first.empty());
    EXPECT_EQ(first.data(), second.data());
    EXPECT_EQ(first.size(), second.size());
}

TEST(Method, instructions_whenMethodHasCode_returnsContiguousOffsetsFromZero)
{
    for (std::size_t index : {0, 1, 2}) {
        auto method = method_of("trycatch.dex", "LTryCatch;", index);

        auto insns = method.instructions();

        ASSERT_FALSE(insns.empty()) << index;
        EXPECT_EQ(base_of(insns[0]).offset, 0u) << index;
        for (std::size_t i = 1; i < insns.size(); ++i) {
            const auto &previous = base_of(insns[i - 1]);
            EXPECT_EQ(base_of(insns[i]).offset, previous.offset + previous.size)
                << "method " << index << " instruction " << i;
        }
    }
}

// divide has 5 code units and safeParse 33.
TEST(Method, instructions_whenMethodHasCode_coversEveryCodeUnit)
{
    const std::pair<std::size_t, uint32_t> cases[] = {{1, 5}, {2, 33}};
    for (const auto &[index, insns_size] : cases) {
        auto method = method_of("trycatch.dex", "LTryCatch;", index);

        uint32_t total = 0;
        for (const auto &insn : method.instructions())
            total += base_of(insn).size;

        EXPECT_EQ(total, insns_size) << index;
    }
}

TEST(Method, instructions_whenBodyEndsWithAReturn_returnsAReturnLast)
{
    auto method = method_of("trycatch.dex", "LTryCatch;", 1);

    auto insns = method.instructions();

    ASSERT_EQ(insns.size(), 5u);
    const auto *ret = std::get_if<ReturnInstruction>(&insns.back());
    ASSERT_NE(ret, nullptr);
    EXPECT_EQ(ret->reg, 0);
}

// safeParse has "goto 001b // +000a" at 0x11, its tenth instruction.
TEST(Method, instructions_whenBodyHasAGoto_returnsItsBranchOffset)
{
    auto method = method_of("trycatch.dex", "LTryCatch;", 2);

    auto insns = method.instructions();

    ASSERT_EQ(insns.size(), 18u);
    const auto *jump = std::get_if<GotoInstruction>(&insns[9]);
    ASSERT_NE(jump, nullptr);
    EXPECT_EQ(jump->base.offset, 0x11u);
    EXPECT_EQ(jump->branch_offset, 10);
}

// safeParse has "invoke-static {v2}, method@0004" at 0x02 and "move-result v2" at 0x05.
TEST(Method, instructions_whenBodyHasAnInvoke_returnsItsMethodIndexAndRegisters)
{
    auto method = method_of("trycatch.dex", "LTryCatch;", 2);

    auto insns = method.instructions();

    ASSERT_EQ(insns.size(), 18u);
    const auto *invoke = std::get_if<InvokeInstruction>(&insns[1]);
    ASSERT_NE(invoke, nullptr);
    EXPECT_EQ(invoke->base.offset, 2u);
    EXPECT_EQ(invoke->base.opcode, 0x71);
    EXPECT_EQ(invoke->method_index, 4u);
    EXPECT_EQ(invoke->arg_regs, (std::vector<uint16_t>{2}));
}

TEST(Method, instructions_whenBodyHasAMoveResult_returnsItsDestination)
{
    auto method = method_of("trycatch.dex", "LTryCatch;", 2);

    auto insns = method.instructions();

    ASSERT_EQ(insns.size(), 18u);
    const auto *move = std::get_if<MoveInstruction>(&insns[2]);
    ASSERT_NE(move, nullptr);
    EXPECT_EQ(move->base.offset, 5u);
    EXPECT_EQ(move->dest, 2);
}

// Circle.<init> has "iput-wide v2, v0, field@0001" at 0x03.
TEST(Method, instructions_whenBodyWritesAWideField_returnsPairWidth)
{
    auto method = method_of("shapes.dex", "LCircle;", 0);

    auto insns = method.instructions();

    ASSERT_EQ(insns.size(), 3u);
    const auto *field = std::get_if<FieldInstruction>(&insns[1]);
    ASSERT_NE(field, nullptr);
    EXPECT_EQ(field->width, OperandWidth::Pair);
    EXPECT_EQ(field->value_reg, 2);
    EXPECT_EQ(field->object_reg, 0);
    EXPECT_EQ(field->field_index, 1u);
}

// The new body is a packed-switch at 0, two instructions, its 8-unit payload at 6, then nops.
TEST(Method, instructions_whenBodyHasASwitchPayload_leavesThePayloadOut)
{
    auto bytes = with_code(load_fixture("fibonacci.dex"), kFibonacciClassifyCode,
                           {0x032b, 0x0006, 0x0000, 0x031a, 0x000e, 0x0311, 0x0100, 0x0002, 0x0000,
                            0x0000, 0x0003, 0x0000, 0x0003, 0x0000});
    auto method = method_at(bytes, "LFibonacci;", 1);

    auto insns = method.instructions();

    ASSERT_EQ(insns.size(), 26u);
    const auto *sw = std::get_if<SwitchInstruction>(&insns[0]);
    ASSERT_NE(sw, nullptr);
    ASSERT_EQ(sw->cases.size(), 2u);
    EXPECT_EQ(sw->cases[1].key, 1);
    EXPECT_EQ(sw->cases[1].target, 3);
    EXPECT_EQ(base_of(insns[2]).offset, 5u);
    EXPECT_EQ(base_of(insns[3]).offset, 14u);
}

TEST(Method, instructions_whenCodeOffsetIsOutOfFile_returnsEmpty)
{
    auto bytes = load_fixture("classes.dex");
    bytes[kClassesHelloDexCodeOff] = 0xFF;
    bytes[kClassesHelloDexCodeOff + 1] = 0x7F;
    auto method = method_at(bytes, "LTestDex;", 1);

    EXPECT_TRUE(method.instructions().empty());
}

TEST(Method, instructions_whenCodeItemIsCutOffByTheEndOfTheFile_returnsEmpty)
{
    auto bytes = load_fixture("classes.dex");
    put_u32(bytes, kClassesHelloDexCode + kCodeInsnsSize, kOffsetPastTheFile);
    auto method = method_at(bytes, "LTestDex;", 1);

    EXPECT_TRUE(method.instructions().empty());
}

// main calls helloDex at 0x02 and println at 0x06.
TEST(Method, calls_whenBodyInvokesStaticAndVirtualMethods_returnsEachTargetInCodeOrder)
{
    auto method = method_of("classes.dex", "LTestDex;", 2);

    auto calls = method.calls();

    ASSERT_EQ(calls.size(), 2u);
    EXPECT_EQ(calls[0].code_offset, 2u);
    EXPECT_EQ(calls[0].target, (MethodId{"LTestDex;", "helloDex", "()Ljava/lang/String;"}));
    EXPECT_EQ(calls[0].kind, InvokeKind::Static);
    EXPECT_EQ(calls[1].code_offset, 6u);
    EXPECT_EQ(calls[1].target, kPrintln);
    EXPECT_EQ(calls[1].kind, InvokeKind::Virtual);
}

TEST(Method, calls_whenBodyInvokesAConstructor_returnsADirectCall)
{
    auto method = method_of("classes.dex", "LTestDex;", 0);

    auto calls = method.calls();

    ASSERT_EQ(calls.size(), 1u);
    EXPECT_EQ(calls[0].code_offset, 0u);
    EXPECT_EQ(calls[0].target, (MethodId{"Ljava/lang/Object;", "<init>", "()V"}));
    EXPECT_EQ(calls[0].kind, InvokeKind::Direct);
}

// Dog.describe has "invoke-super {v2}, LPet;.describe:()Ljava/lang/String;" at 0x05.
TEST(Method, calls_whenBodyInvokesSuper_returnsASuperCall)
{
    auto method = method_of("polymorphic.dex", "LDog;", 1);

    auto calls = method.calls();

    ASSERT_EQ(calls.size(), 5u);
    EXPECT_EQ(calls[1].code_offset, 5u);
    EXPECT_EQ(calls[1].target, (MethodId{"LPet;", "describe", "()Ljava/lang/String;"}));
    EXPECT_EQ(calls[1].kind, InvokeKind::Super);
}

TEST(Method, calls_whenBodyInvokesAnInterfaceMethod_returnsAnInterfaceCall)
{
    auto method = method_of("polymorphic.dex", "LKennel;", 2);

    auto calls = method.calls();

    ASSERT_EQ(calls.size(), 1u);
    EXPECT_EQ(calls[0].target, (MethodId{"LAnimal;", "sound", "()Ljava/lang/String;"}));
    EXPECT_EQ(calls[0].kind, InvokeKind::Interface);
}

// Leaf declares neither m nor s: Mid defines m and Base defines s.
TEST(Method, calls_whenTargetIsInherited_returnsTheClassNamedAtTheCallSite)
{
    auto virtual_call = method_of("inherit.dex", "LUseA;", 1).calls();
    auto static_call = method_of("inherit.dex", "LUseA;", 2).calls();

    ASSERT_EQ(virtual_call.size(), 1u);
    ASSERT_EQ(static_call.size(), 1u);
    EXPECT_EQ(virtual_call[0].target, (MethodId{"LLeaf;", "m", "()V"}));
    EXPECT_EQ(static_call[0].target, (MethodId{"LLeaf;", "s", "()V"}));
}

TEST(Method, calls_whenTargetIsOutsideTheFile_returnsItsDescriptorAllTheSame)
{
    auto method = method_of("inherit.dex", "LUseE;", 2);

    auto calls = method.calls();

    ASSERT_EQ(calls.size(), 1u);
    EXPECT_EQ(calls[0].target, (MethodId{"Ljava/util/ArrayList;", "size", "()I"}));
}

// RequestChangePasswordTask$1.run calls Toast.makeText at 0x44.
TEST(Method, calls_whenTargetTakesSeveralParameters_returnsTheFullPrototype)
{
    auto method = method_of(
        "sample.dex", "Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask$1;", 1);

    auto calls = method.calls();

    const MethodCall *make_text = nullptr;
    for (const auto &call : calls)
        if (call.code_offset == 0x44)
            make_text = &call;
    ASSERT_NE(make_text, nullptr);
    EXPECT_EQ(make_text->target, (MethodId{"Landroid/widget/Toast;", "makeText",
                                           "(Landroid/content/Context;Ljava/lang/CharSequence;I)"
                                           "Landroid/widget/Toast;"}));
    EXPECT_EQ(make_text->kind, InvokeKind::Static);
}

TEST(Method, calls_whenTargetTakesAnArray_returnsTheArrayDescriptorInThePrototype)
{
    auto method = method_of("sample.dex", "Lcom/android/insecurebankv2/ChangePassword$1;", 1);

    auto calls = method.calls();

    ASSERT_EQ(calls.size(), 2u);
    EXPECT_EQ(calls[1].code_offset, 0x11u);
    EXPECT_EQ(calls[1].target,
              (MethodId{"Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask;",
                        "execute", "([Ljava/lang/Object;)Landroid/os/AsyncTask;"}));
}

// Pet.describe calls StringBuilder.append at 0x07, 0x0c and 0x13.
TEST(Method, calls_whenBodyInvokesTheSameMethodSeveralTimes_returnsOneCallPerSite)
{
    auto method = method_of("polymorphic.dex", "LPet;", 1);

    auto calls = method.calls();

    EXPECT_EQ(offsets_of(calls), (std::vector<uint32_t>{0x02, 0x07, 0x0c, 0x0f, 0x13, 0x16}));
    ASSERT_EQ(calls.size(), 6u);
    EXPECT_EQ(calls[1].target, kAppend);
    EXPECT_EQ(calls[2].target, kAppend);
    EXPECT_EQ(calls[4].target, kAppend);
}

TEST(Method, calls_whenBodyHasNoInvoke_returnsEmpty)
{
    auto method = method_of("classes.dex", "LTestDex;", 1);

    EXPECT_TRUE(method.calls().empty());
}

TEST(Method, calls_whenMethodIsAbstract_returnsEmpty)
{
    auto method = method_of("shapes.dex", "LShape;", 0);

    EXPECT_TRUE(method.calls().empty());
}

// dexdump -i shows the new body as the five range invokes of methods 11, 10, 12, 7 and 0.
TEST(Method, calls_whenBodyUsesRangeInvokes_returnsTheKindOfEachOpcode)
{
    auto method =
        pet_describe_with({0x0174, 0x000b, 0x0002, 0x0175, 0x000a, 0x0002, 0x0176, 0x000c, 0x0002,
                           0x0177, 0x0007, 0x0002, 0x0178, 0x0000, 0x0002, 0x0011});

    auto calls = method.calls();

    EXPECT_EQ(offsets_of(calls), (std::vector<uint32_t>{0, 3, 6, 9, 12}));
    EXPECT_EQ(kinds_of(calls),
              (std::vector<InvokeKind>{InvokeKind::Virtual, InvokeKind::Super, InvokeKind::Direct,
                                       InvokeKind::Static, InvokeKind::Interface}));
    ASSERT_EQ(calls.size(), 5u);
    EXPECT_EQ(calls[0].target, kPetSound);
    EXPECT_EQ(calls[3].target, (MethodId{"LKennel;", "dogNoise", "(LDog;)Ljava/lang/String;"}));
}

// dexdump -i shows the new body as two invoke-polymorphic forms, then an invoke-virtual at 0x08.
TEST(Method, calls_whenBodyInvokesPolymorphic_returnsAPolymorphicCallToTheNamedMethod)
{
    auto method = pet_describe_with({0x10fa, 0x000f, 0x0002, 0x0000, 0x01fb, 0x000e, 0x0002, 0x0003,
                                     0x106e, 0x000b, 0x0002, 0x0011});

    auto calls = method.calls();

    ASSERT_EQ(calls.size(), 3u);
    EXPECT_EQ(calls[0].code_offset, 0u);
    EXPECT_EQ(calls[0].target,
              (MethodId{"Ljava/lang/StringBuilder;", "toString", "()Ljava/lang/String;"}));
    EXPECT_EQ(calls[0].kind, InvokeKind::Polymorphic);
    EXPECT_EQ(calls[1].code_offset, 4u);
    EXPECT_EQ(calls[1].target, kAppend);
    EXPECT_EQ(calls[1].kind, InvokeKind::Polymorphic);
}

TEST(Method, calls_whenAnInvokeFollowsAPolymorphicOne_returnsItAtItsOwnOffset)
{
    auto method = pet_describe_with({0x10fa, 0x000f, 0x0002, 0x0000, 0x01fb, 0x000e, 0x0002, 0x0003,
                                     0x106e, 0x000b, 0x0002, 0x0011});

    auto calls = method.calls();

    ASSERT_EQ(calls.size(), 3u);
    EXPECT_EQ(calls[2].code_offset, 8u);
    EXPECT_EQ(calls[2].target, kPetSound);
    EXPECT_EQ(calls[2].kind, InvokeKind::Virtual);
}

// dexdump -i shows the new body as two invoke-custom forms, then an invoke-virtual at 0x06.
TEST(Method, calls_whenBodyInvokesCustom_returnsNoCallForTheCallSite)
{
    auto method = pet_describe_with(
        {0x10fc, 0x0000, 0x0002, 0x01fd, 0x0000, 0x0002, 0x106e, 0x000b, 0x0002, 0x0011});

    auto calls = method.calls();

    ASSERT_EQ(calls.size(), 1u);
    EXPECT_EQ(calls[0].code_offset, 6u);
    EXPECT_EQ(calls[0].target, kPetSound);
}

TEST(Method, calls_whenMethodIndexIsOutOfRange_returnsAnEmptyTarget)
{
    auto method = pet_describe_with({0x0071, 0xffff, 0x0000, 0x0011});

    auto calls = method.calls();

    ASSERT_EQ(calls.size(), 1u);
    EXPECT_EQ(calls[0].target, MethodId{});
    EXPECT_EQ(calls[0].kind, InvokeKind::Static);
}

TEST(Method, calls_whenParameterListIsOutOfFile_marksThePrototypeUnparseable)
{
    auto bytes = load_fixture("shapes.dex");
    put_u32(bytes,
            get_u32(bytes, kProtoIdsOff) + kShapesProtoStringToVoid * kProtoIdSize +
                kProtoParametersOff,
            kOffsetPastTheFile);
    auto method = method_at(bytes, "LCircle;", 0);

    auto calls = method.calls();

    ASSERT_EQ(calls.size(), 1u);
    EXPECT_EQ(calls[0].target, (MethodId{"LAbstractShape;", "<init>", "(<unparseable>)V"}));
}

TEST(Method, fieldAccesses_whenBodyReadsAStaticField_returnsAStaticRead)
{
    auto method = method_of("classes.dex", "LTestDex;", 2);

    auto accesses = method.field_accesses();

    ASSERT_EQ(accesses.size(), 1u);
    EXPECT_EQ(accesses[0].code_offset, 0u);
    EXPECT_EQ(accesses[0].field, kSystemOut);
    EXPECT_TRUE(accesses[0].is_static);
    EXPECT_FALSE(accesses[0].is_write);
}

// <clinit> of MultiStringTest has "sput-object v0, LMultiStringTest;.greeting" at 0x02.
TEST(Method, fieldAccesses_whenBodyWritesAStaticField_returnsAStaticWrite)
{
    auto method = method_of("multistring.dex", "LMultiStringTest;", 0);

    auto accesses = method.field_accesses();

    ASSERT_EQ(accesses.size(), 7u);
    EXPECT_EQ(accesses[0].code_offset, 2u);
    EXPECT_EQ(accesses[0].field, (FieldId{"LMultiStringTest;", "greeting", "Ljava/lang/String;"}));
    EXPECT_TRUE(accesses[0].is_static);
    EXPECT_TRUE(accesses[0].is_write);
}

TEST(Method, fieldAccesses_whenBodyReadsAnInstanceField_returnsAnInstanceRead)
{
    auto method = method_of("shapes.dex", "LAbstractShape;", 1);

    auto accesses = method.field_accesses();

    ASSERT_EQ(accesses.size(), 1u);
    EXPECT_EQ(accesses[0].code_offset, 0u);
    EXPECT_EQ(accesses[0].field, (FieldId{"LAbstractShape;", "color", "Ljava/lang/String;"}));
    EXPECT_FALSE(accesses[0].is_static);
    EXPECT_FALSE(accesses[0].is_write);
}

TEST(Method, fieldAccesses_whenBodyWritesAnInstanceField_returnsAnInstanceWrite)
{
    auto method = method_of("shapes.dex", "LCircle;", 0);

    auto accesses = method.field_accesses();

    ASSERT_EQ(accesses.size(), 1u);
    EXPECT_EQ(accesses[0].code_offset, 3u);
    EXPECT_EQ(accesses[0].field, (FieldId{"LCircle;", "radius", "D"}));
    EXPECT_FALSE(accesses[0].is_static);
    EXPECT_TRUE(accesses[0].is_write);
}

// Rectangle.<init> writes width at 0x03 and height at 0x05; height has the lower field id.
TEST(Method, fieldAccesses_whenBodyTouchesSeveralFields_returnsThemInCodeOrder)
{
    auto method = method_of("shapes.dex", "LRectangle;", 0);

    auto accesses = method.field_accesses();

    EXPECT_EQ(field_names_of(accesses), (std::vector<std::string>{"width", "height"}));
    ASSERT_EQ(accesses.size(), 2u);
    EXPECT_EQ(accesses[0].code_offset, 3u);
    EXPECT_EQ(accesses[1].code_offset, 5u);
}

TEST(Method, fieldAccesses_whenBodyTouchesTheSameFieldSeveralTimes_returnsOneAccessPerSite)
{
    auto method = method_of("multistring.dex", "LMultiStringTest;", 2);

    auto accesses = method.field_accesses();

    EXPECT_EQ(
        field_names_of(accesses),
        (std::vector<std::string>{"out", "greeting", "out", "farewell", "out", "question", "out",
                                  "answer", "out", "emoji", "out", "empty", "out", "withNull"}));
}

// onClick reads this$0 at 0x02 and 0x0b, and ChangePassword.uname at 0x0d.
TEST(Method, fieldAccesses_whenFieldBelongsToAnotherClass_returnsThatClass)
{
    auto method = method_of("sample.dex", "Lcom/android/insecurebankv2/ChangePassword$1;", 1);

    auto accesses = method.field_accesses();

    ASSERT_EQ(accesses.size(), 3u);
    EXPECT_EQ(accesses[0].field, (FieldId{"Lcom/android/insecurebankv2/ChangePassword$1;", "this$0",
                                          "Lcom/android/insecurebankv2/ChangePassword;"}));
    EXPECT_EQ(accesses[2].code_offset, 0x0du);
    EXPECT_EQ(accesses[2].field, (FieldId{"Lcom/android/insecurebankv2/ChangePassword;", "uname",
                                          "Ljava/lang/String;"}));
}

TEST(Method, fieldAccesses_whenBodyTouchesNoField_returnsEmpty)
{
    auto method = method_of("classes.dex", "LTestDex;", 1);

    EXPECT_TRUE(method.field_accesses().empty());
}

TEST(Method, fieldAccesses_whenMethodIsAbstract_returnsEmpty)
{
    auto method = method_of("shapes.dex", "LShape;", 0);

    EXPECT_TRUE(method.field_accesses().empty());
}

TEST(Method, fieldAccesses_whenFieldIndexIsOutOfRange_returnsAnEmptyField)
{
    auto method = pet_describe_with({0x0060, 0xffff, 0x0011});

    auto accesses = method.field_accesses();

    ASSERT_EQ(accesses.size(), 1u);
    EXPECT_EQ(accesses[0].field, FieldId{});
    EXPECT_TRUE(accesses[0].is_static);
    EXPECT_FALSE(accesses[0].is_write);
}

TEST(Method, typeUses_whenBodyCreatesAnObject_returnsANewInstanceUse)
{
    auto method = method_of("polymorphic.dex", "LPet;", 1);

    auto uses = method.type_uses();

    ASSERT_EQ(uses.size(), 1u);
    EXPECT_EQ(uses[0].code_offset, 0u);
    EXPECT_EQ(uses[0].descriptor, "Ljava/lang/StringBuilder;");
    EXPECT_EQ(uses[0].kind, TypeRefKind::NewInstance);
}

// doCast has "check-cast v0, Ljava/lang/String;" at 0x02.
TEST(Method, typeUses_whenBodyCastsAnObject_returnsACheckCastUse)
{
    auto method = method_of("casts.dex", "LCasts;", 1);

    auto uses = method.type_uses();

    ASSERT_EQ(uses.size(), 1u);
    EXPECT_EQ(uses[0].code_offset, 2u);
    EXPECT_EQ(uses[0].descriptor, "Ljava/lang/String;");
    EXPECT_EQ(uses[0].kind, TypeRefKind::CheckCast);
}

// makeArray has "new-array v0, v0, [Ljava/lang/String;" at 0x01.
TEST(Method, typeUses_whenBodyAllocatesAnArray_returnsTheArrayType)
{
    auto method = method_of("casts.dex", "LCasts;", 2);

    auto uses = method.type_uses();

    ASSERT_EQ(uses.size(), 1u);
    EXPECT_EQ(uses[0].code_offset, 1u);
    EXPECT_EQ(uses[0].descriptor, "[Ljava/lang/String;");
    EXPECT_EQ(uses[0].kind, TypeRefKind::NewArray);
}

// callPreferences has "const-class v1, Lcom/android/insecurebankv2/FilePrefActivity;" at 0x02.
TEST(Method, typeUses_whenBodyLoadsAClassConstant_returnsAConstClassUse)
{
    auto method = method_of("sample.dex", "Lcom/android/insecurebankv2/ChangePassword;", 7);

    auto uses = method.type_uses();

    ASSERT_EQ(uses.size(), 2u);
    EXPECT_EQ(uses[1].code_offset, 2u);
    EXPECT_EQ(uses[1].descriptor, "Lcom/android/insecurebankv2/FilePrefActivity;");
    EXPECT_EQ(uses[1].kind, TypeRefKind::ConstClass);
}

// dexdump -i shows the new body as "instance-of v0, v2, Ljava/lang/String;".
TEST(Method, typeUses_whenBodyTestsAType_returnsAnInstanceOfUse)
{
    auto method = casts_make_array_with({0x2020, 0x0002, 0x0011});

    auto uses = method.type_uses();

    ASSERT_EQ(uses.size(), 1u);
    EXPECT_EQ(uses[0].code_offset, 0u);
    EXPECT_EQ(uses[0].descriptor, "Ljava/lang/String;");
    EXPECT_EQ(uses[0].kind, TypeRefKind::InstanceOf);
}

// dexdump -i shows the new body as "filled-new-array {v2, v3, v4}, [Ljava/lang/String;".
TEST(Method, typeUses_whenBodyFillsANewArray_returnsAFilledNewArrayUse)
{
    auto method = casts_make_array_with({0x3024, 0x0004, 0x0432, 0x000c, 0x0011});

    auto uses = method.type_uses();

    ASSERT_EQ(uses.size(), 1u);
    EXPECT_EQ(uses[0].code_offset, 0u);
    EXPECT_EQ(uses[0].descriptor, "[Ljava/lang/String;");
    EXPECT_EQ(uses[0].kind, TypeRefKind::FilledNewArray);
}

// dexdump -i shows the new body as "filled-new-array/range {v2, v3, v4}, [Ljava/lang/String;".
TEST(Method, typeUses_whenBodyFillsANewArrayFromARange_returnsAFilledNewArrayUse)
{
    auto method = casts_make_array_with({0x0325, 0x0004, 0x0002, 0x000c, 0x0011});

    auto uses = method.type_uses();

    ASSERT_EQ(uses.size(), 1u);
    EXPECT_EQ(uses[0].descriptor, "[Ljava/lang/String;");
    EXPECT_EQ(uses[0].kind, TypeRefKind::FilledNewArray);
}

// dexdump -i shows the new body as these six instructions, one every two code units.
TEST(Method, typeUses_whenBodyHasEveryKindOfUse_returnsThemInCodeOrder)
{
    auto method = casts_make_array_with({0x001c, 0x0002, 0x021f, 0x0002, 0x2020, 0x0002, 0x0022,
                                         0x0001, 0x0023, 0x0004, 0x3024, 0x0004, 0x0432});

    auto uses = method.type_uses();

    ASSERT_EQ(uses.size(), 6u);
    const TypeRefKind kinds[] = {TypeRefKind::ConstClass, TypeRefKind::CheckCast,
                                 TypeRefKind::InstanceOf, TypeRefKind::NewInstance,
                                 TypeRefKind::NewArray,   TypeRefKind::FilledNewArray};
    const std::string_view descriptors[] = {"Ljava/lang/String;",  "Ljava/lang/String;",
                                            "Ljava/lang/String;",  "Ljava/lang/Object;",
                                            "[Ljava/lang/String;", "[Ljava/lang/String;"};
    for (std::size_t i = 0; i < uses.size(); ++i) {
        EXPECT_EQ(uses[i].code_offset, 2 * i) << i;
        EXPECT_EQ(uses[i].kind, kinds[i]) << i;
        EXPECT_EQ(uses[i].descriptor, descriptors[i]) << i;
    }
}

TEST(Method, typeUses_whenBodyReadsAnArrayLength_returnsNoUseForIt)
{
    auto method = casts_make_array_with({0x0021, 0x0011});

    EXPECT_TRUE(method.type_uses().empty());
}

TEST(Method, typeUses_whenBodyUsesNoType_returnsEmpty)
{
    auto method = method_of("classes.dex", "LTestDex;", 2);

    EXPECT_TRUE(method.type_uses().empty());
}

TEST(Method, typeUses_whenMethodIsAbstract_returnsEmpty)
{
    auto method = method_of("shapes.dex", "LShape;", 0);

    EXPECT_TRUE(method.type_uses().empty());
}

TEST(Method, typeUses_whenTypeIndexIsOutOfRange_returnsAnEmptyDescriptor)
{
    auto method = casts_make_array_with({0x001c, 0xffff, 0x0011});

    auto uses = method.type_uses();

    ASSERT_EQ(uses.size(), 1u);
    EXPECT_EQ(uses[0].descriptor, "");
    EXPECT_EQ(uses[0].kind, TypeRefKind::ConstClass);
}

TEST(Method, typeUses_whenCalledTwice_returnsDescriptorsInTheSameStorage)
{
    auto method = method_of("casts.dex", "LCasts;", 1);

    auto first = method.type_uses();
    auto second = method.type_uses();

    ASSERT_EQ(first.size(), 1u);
    ASSERT_EQ(second.size(), 1u);
    EXPECT_EQ(first[0].descriptor.data(), second[0].descriptor.data());
}

TEST(Method, copyConstructor_whenHandleIsCopied_readsTheSameBody)
{
    auto method = method_of("classes.dex", "LTestDex;", 2);

    Method copy = method;

    EXPECT_EQ(copy.instructions().data(), method.instructions().data());
    EXPECT_EQ(copy.calls().size(), 2u);
}

} // namespace
} // namespace dexsplit
