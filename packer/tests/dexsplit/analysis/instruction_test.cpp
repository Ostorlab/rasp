// Tests for the Dalvik instruction decoder, run on hand-written code units.

#include "analysis/instruction.hpp"

#include <cstdint>
#include <gtest/gtest.h>
#include <initializer_list>
#include <limits>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace dexsplit {
namespace {

std::vector<Instruction> decode(std::initializer_list<uint16_t> units)
{
    std::vector<uint16_t> insns(units);
    return decode_instructions(insns);
}

template <typename T> const T *only(const std::vector<Instruction> &insns)
{
    return insns.size() == 1 ? std::get_if<T>(&insns[0]) : nullptr;
}

std::string render(std::initializer_list<uint16_t> units)
{
    auto insns = decode(units);
    return insns.empty() ? std::string("<nothing decoded>") : to_string(insns[0]);
}

uint16_t unit(uint8_t opcode, uint8_t high) { return static_cast<uint16_t>(opcode | (high << 8)); }

std::vector<uint32_t> offsets_of(const std::vector<Instruction> &insns)
{
    std::vector<uint32_t> offsets;
    for (const auto &insn : insns)
        offsets.push_back(base_of(insn).offset);
    return offsets;
}

TEST(Instruction, invokeKindFromOpcode_whenOpcodeIsAnInvoke_returnsItsKind)
{
    const std::pair<uint8_t, InvokeKind> cases[] = {
        {0x6e, InvokeKind::Virtual}, {0x6f, InvokeKind::Super},     {0x70, InvokeKind::Direct},
        {0x71, InvokeKind::Static},  {0x72, InvokeKind::Interface}, {0xfa, InvokeKind::Polymorphic},
        {0xfc, InvokeKind::Custom},
    };

    for (const auto &[opcode, kind] : cases)
        EXPECT_EQ(invoke_kind_from_opcode(opcode), kind) << "opcode " << int{opcode};
}

TEST(Instruction, invokeKindFromOpcode_whenOpcodeIsARangeInvoke_returnsTheKindOfItsPlainForm)
{
    const std::pair<uint8_t, InvokeKind> cases[] = {
        {0x74, InvokeKind::Virtual}, {0x75, InvokeKind::Super},     {0x76, InvokeKind::Direct},
        {0x77, InvokeKind::Static},  {0x78, InvokeKind::Interface}, {0xfb, InvokeKind::Polymorphic},
        {0xfd, InvokeKind::Custom},
    };

    for (const auto &[opcode, kind] : cases)
        EXPECT_EQ(invoke_kind_from_opcode(opcode), kind) << "opcode " << int{opcode};
}

TEST(Instruction, invokeKindFromOpcode_whenOpcodeIsNotAnInvoke_returnsNullopt)
{
    const std::set<int> invokes = {0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75,
                                   0x76, 0x77, 0x78, 0xfa, 0xfb, 0xfc, 0xfd};

    for (int opcode = 0; opcode < 256; ++opcode) {
        if (invokes.contains(opcode))
            continue;
        EXPECT_FALSE(invoke_kind_from_opcode(static_cast<uint8_t>(opcode)).has_value())
            << "opcode " << opcode;
    }
}

TEST(Instruction, typeRefKindFromOpcode_whenOpcodeCarriesAType_returnsItsKind)
{
    const std::pair<uint8_t, TypeRefKind> cases[] = {
        {0x1c, TypeRefKind::ConstClass},     {0x1f, TypeRefKind::CheckCast},
        {0x20, TypeRefKind::InstanceOf},     {0x22, TypeRefKind::NewInstance},
        {0x23, TypeRefKind::NewArray},       {0x24, TypeRefKind::FilledNewArray},
        {0x25, TypeRefKind::FilledNewArray},
    };

    for (const auto &[opcode, kind] : cases)
        EXPECT_EQ(type_ref_kind_from_opcode(opcode), kind) << "opcode " << int{opcode};
}

TEST(Instruction, typeRefKindFromOpcode_whenOpcodeIsArrayLength_returnsNullopt)
{
    EXPECT_FALSE(type_ref_kind_from_opcode(0x21).has_value());
}

TEST(Instruction, typeRefKindFromOpcode_whenOpcodeCarriesNoType_returnsNullopt)
{
    const std::set<int> typed = {0x1c, 0x1f, 0x20, 0x22, 0x23, 0x24, 0x25};

    for (int opcode = 0; opcode < 256; ++opcode) {
        if (typed.contains(opcode))
            continue;
        EXPECT_FALSE(type_ref_kind_from_opcode(static_cast<uint8_t>(opcode)).has_value())
            << "opcode " << opcode;
    }
}

TEST(Instruction, baseOf_whenInsnIsAnyVariant_returnsTheBaseOfThatVariant)
{
    Instruction insn = ConstStringInstruction{{4, 0x1a, 2}, 0, 1};

    const InstructionBase &base = base_of(insn);

    EXPECT_EQ(&base, &std::get<ConstStringInstruction>(insn).base);
    EXPECT_EQ(base.offset, 4u);
    EXPECT_EQ(base.opcode, 0x1a);
    EXPECT_EQ(base.size, 2);
}

TEST(Instruction, isTerminator_whenInsnIsAGoto_returnsTrue)
{
    auto insns = decode({0x0528, 0x0029, 0x0005, 0x002a, 0x0005, 0x0000});

    ASSERT_EQ(insns.size(), 3u);
    for (const auto &insn : insns)
        EXPECT_TRUE(is_terminator(insn)) << to_string(insn);
}

TEST(Instruction, isTerminator_whenInsnIsAConditionalBranch_returnsTrue)
{
    auto insns = decode({0x2132, 0x0003, 0x0538, 0x0003});

    ASSERT_EQ(insns.size(), 2u);
    for (const auto &insn : insns)
        EXPECT_TRUE(is_terminator(insn)) << to_string(insn);
}

TEST(Instruction, isTerminator_whenInsnIsASwitch_returnsTrue)
{
    auto insns = decode({0x002b, 0x0010, 0x0000, 0x002c, 0x0010, 0x0000});

    ASSERT_EQ(insns.size(), 2u);
    for (const auto &insn : insns)
        EXPECT_TRUE(is_terminator(insn)) << to_string(insn);
}

TEST(Instruction, isTerminator_whenInsnIsAReturn_returnsTrue)
{
    auto insns = decode({0x000e, 0x000f, 0x0010, 0x0011});

    ASSERT_EQ(insns.size(), 4u);
    for (const auto &insn : insns)
        EXPECT_TRUE(is_terminator(insn)) << to_string(insn);
}

TEST(Instruction, isTerminator_whenInsnIsAThrow_returnsTrue)
{
    auto insns = decode({0x0227});

    ASSERT_EQ(insns.size(), 1u);
    EXPECT_TRUE(is_terminator(insns[0]));
}

TEST(Instruction, isTerminator_whenInsnFallsThrough_returnsFalse)
{
    auto insns = decode({0x0000, 0x2101, 0x1012, 0x001a, 0x0001, 0x206e, 0x0003, 0x0001, 0x0160,
                         0x0000, 0x0190, 0x0302, 0x031d, 0x0126, 0x0010, 0x0000});

    ASSERT_EQ(insns.size(), 9u);
    for (const auto &insn : insns)
        EXPECT_FALSE(is_terminator(insn)) << to_string(insn);
}

TEST(Instruction, opcodeName_whenOpcodeIsUsed_returnsItsMnemonic)
{
    EXPECT_EQ(opcode_name(0x00), "nop");
    EXPECT_EQ(opcode_name(0x0e), "return-void");
    EXPECT_EQ(opcode_name(0x1a), "const-string");
    EXPECT_EQ(opcode_name(0x6e), "invoke-virtual");
    EXPECT_EQ(opcode_name(0x71), "invoke-static");
    EXPECT_EQ(opcode_name(0x78), "invoke-interface/range");
    EXPECT_EQ(opcode_name(0xfa), "invoke-polymorphic");
    EXPECT_EQ(opcode_name(0xff), "const-method-type");
}

TEST(Instruction, opcodeName_whenOpcodeIsUnused_returnsUnusedAndItsHexValue)
{
    EXPECT_EQ(opcode_name(0x3e), "unused-3e");
    EXPECT_EQ(opcode_name(0x73), "unused-73");
    EXPECT_EQ(opcode_name(0xf9), "unused-f9");
}

TEST(Instruction, toString_whenInsnIsNop_returnsTheMnemonicAlone)
{
    EXPECT_EQ(render({0x0000}), "nop");
}

TEST(Instruction, toString_whenInsnIsReturnVoid_returnsTheMnemonicAlone)
{
    EXPECT_EQ(render({0x000e}), "return-void");
}

TEST(Instruction, toString_whenInsnReturnsAValue_namesTheRegister)
{
    EXPECT_EQ(render({0x0311}), "return-object v3");
}

TEST(Instruction, toString_whenInsnIsThrow_namesTheRegister)
{
    EXPECT_EQ(render({0x0227}), "throw v2");
}

TEST(Instruction, toString_whenGotoIsBackward_printsANegativeOffset)
{
    EXPECT_EQ(render({0xf528}), "goto -11");
}

TEST(Instruction, toString_whenGotoIsForward_printsAPlusSign)
{
    EXPECT_EQ(render({0x0029, 0x0005}), "goto/16 +5");
}

TEST(Instruction, toString_whenInsnIsIf_printsBothRegistersAndTheOffset)
{
    EXPECT_EQ(render({0x2132, 0xfffd}), "if-eq v1, v2, -3");
}

TEST(Instruction, toString_whenInsnIsIfZero_printsTheRegisterAndTheOffset)
{
    EXPECT_EQ(render({0x0538, 0x0007}), "if-eqz v5, +7");
}

TEST(Instruction, toString_whenInsnIsSwitch_printsTheRegisterAndThePayloadOffset)
{
    EXPECT_EQ(render({0x042b, 0x0010, 0x0000}), "packed-switch v4, +16");
}

TEST(Instruction, toString_whenInsnIsMove_printsDestinationThenSource)
{
    EXPECT_EQ(render({0x2101}), "move v1, v2");
}

TEST(Instruction, toString_whenInsnIsMoveResult_printsTheDestinationOnly)
{
    EXPECT_EQ(render({0x050c}), "move-result-object v5");
}

TEST(Instruction, toString_whenInsnIsMoveException_printsTheDestinationOnly)
{
    EXPECT_EQ(render({0x020d}), "move-exception v2");
}

TEST(Instruction, toString_whenInsnIsConst_printsTheSignedValue)
{
    EXPECT_EQ(render({0xf312}), "const/4 v3, #-1");
}

TEST(Instruction, toString_whenInsnIsConstWide_printsThe64BitValue)
{
    EXPECT_EQ(render({0x0218, 0x2d18, 0x5444, 0x21fb, 0x4009}),
              "const-wide v2, #4614256656552045848");
}

TEST(Instruction, toString_whenInsnIsConstString_printsTheStringIndex)
{
    EXPECT_EQ(render({0x001a, 0x0001}), "const-string v0, string@1");
}

TEST(Instruction, toString_whenInsnIsConstClass_printsTheTypeIndex)
{
    EXPECT_EQ(render({0x021c, 0x0007}), "const-class v2, type@7");
}

TEST(Instruction, toString_whenInsnIsConstMethodHandle_printsTheIndex)
{
    EXPECT_EQ(render({0x01fe, 0x0004}), "const-method-handle v1, idx@4");
}

TEST(Instruction, toString_whenInsnIsCheckCast_printsOneRegisterAndTheTypeIndex)
{
    EXPECT_EQ(render({0x031f, 0x0007}), "check-cast v3, type@7");
}

TEST(Instruction, toString_whenInsnIsInstanceOf_printsTheSourceRegisterLast)
{
    EXPECT_EQ(render({0x2120, 0x0005}), "instance-of v1, type@5, v2");
}

TEST(Instruction, toString_whenInsnIsFilledNewArray_printsTheRegistersThenTheType)
{
    EXPECT_EQ(render({0x3024, 0x0005, 0x0321}), "filled-new-array {v1, v2, v3} type@5");
}

TEST(Instruction, toString_whenInsnIsMonitorEnter_namesTheRegister)
{
    EXPECT_EQ(render({0x031d}), "monitor-enter v3");
}

TEST(Instruction, toString_whenInsnIsFillArrayData_printsTheRegisterAndThePayloadOffset)
{
    EXPECT_EQ(render({0x0126, 0x0010, 0x0000}), "fill-array-data v1, +16");
}

TEST(Instruction, toString_whenInsnIsCompare_printsThreeRegisters)
{
    EXPECT_EQ(render({0x0231, 0x0003}), "cmp-long v2, v3, v0");
}

TEST(Instruction, toString_whenInsnIsArrayOp_printsTheArrayAndIndexAsASubscript)
{
    EXPECT_EQ(render({0x0144, 0x0302}), "aget v1, v2[v3]");
}

TEST(Instruction, toString_whenInsnIsAnInstanceFieldOp_printsTheObjectRegisterBeforeTheField)
{
    EXPECT_EQ(render({0x2152, 0x0007}), "iget v1, v2.field@7");
}

TEST(Instruction, toString_whenInsnIsAStaticFieldOp_printsTheFieldIndexAlone)
{
    EXPECT_EQ(render({0x0360, 0x0009}), "sget v3, field@9");
}

TEST(Instruction, toString_whenInvokeHasArguments_printsTheMethodIndexThenTheRegisters)
{
    EXPECT_EQ(render({0x206e, 0x0003, 0x0001}), "invoke-virtual method@3 {v1, v0}");
}

TEST(Instruction, toString_whenInvokeHasNoArgument_printsAnEmptyRegisterList)
{
    EXPECT_EQ(render({0x0071, 0x0001, 0x0000}), "invoke-static method@1 {}");
}

TEST(Instruction, toString_whenInsnIsInvokePolymorphic_printsTheMethodIndexAndNotThePrototype)
{
    EXPECT_EQ(render({0x20fa, 0x0010, 0x0021, 0x0020}), "invoke-polymorphic method@16 {v1, v2}");
}

TEST(Instruction, toString_whenInsnIsInvokeCustom_printsTheCallSiteIndex)
{
    EXPECT_EQ(render({0x10fc, 0x0002, 0x0003}), "invoke-custom site@2 {v3}");
}

TEST(Instruction, toString_whenInsnIsAUnaryOp_printsDestinationThenSource)
{
    EXPECT_EQ(render({0x217b}), "neg-int v1, v2");
}

TEST(Instruction, toString_whenInsnIsABinaryOp_printsThreeRegisters)
{
    EXPECT_EQ(render({0x0190, 0x0302}), "add-int v1, v2, v3");
}

TEST(Instruction, toString_whenInsnIsATwoAddressOp_printsTheDestinationTwice)
{
    EXPECT_EQ(render({0x21b0}), "add-int/2addr v1, v1, v2");
}

TEST(Instruction, toString_whenInsnIsABinaryLiteralOp_printsTheSignedLiteral)
{
    EXPECT_EQ(render({0x01d8, 0xff02}), "add-int/lit8 v1, v2, #-1");
}

TEST(Instruction, toString_whenOpcodeIsUnused_returnsItsUnusedName)
{
    EXPECT_EQ(render({0x0073}), "unused-73");
}

// The units are the body of TestDex.main in classes.dex, as dexdump shows it.
TEST(Instruction, toString_whenCodeIsAWholeMethodBody_rendersEachInstructionWithRawIndexes)
{
    auto insns =
        decode({0x0162, 0x0000, 0x0071, 0x0001, 0x0000, 0x000c, 0x206e, 0x0003, 0x0001, 0x000e});

    std::vector<std::string> rendered;
    for (const auto &insn : insns)
        rendered.push_back(to_string(insn));

    EXPECT_EQ(rendered,
              (std::vector<std::string>{"sget-object v1, field@0", "invoke-static method@1 {}",
                                        "move-result-object v0", "invoke-virtual method@3 {v1, v0}",
                                        "return-void"}));
}

TEST(Instruction, decodeInstructions_whenCodeIsEmpty_returnsNothing)
{
    EXPECT_TRUE(decode({}).empty());
}

TEST(Instruction, decodeInstructions_whenInsnIsNop_returnsANopOfOneUnit)
{
    auto insns = decode({0x0000});

    const auto *nop = only<NopInstruction>(insns);
    ASSERT_NE(nop, nullptr);
    EXPECT_EQ(nop->base.offset, 0u);
    EXPECT_EQ(nop->base.opcode, 0x00);
    EXPECT_EQ(nop->base.size, 1);
}

} // namespace
} // namespace dexsplit
