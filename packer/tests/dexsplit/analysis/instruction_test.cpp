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

TEST(Instruction, decodeInstructions_whenInsnsFollowEachOther_returnsContiguousOffsets)
{
    auto insns = decode({0x1012, 0x001a, 0x0001, 0x0014, 0x5678, 0x1234, 0x0018, 0x0001, 0x0000,
                         0x0000, 0x0000, 0x000e});

    ASSERT_EQ(insns.size(), 5u);
    EXPECT_EQ(offsets_of(insns), (std::vector<uint32_t>{0, 1, 3, 6, 11}));
    EXPECT_EQ(base_of(insns[0]).size, 1);
    EXPECT_EQ(base_of(insns[1]).size, 2);
    EXPECT_EQ(base_of(insns[2]).size, 3);
    EXPECT_EQ(base_of(insns[3]).size, 5);
    EXPECT_EQ(base_of(insns[4]).size, 1);
}

TEST(Instruction, decodeInstructions_whenInsnIsMove_returnsFourBitRegisters)
{
    auto insns = decode({0x2101});

    const auto *move = only<MoveInstruction>(insns);
    ASSERT_NE(move, nullptr);
    EXPECT_EQ(move->dest, 1);
    EXPECT_EQ(move->src, 2);
    EXPECT_EQ(move->width, OperandWidth::Single);
    EXPECT_EQ(move->base.size, 1);
}

TEST(Instruction, decodeInstructions_whenInsnIsMoveFrom16_returnsASixteenBitSource)
{
    auto insns = decode({0x0a02, 0x1234});

    const auto *move = only<MoveInstruction>(insns);
    ASSERT_NE(move, nullptr);
    EXPECT_EQ(move->dest, 0x0a);
    EXPECT_EQ(move->src, 0x1234);
    EXPECT_EQ(move->base.size, 2);
}

TEST(Instruction, decodeInstructions_whenInsnIsMove16_returnsTwoSixteenBitRegisters)
{
    auto insns = decode({0x0003, 0x0123, 0x4567});

    const auto *move = only<MoveInstruction>(insns);
    ASSERT_NE(move, nullptr);
    EXPECT_EQ(move->dest, 0x0123);
    EXPECT_EQ(move->src, 0x4567);
    EXPECT_EQ(move->base.size, 3);
}

TEST(Instruction, decodeInstructions_whenMoveIsWide_returnsPairWidth)
{
    for (auto units :
         {std::vector<uint16_t>{0x2104}, std::vector<uint16_t>{0x0a05, 0x1234},
          std::vector<uint16_t>{0x0006, 0x0123, 0x4567}, std::vector<uint16_t>{0x050b}}) {
        auto insns = decode_instructions(units);

        const auto *move = only<MoveInstruction>(insns);
        ASSERT_NE(move, nullptr);
        EXPECT_EQ(move->width, OperandWidth::Pair) << opcode_name(move->base.opcode);
    }
}

TEST(Instruction, decodeInstructions_whenMoveIsAnObjectMove_returnsSingleWidth)
{
    for (auto units :
         {std::vector<uint16_t>{0x2107}, std::vector<uint16_t>{0x0a08, 0x1234},
          std::vector<uint16_t>{0x0009, 0x0123, 0x4567}, std::vector<uint16_t>{0x050c}}) {
        auto insns = decode_instructions(units);

        const auto *move = only<MoveInstruction>(insns);
        ASSERT_NE(move, nullptr);
        EXPECT_EQ(move->width, OperandWidth::Single) << opcode_name(move->base.opcode);
    }
}

TEST(Instruction, decodeInstructions_whenInsnIsMoveResult_returnsSourceZero)
{
    auto insns = decode({0x050a});

    const auto *move = only<MoveInstruction>(insns);
    ASSERT_NE(move, nullptr);
    EXPECT_EQ(move->dest, 5);
    EXPECT_EQ(move->src, 0);
    EXPECT_EQ(move->width, OperandWidth::Single);
}

TEST(Instruction, decodeInstructions_whenInsnIsMoveException_returnsAMoveWithSourceZero)
{
    auto insns = decode({0x020d});

    const auto *move = only<MoveInstruction>(insns);
    ASSERT_NE(move, nullptr);
    EXPECT_EQ(move->dest, 2);
    EXPECT_EQ(move->src, 0);
}

TEST(Instruction, decodeInstructions_whenInsnIsReturnVoid_returnsNoRegister)
{
    auto insns = decode({0x000e});

    const auto *ret = only<ReturnInstruction>(insns);
    ASSERT_NE(ret, nullptr);
    EXPECT_FALSE(ret->reg.has_value());
}

TEST(Instruction, decodeInstructions_whenInsnIsReturn_returnsItsRegister)
{
    auto insns = decode({0x030f});

    const auto *ret = only<ReturnInstruction>(insns);
    ASSERT_NE(ret, nullptr);
    EXPECT_EQ(ret->reg, 3);
    EXPECT_EQ(ret->width, OperandWidth::Single);
}

TEST(Instruction, decodeInstructions_whenInsnIsReturnWide_returnsPairWidth)
{
    auto insns = decode({0x0310});

    const auto *ret = only<ReturnInstruction>(insns);
    ASSERT_NE(ret, nullptr);
    EXPECT_EQ(ret->reg, 3);
    EXPECT_EQ(ret->width, OperandWidth::Pair);
}

TEST(Instruction, decodeInstructions_whenInsnIsReturnObject_returnsSingleWidth)
{
    auto insns = decode({0x0311});

    const auto *ret = only<ReturnInstruction>(insns);
    ASSERT_NE(ret, nullptr);
    EXPECT_EQ(ret->reg, 3);
    EXPECT_EQ(ret->width, OperandWidth::Single);
}

TEST(Instruction, decodeInstructions_whenConst4LiteralIsPositive_returnsIt)
{
    auto insns = decode({0x7012});

    const auto *constant = only<ConstInstruction>(insns);
    ASSERT_NE(constant, nullptr);
    EXPECT_EQ(constant->dest, 0);
    EXPECT_EQ(constant->value, 7);
    EXPECT_EQ(constant->width, OperandWidth::Single);
}

TEST(Instruction, decodeInstructions_whenConst4LiteralIsNegative_signExtendsIt)
{
    auto insns = decode({0xf312});

    const auto *constant = only<ConstInstruction>(insns);
    ASSERT_NE(constant, nullptr);
    EXPECT_EQ(constant->dest, 3);
    EXPECT_EQ(constant->value, -1);
}

TEST(Instruction, decodeInstructions_whenInsnIsConst16_signExtendsTheLiteral)
{
    auto insns = decode({0x0113, 0xfffe});

    const auto *constant = only<ConstInstruction>(insns);
    ASSERT_NE(constant, nullptr);
    EXPECT_EQ(constant->dest, 1);
    EXPECT_EQ(constant->value, -2);
    EXPECT_EQ(constant->width, OperandWidth::Single);
}

TEST(Instruction, decodeInstructions_whenInsnIsConst_joinsTheTwoUnitsLowFirst)
{
    auto insns = decode({0x0214, 0x5678, 0x1234});

    const auto *constant = only<ConstInstruction>(insns);
    ASSERT_NE(constant, nullptr);
    EXPECT_EQ(constant->dest, 2);
    EXPECT_EQ(constant->value, 0x12345678);
    EXPECT_EQ(constant->width, OperandWidth::Single);
}

TEST(Instruction, decodeInstructions_whenConstIsNegative_signExtendsItTo64Bits)
{
    auto insns = decode({0x0214, 0xffff, 0xffff});

    const auto *constant = only<ConstInstruction>(insns);
    ASSERT_NE(constant, nullptr);
    EXPECT_EQ(constant->value, -1);
}

TEST(Instruction, decodeInstructions_whenInsnIsConstHigh16_shiftsTheLiteralSixteenBits)
{
    auto insns = decode({0x0215, 0x7fc0});

    const auto *constant = only<ConstInstruction>(insns);
    ASSERT_NE(constant, nullptr);
    EXPECT_EQ(constant->value, 0x7fc00000);
    EXPECT_EQ(constant->width, OperandWidth::Single);
}

TEST(Instruction, decodeInstructions_whenConstHigh16HasTheTopBitSet_returnsANegativeValue)
{
    auto insns = decode({0x0215, 0x8000});

    const auto *constant = only<ConstInstruction>(insns);
    ASSERT_NE(constant, nullptr);
    EXPECT_EQ(constant->value, std::numeric_limits<int32_t>::min());
}

TEST(Instruction, decodeInstructions_whenInsnIsConstWide16_signExtendsTheLiteral)
{
    auto insns = decode({0x0216, 0xffff});

    const auto *constant = only<ConstInstruction>(insns);
    ASSERT_NE(constant, nullptr);
    EXPECT_EQ(constant->value, -1);
    EXPECT_EQ(constant->width, OperandWidth::Pair);
}

TEST(Instruction, decodeInstructions_whenInsnIsConstWide32_signExtendsTheLiteral)
{
    auto insns = decode({0x0217, 0x0000, 0x8000});

    const auto *constant = only<ConstInstruction>(insns);
    ASSERT_NE(constant, nullptr);
    EXPECT_EQ(constant->value, std::numeric_limits<int32_t>::min());
    EXPECT_EQ(constant->width, OperandWidth::Pair);
}

// The units are the ones dexdump shows for "const-wide v2, #double 3.14159" in shapes.dex.
TEST(Instruction, decodeInstructions_whenInsnIsConstWide_joinsFourUnitsLowFirst)
{
    auto insns = decode({0x0218, 0x2d18, 0x5444, 0x21fb, 0x4009});

    const auto *constant = only<ConstInstruction>(insns);
    ASSERT_NE(constant, nullptr);
    EXPECT_EQ(constant->dest, 2);
    EXPECT_EQ(constant->value, 0x400921fb54442d18);
    EXPECT_EQ(constant->width, OperandWidth::Pair);
    EXPECT_EQ(constant->base.size, 5);
}

TEST(Instruction, decodeInstructions_whenInsnIsConstWideHigh16_shiftsTheLiteralFortyEightBits)
{
    auto insns = decode({0x0219, 0x4000});

    const auto *constant = only<ConstInstruction>(insns);
    ASSERT_NE(constant, nullptr);
    EXPECT_EQ(constant->value, 0x4000000000000000);
    EXPECT_EQ(constant->width, OperandWidth::Pair);
}

TEST(Instruction, decodeInstructions_whenConstWideHigh16HasTheTopBitSet_returnsTheLowestValue)
{
    auto insns = decode({0x0219, 0x8000});

    const auto *constant = only<ConstInstruction>(insns);
    ASSERT_NE(constant, nullptr);
    EXPECT_EQ(constant->value, std::numeric_limits<int64_t>::min());
}

TEST(Instruction, decodeInstructions_whenInsnIsConstString_returnsASixteenBitStringIndex)
{
    auto insns = decode({0x031a, 0xfffe});

    const auto *load = only<ConstStringInstruction>(insns);
    ASSERT_NE(load, nullptr);
    EXPECT_EQ(load->dest, 3);
    EXPECT_EQ(load->string_index, 0xfffeu);
    EXPECT_EQ(load->base.size, 2);
}

TEST(Instruction, decodeInstructions_whenInsnIsConstStringJumbo_returnsA32BitStringIndex)
{
    auto insns = decode({0x011b, 0x5678, 0x0001});

    const auto *load = only<ConstStringInstruction>(insns);
    ASSERT_NE(load, nullptr);
    EXPECT_EQ(load->dest, 1);
    EXPECT_EQ(load->string_index, 0x00015678u);
    EXPECT_EQ(load->base.size, 3);
}

TEST(Instruction, decodeInstructions_whenInsnIsConstClass_returnsItsTypeIndex)
{
    auto insns = decode({0x021c, 0x0007});

    const auto *load = only<ConstClassInstruction>(insns);
    ASSERT_NE(load, nullptr);
    EXPECT_EQ(load->dest, 2);
    EXPECT_EQ(load->type_index, 7u);
}

TEST(Instruction, decodeInstructions_whenInsnIsConstMethodHandle_returnsItsIndex)
{
    auto insns = decode({0x01fe, 0x0004});

    const auto *load = only<ConstHandleInstruction>(insns);
    ASSERT_NE(load, nullptr);
    EXPECT_EQ(load->base.opcode, 0xfe);
    EXPECT_EQ(load->dest, 1);
    EXPECT_EQ(load->index, 4u);
}

TEST(Instruction, decodeInstructions_whenInsnIsConstMethodType_returnsItsProtoIndex)
{
    auto insns = decode({0x01ff, 0x0005});

    const auto *load = only<ConstHandleInstruction>(insns);
    ASSERT_NE(load, nullptr);
    EXPECT_EQ(load->base.opcode, 0xff);
    EXPECT_EQ(load->dest, 1);
    EXPECT_EQ(load->index, 5u);
}

TEST(Instruction, decodeInstructions_whenInsnIsMonitorEnter_returnsAnEnter)
{
    auto insns = decode({0x031d});

    const auto *monitor = only<MonitorInstruction>(insns);
    ASSERT_NE(monitor, nullptr);
    EXPECT_EQ(monitor->reg, 3);
    EXPECT_TRUE(monitor->is_enter);
}

TEST(Instruction, decodeInstructions_whenInsnIsMonitorExit_returnsAnExit)
{
    auto insns = decode({0x031e});

    const auto *monitor = only<MonitorInstruction>(insns);
    ASSERT_NE(monitor, nullptr);
    EXPECT_EQ(monitor->reg, 3);
    EXPECT_FALSE(monitor->is_enter);
}

TEST(Instruction, decodeInstructions_whenInsnIsCheckCast_returnsOneRegisterAndNoSource)
{
    auto insns = decode({0x031f, 0x0007});

    const auto *type = only<TypeInstruction>(insns);
    ASSERT_NE(type, nullptr);
    EXPECT_EQ(type->dest, 3);
    EXPECT_EQ(type->type_index, 7u);
    EXPECT_FALSE(type->src.has_value());
}

TEST(Instruction, decodeInstructions_whenInsnIsInstanceOf_returnsResultAndObjectRegisters)
{
    auto insns = decode({0x2120, 0x0005});

    const auto *type = only<TypeInstruction>(insns);
    ASSERT_NE(type, nullptr);
    EXPECT_EQ(type->dest, 1);
    EXPECT_EQ(type->src, 2);
    EXPECT_EQ(type->type_index, 5u);
}

TEST(Instruction, decodeInstructions_whenInsnIsNewInstance_returnsOneRegisterAndNoSource)
{
    auto insns = decode({0x0322, 0x0009});

    const auto *type = only<TypeInstruction>(insns);
    ASSERT_NE(type, nullptr);
    EXPECT_EQ(type->dest, 3);
    EXPECT_EQ(type->type_index, 9u);
    EXPECT_FALSE(type->src.has_value());
}

TEST(Instruction, decodeInstructions_whenInsnIsNewArray_returnsResultAndSizeRegisters)
{
    auto insns = decode({0x2123, 0x0004});

    const auto *type = only<TypeInstruction>(insns);
    ASSERT_NE(type, nullptr);
    EXPECT_EQ(type->dest, 1);
    EXPECT_EQ(type->src, 2);
    EXPECT_EQ(type->type_index, 4u);
}

TEST(Instruction, decodeInstructions_whenInsnIsArrayLength_returnsAUnaryOp)
{
    auto insns = decode({0x2121});

    const auto *length = only<UnaryOpInstruction>(insns);
    ASSERT_NE(length, nullptr);
    EXPECT_EQ(length->dest, 1);
    EXPECT_EQ(length->src, 2);
    EXPECT_EQ(length->dest_width, OperandWidth::Single);
    EXPECT_EQ(length->src_width, OperandWidth::Single);
}

TEST(Instruction, decodeInstructions_whenInsnIsFilledNewArray_returnsEveryElementRegister)
{
    auto insns = decode({0x3024, 0x0005, 0x0321});

    const auto *array = only<FilledNewArrayInstruction>(insns);
    ASSERT_NE(array, nullptr);
    EXPECT_EQ(array->type_index, 5u);
    EXPECT_EQ(array->arg_regs, (std::vector<uint16_t>{1, 2, 3}));
    EXPECT_EQ(array->base.size, 3);
}

TEST(Instruction, decodeInstructions_whenFilledNewArrayHasFiveElements_takesTheFifthFromUnitZero)
{
    auto insns = decode({0x5924, 0x0005, 0x4321});

    const auto *array = only<FilledNewArrayInstruction>(insns);
    ASSERT_NE(array, nullptr);
    EXPECT_EQ(array->arg_regs, (std::vector<uint16_t>{1, 2, 3, 4, 9}));
}

TEST(Instruction, decodeInstructions_whenInsnIsFilledNewArrayRange_returnsTheWholeRegisterRange)
{
    auto insns = decode({0x0425, 0x0009, 0x0004});

    const auto *array = only<FilledNewArrayInstruction>(insns);
    ASSERT_NE(array, nullptr);
    EXPECT_EQ(array->type_index, 9u);
    EXPECT_EQ(array->arg_regs, (std::vector<uint16_t>{4, 5, 6, 7}));
}

TEST(Instruction, decodeInstructions_whenInsnIsFillArrayData_returnsItsRegisterAndPayloadOffset)
{
    auto insns = decode({0x0126, 0x0010, 0x0000});

    const auto *fill = only<FillArrayInstruction>(insns);
    ASSERT_NE(fill, nullptr);
    EXPECT_EQ(fill->reg, 1);
    EXPECT_EQ(fill->payload_offset, 16);
    EXPECT_EQ(fill->base.size, 3);
}

TEST(Instruction, decodeInstructions_whenFillArrayDataPayloadIsBehind_returnsANegativeOffset)
{
    auto insns = decode({0x0126, 0xfff8, 0xffff});

    const auto *fill = only<FillArrayInstruction>(insns);
    ASSERT_NE(fill, nullptr);
    EXPECT_EQ(fill->payload_offset, -8);
}

TEST(Instruction, decodeInstructions_whenInsnIsThrow_returnsItsRegister)
{
    auto insns = decode({0x0227});

    const auto *thrown = only<ThrowInstruction>(insns);
    ASSERT_NE(thrown, nullptr);
    EXPECT_EQ(thrown->reg, 2);
}

// The unit is the one dexdump shows for "goto 0014 // -000b" in fibonacci.dex.
TEST(Instruction, decodeInstructions_whenInsnIsGoto_signExtendsTheEightBitOffset)
{
    auto insns = decode({0xf528});

    const auto *jump = only<GotoInstruction>(insns);
    ASSERT_NE(jump, nullptr);
    EXPECT_EQ(jump->branch_offset, -11);
    EXPECT_EQ(jump->base.size, 1);
}

TEST(Instruction, decodeInstructions_whenInsnIsGoto16_signExtendsTheSixteenBitOffset)
{
    auto insns = decode({0x0029, 0xfff0});

    const auto *jump = only<GotoInstruction>(insns);
    ASSERT_NE(jump, nullptr);
    EXPECT_EQ(jump->branch_offset, -16);
    EXPECT_EQ(jump->base.size, 2);
}

TEST(Instruction, decodeInstructions_whenInsnIsGoto32_joinsTheTwoUnitsLowFirst)
{
    auto insns = decode({0x002a, 0x0000, 0xffff});

    const auto *jump = only<GotoInstruction>(insns);
    ASSERT_NE(jump, nullptr);
    EXPECT_EQ(jump->branch_offset, -65536);
    EXPECT_EQ(jump->base.size, 3);
}

TEST(Instruction, decodeInstructions_whenInsnIsPackedSwitch_returnsItsRegisterAndPayloadOffset)
{
    auto insns = decode({0x042b, 0x0010, 0x0000});

    const auto *sw = only<SwitchInstruction>(insns);
    ASSERT_NE(sw, nullptr);
    EXPECT_TRUE(sw->is_packed);
    EXPECT_EQ(sw->reg, 4);
    EXPECT_EQ(sw->payload_offset, 16);
    EXPECT_EQ(sw->base.size, 3);
}

TEST(Instruction, decodeInstructions_whenInsnIsSparseSwitch_returnsItsRegisterAndPayloadOffset)
{
    auto insns = decode({0x042c, 0x0010, 0x0000});

    const auto *sw = only<SwitchInstruction>(insns);
    ASSERT_NE(sw, nullptr);
    EXPECT_FALSE(sw->is_packed);
    EXPECT_EQ(sw->reg, 4);
    EXPECT_EQ(sw->payload_offset, 16);
}

TEST(Instruction, decodeInstructions_whenPackedSwitchHasAPayload_returnsConsecutiveKeys)
{
    auto insns = decode({0x002b, 0x0005, 0x0000, 0x000e, 0x000e, 0x0100, 0x0003, 0x000a, 0x0000,
                         0x0014, 0x0000, 0x001e, 0x0000, 0x0028, 0x0000});

    ASSERT_FALSE(insns.empty());
    const auto *sw = std::get_if<SwitchInstruction>(&insns[0]);
    ASSERT_NE(sw, nullptr);
    ASSERT_EQ(sw->cases.size(), 3u);
    EXPECT_EQ(sw->cases[0].key, 10);
    EXPECT_EQ(sw->cases[0].target, 20);
    EXPECT_EQ(sw->cases[1].key, 11);
    EXPECT_EQ(sw->cases[1].target, 30);
    EXPECT_EQ(sw->cases[2].key, 12);
    EXPECT_EQ(sw->cases[2].target, 40);
}

TEST(Instruction, decodeInstructions_whenPackedSwitchKeysPassTheLargestInt_returnsNoCases)
{
    auto insns = decode(
        {0x002b, 0x0003, 0x0000, 0x0100, 0x0002, 0xffff, 0x7fff, 0x0007, 0x0000, 0x0009, 0x0000});

    ASSERT_FALSE(insns.empty());
    const auto *sw = std::get_if<SwitchInstruction>(&insns[0]);
    ASSERT_NE(sw, nullptr);
    EXPECT_TRUE(sw->cases.empty());
}

TEST(Instruction, decodeInstructions_whenPackedSwitchLastKeyIsTheLargestInt_returnsIt)
{
    auto insns = decode({0x002b, 0x0003, 0x0000, 0x0100, 0x0001, 0xffff, 0x7fff, 0x0007, 0x0000});

    ASSERT_FALSE(insns.empty());
    const auto *sw = std::get_if<SwitchInstruction>(&insns[0]);
    ASSERT_NE(sw, nullptr);
    ASSERT_EQ(sw->cases.size(), 1u);
    EXPECT_EQ(sw->cases[0].key, std::numeric_limits<int32_t>::max());
}

TEST(Instruction, decodeInstructions_whenPackedSwitchFirstKeyIsNegative_countsUpFromIt)
{
    auto insns = decode(
        {0x002b, 0x0003, 0x0000, 0x0100, 0x0002, 0xffff, 0xffff, 0x0007, 0x0000, 0x0009, 0x0000});

    ASSERT_FALSE(insns.empty());
    const auto *sw = std::get_if<SwitchInstruction>(&insns[0]);
    ASSERT_NE(sw, nullptr);
    ASSERT_EQ(sw->cases.size(), 2u);
    EXPECT_EQ(sw->cases[0].key, -1);
    EXPECT_EQ(sw->cases[0].target, 7);
    EXPECT_EQ(sw->cases[1].key, 0);
    EXPECT_EQ(sw->cases[1].target, 9);
}

TEST(Instruction, decodeInstructions_whenSparseSwitchHasAPayload_returnsEachKeyWithItsTarget)
{
    auto insns =
        decode({0x012c, 0x0005, 0x0000, 0x000e, 0x000e, 0x0200, 0x0003, 0xfffe, 0xffff, 0x0000,
                0x0000, 0x0005, 0x0000, 0x0064, 0x0000, 0x00c8, 0x0000, 0x012c, 0x0000});

    ASSERT_FALSE(insns.empty());
    const auto *sw = std::get_if<SwitchInstruction>(&insns[0]);
    ASSERT_NE(sw, nullptr);
    ASSERT_EQ(sw->cases.size(), 3u);
    EXPECT_EQ(sw->cases[0].key, -2);
    EXPECT_EQ(sw->cases[0].target, 100);
    EXPECT_EQ(sw->cases[1].key, 0);
    EXPECT_EQ(sw->cases[1].target, 200);
    EXPECT_EQ(sw->cases[2].key, 5);
    EXPECT_EQ(sw->cases[2].target, 300);
}

TEST(Instruction, decodeInstructions_whenSwitchTargetIsBackward_returnsANegativeTarget)
{
    auto insns = decode({0x002c, 0x0003, 0x0000, 0x0200, 0x0001, 0x0007, 0x0000, 0xfff4, 0xffff});

    ASSERT_FALSE(insns.empty());
    const auto *sw = std::get_if<SwitchInstruction>(&insns[0]);
    ASSERT_NE(sw, nullptr);
    ASSERT_EQ(sw->cases.size(), 1u);
    EXPECT_EQ(sw->cases[0].key, 7);
    EXPECT_EQ(sw->cases[0].target, -12);
}

TEST(Instruction, decodeInstructions_whenSwitchPayloadIsBehindTheSwitch_readsItsCases)
{
    auto insns = decode({0x0100, 0x0001, 0x0005, 0x0000, 0x0009, 0x0000, 0x002b, 0xfffa, 0xffff});

    const auto *sw = only<SwitchInstruction>(insns);
    ASSERT_NE(sw, nullptr);
    EXPECT_EQ(sw->base.offset, 6u);
    ASSERT_EQ(sw->cases.size(), 1u);
    EXPECT_EQ(sw->cases[0].key, 5);
    EXPECT_EQ(sw->cases[0].target, 9);
}

TEST(Instruction, decodeInstructions_whenPackedSwitchPointsAtASparsePayload_returnsNoCases)
{
    auto insns = decode({0x002b, 0x0003, 0x0000, 0x0200, 0x0002, 0x0000, 0x0000, 0x0001, 0x0000,
                         0x0002, 0x0000, 0x0003, 0x0000});

    ASSERT_FALSE(insns.empty());
    const auto *sw = std::get_if<SwitchInstruction>(&insns[0]);
    ASSERT_NE(sw, nullptr);
    EXPECT_TRUE(sw->is_packed);
    EXPECT_TRUE(sw->cases.empty());
}

TEST(Instruction, decodeInstructions_whenSparseSwitchPointsAtAPackedPayload_returnsNoCases)
{
    auto insns = decode({0x002c, 0x0003, 0x0000, 0x0100, 0x0001, 0x0000, 0x0000, 0x0001, 0x0000});

    ASSERT_FALSE(insns.empty());
    const auto *sw = std::get_if<SwitchInstruction>(&insns[0]);
    ASSERT_NE(sw, nullptr);
    EXPECT_FALSE(sw->is_packed);
    EXPECT_TRUE(sw->cases.empty());
}

TEST(Instruction, decodeInstructions_whenSwitchPayloadOffsetIsPastTheEnd_returnsNoCases)
{
    auto insns = decode({0x002b, 0x0040, 0x0000, 0x000e});

    ASSERT_FALSE(insns.empty());
    const auto *sw = std::get_if<SwitchInstruction>(&insns[0]);
    ASSERT_NE(sw, nullptr);
    EXPECT_TRUE(sw->cases.empty());
}

TEST(Instruction, decodeInstructions_whenSwitchPayloadOffsetIsBeforeTheStart_returnsNoCases)
{
    auto insns = decode({0x0100, 0x0001, 0x0005, 0x0000, 0x0009, 0x0000, 0x002b, 0xfff9, 0xffff});

    const auto *sw = only<SwitchInstruction>(insns);
    ASSERT_NE(sw, nullptr);
    EXPECT_EQ(sw->base.offset, 6u);
    EXPECT_EQ(sw->payload_offset, -7);
    EXPECT_TRUE(sw->cases.empty());
}

TEST(Instruction, decodeInstructions_whenPackedSwitchPayloadIsCutOff_returnsNoCases)
{
    auto insns = decode({0x002b, 0x0003, 0x0000, 0x0100, 0x0003, 0x0000, 0x0000, 0x0014, 0x0000});

    ASSERT_FALSE(insns.empty());
    const auto *sw = std::get_if<SwitchInstruction>(&insns[0]);
    ASSERT_NE(sw, nullptr);
    EXPECT_TRUE(sw->cases.empty());
}

TEST(Instruction, decodeInstructions_whenSparseSwitchPayloadIsCutOff_returnsNoCases)
{
    auto insns = decode(
        {0x002c, 0x0003, 0x0000, 0x0200, 0x0002, 0x0001, 0x0000, 0x0002, 0x0000, 0x0014, 0x0000});

    ASSERT_FALSE(insns.empty());
    const auto *sw = std::get_if<SwitchInstruction>(&insns[0]);
    ASSERT_NE(sw, nullptr);
    EXPECT_TRUE(sw->cases.empty());
}

TEST(Instruction, decodeInstructions_whenCodeHasAPackedSwitchPayload_skipsItAndDecodesWhatFollows)
{
    auto insns = decode({0x002b, 0x0004, 0x0000, 0x000e, 0x0100, 0x0002, 0x0000, 0x0000, 0x0003,
                         0x0000, 0x0003, 0x0000, 0x000e});

    ASSERT_EQ(insns.size(), 3u);
    EXPECT_TRUE(std::holds_alternative<SwitchInstruction>(insns[0]));
    EXPECT_TRUE(std::holds_alternative<ReturnInstruction>(insns[1]));
    EXPECT_TRUE(std::holds_alternative<ReturnInstruction>(insns[2]));
    EXPECT_EQ(offsets_of(insns), (std::vector<uint32_t>{0, 3, 12}));
}

TEST(Instruction, decodeInstructions_whenCodeHasASparseSwitchPayload_skipsItAndDecodesWhatFollows)
{
    auto insns = decode({0x002c, 0x0004, 0x0000, 0x000e, 0x0200, 0x0002, 0x0001, 0x0000, 0x0002,
                         0x0000, 0x0003, 0x0000, 0x0003, 0x0000, 0x000e});

    ASSERT_EQ(insns.size(), 3u);
    EXPECT_TRUE(std::holds_alternative<SwitchInstruction>(insns[0]));
    EXPECT_TRUE(std::holds_alternative<ReturnInstruction>(insns[1]));
    EXPECT_TRUE(std::holds_alternative<ReturnInstruction>(insns[2]));
    EXPECT_EQ(offsets_of(insns), (std::vector<uint32_t>{0, 3, 14}));
}

TEST(Instruction, decodeInstructions_whenCodeHasAFillArrayDataPayload_skipsItAndDecodesWhatFollows)
{
    auto insns = decode({0x0126, 0x0004, 0x0000, 0x000e, 0x0300, 0x0004, 0x0002, 0x0000, 0x6e6e,
                         0x6e6e, 0x7171, 0x7171, 0x000e});

    ASSERT_EQ(insns.size(), 3u);
    EXPECT_TRUE(std::holds_alternative<FillArrayInstruction>(insns[0]));
    EXPECT_TRUE(std::holds_alternative<ReturnInstruction>(insns[1]));
    EXPECT_TRUE(std::holds_alternative<ReturnInstruction>(insns[2]));
    EXPECT_EQ(offsets_of(insns), (std::vector<uint32_t>{0, 3, 12}));
}

TEST(Instruction, decodeInstructions_whenFillArrayDataHasAnOddByteCount_skipsThePaddingByteToo)
{
    auto insns = decode(
        {0x0126, 0x0004, 0x0000, 0x000e, 0x0300, 0x0001, 0x0003, 0x0000, 0x6e6e, 0x006e, 0x000e});

    ASSERT_EQ(insns.size(), 3u);
    EXPECT_EQ(offsets_of(insns), (std::vector<uint32_t>{0, 3, 10}));
}

TEST(Instruction, decodeInstructions_whenPayloadHoldsInvokeOpcodes_returnsNoInvokeFromIt)
{
    auto insns = decode({0x000e, 0x0000, 0x0300, 0x0002, 0x0003, 0x0000, 0x206e, 0x0003, 0x0001});

    ASSERT_EQ(insns.size(), 2u);
    EXPECT_TRUE(std::holds_alternative<ReturnInstruction>(insns[0]));
    EXPECT_TRUE(std::holds_alternative<NopInstruction>(insns[1]));
}

TEST(Instruction, decodeInstructions_whenPayloadDeclaresMoreUnitsThanRemain_stopsAtTheEnd)
{
    auto insns = decode({0x000e, 0x0100, 0x00ff, 0x0000, 0x0000, 0x000e});

    const auto *ret = only<ReturnInstruction>(insns);
    ASSERT_NE(ret, nullptr);
    EXPECT_EQ(ret->base.offset, 0u);
}

TEST(Instruction, decodeInstructions_whenPayloadHeaderIsCutOff_skipsOneUnit)
{
    auto insns = decode({0x0300, 0x000e});

    const auto *ret = only<ReturnInstruction>(insns);
    ASSERT_NE(ret, nullptr);
    EXPECT_EQ(ret->base.offset, 1u);
}

TEST(Instruction, decodeInstructions_whenNopHasAnUnknownPayloadIdent_skipsOneUnit)
{
    auto insns = decode({0x0400, 0x000e});

    const auto *ret = only<ReturnInstruction>(insns);
    ASSERT_NE(ret, nullptr);
    EXPECT_EQ(ret->base.offset, 1u);
}

TEST(Instruction, decodeInstructions_whenInsnIsACompare_returnsDestinationAndBothSources)
{
    auto insns = decode({0x012d, 0x0302});

    const auto *compare = only<CompareInstruction>(insns);
    ASSERT_NE(compare, nullptr);
    EXPECT_EQ(compare->dest, 1);
    EXPECT_EQ(compare->src_a, 2);
    EXPECT_EQ(compare->src_b, 3);
    EXPECT_EQ(compare->base.size, 2);
}

TEST(Instruction, decodeInstructions_whenCompareIsOnFloats_returnsSingleSourceWidth)
{
    for (uint8_t opcode : {0x2d, 0x2e}) {
        auto insns = decode({unit(opcode, 1), 0x0302});

        const auto *compare = only<CompareInstruction>(insns);
        ASSERT_NE(compare, nullptr);
        EXPECT_EQ(compare->src_width, OperandWidth::Single) << opcode_name(opcode);
    }
}

TEST(Instruction, decodeInstructions_whenCompareIsOnDoublesOrLongs_returnsPairSourceWidth)
{
    for (uint8_t opcode : {0x2f, 0x30, 0x31}) {
        auto insns = decode({unit(opcode, 1), 0x0302});

        const auto *compare = only<CompareInstruction>(insns);
        ASSERT_NE(compare, nullptr);
        EXPECT_EQ(compare->src_width, OperandWidth::Pair) << opcode_name(opcode);
    }
}

TEST(Instruction, decodeInstructions_whenInsnIsIf_returnsBothRegistersAndTheSignedOffset)
{
    auto insns = decode({0x2132, 0xfffd});

    const auto *branch = only<IfInstruction>(insns);
    ASSERT_NE(branch, nullptr);
    EXPECT_EQ(branch->reg_a, 1);
    EXPECT_EQ(branch->reg_b, 2);
    EXPECT_EQ(branch->branch_offset, -3);
    EXPECT_EQ(branch->base.size, 2);
}

TEST(Instruction, decodeInstructions_whenOpcodeIsAnyTwoRegisterIf_returnsAnIf)
{
    for (int opcode = 0x32; opcode <= 0x37; ++opcode) {
        auto insns = decode({unit(static_cast<uint8_t>(opcode), 0x21), 0x0004});

        const auto *branch = only<IfInstruction>(insns);
        ASSERT_NE(branch, nullptr) << opcode;
        EXPECT_EQ(branch->base.opcode, opcode);
        EXPECT_EQ(branch->branch_offset, 4);
    }
}

// The units are the ones dexdump shows for "if-gez v10, 0005 // +0005" in fibonacci.dex.
TEST(Instruction, decodeInstructions_whenInsnIsIfZero_returnsTheRegisterAndTheSignedOffset)
{
    auto insns = decode({0x0a3b, 0x0005});

    const auto *branch = only<IfZeroInstruction>(insns);
    ASSERT_NE(branch, nullptr);
    EXPECT_EQ(branch->reg, 10);
    EXPECT_EQ(branch->branch_offset, 5);
    EXPECT_EQ(branch->base.size, 2);
}

TEST(Instruction, decodeInstructions_whenOpcodeIsAnyZeroTestIf_returnsAnIfZero)
{
    for (int opcode = 0x38; opcode <= 0x3d; ++opcode) {
        auto insns = decode({unit(static_cast<uint8_t>(opcode), 5), 0xfffc});

        const auto *branch = only<IfZeroInstruction>(insns);
        ASSERT_NE(branch, nullptr) << opcode;
        EXPECT_EQ(branch->base.opcode, opcode);
        EXPECT_EQ(branch->branch_offset, -4);
    }
}

// The units are the ones dexdump shows for "aput-object v2, v0, v1" in casts.dex.
TEST(Instruction, decodeInstructions_whenInsnIsAnArrayOp_returnsValueArrayAndIndexRegisters)
{
    auto insns = decode({0x024d, 0x0100});

    const auto *array = only<ArrayOpInstruction>(insns);
    ASSERT_NE(array, nullptr);
    EXPECT_EQ(array->value_reg, 2);
    EXPECT_EQ(array->array_reg, 0);
    EXPECT_EQ(array->index_reg, 1);
    EXPECT_EQ(array->base.size, 2);
}

TEST(Instruction, decodeInstructions_whenOpcodeIsAnAget_returnsARead)
{
    for (int opcode = 0x44; opcode <= 0x4a; ++opcode) {
        auto insns = decode({unit(static_cast<uint8_t>(opcode), 1), 0x0302});

        const auto *array = only<ArrayOpInstruction>(insns);
        ASSERT_NE(array, nullptr) << opcode;
        EXPECT_FALSE(array->is_write) << opcode_name(array->base.opcode);
    }
}

TEST(Instruction, decodeInstructions_whenOpcodeIsAnAput_returnsAWrite)
{
    for (int opcode = 0x4b; opcode <= 0x51; ++opcode) {
        auto insns = decode({unit(static_cast<uint8_t>(opcode), 1), 0x0302});

        const auto *array = only<ArrayOpInstruction>(insns);
        ASSERT_NE(array, nullptr) << opcode;
        EXPECT_TRUE(array->is_write) << opcode_name(array->base.opcode);
    }
}

TEST(Instruction, decodeInstructions_whenArrayOpIsWide_returnsPairWidthAndSingleOtherwise)
{
    for (int opcode = 0x44; opcode <= 0x51; ++opcode) {
        auto insns = decode({unit(static_cast<uint8_t>(opcode), 1), 0x0302});

        const auto *array = only<ArrayOpInstruction>(insns);
        ASSERT_NE(array, nullptr) << opcode;
        bool wide = opcode == 0x45 || opcode == 0x4c;
        EXPECT_EQ(array->width, wide ? OperandWidth::Pair : OperandWidth::Single)
            << opcode_name(array->base.opcode);
    }
}

// The units are the ones dexdump shows for "iget-object v0, v1, field@0000" in shapes.dex.
TEST(Instruction, decodeInstructions_whenInsnIsAnInstanceFieldOp_returnsValueAndObjectRegisters)
{
    auto insns = decode({0x1054, 0x0000});

    const auto *field = only<FieldInstruction>(insns);
    ASSERT_NE(field, nullptr);
    EXPECT_EQ(field->value_reg, 0);
    EXPECT_EQ(field->object_reg, 1);
    EXPECT_EQ(field->field_index, 0u);
    EXPECT_FALSE(field->is_static);
    EXPECT_EQ(field->base.size, 2);
}

TEST(Instruction, decodeInstructions_whenInsnIsAFieldOp_returnsTheSixteenBitFieldIndex)
{
    auto insns = decode({0x2152, 0xfffe});

    const auto *field = only<FieldInstruction>(insns);
    ASSERT_NE(field, nullptr);
    EXPECT_EQ(field->field_index, 0xfffeu);
}

TEST(Instruction, decodeInstructions_whenOpcodeIsAnIget_returnsAnInstanceRead)
{
    for (int opcode = 0x52; opcode <= 0x58; ++opcode) {
        auto insns = decode({unit(static_cast<uint8_t>(opcode), 0x21), 0x0007});

        const auto *field = only<FieldInstruction>(insns);
        ASSERT_NE(field, nullptr) << opcode;
        EXPECT_FALSE(field->is_write) << opcode_name(field->base.opcode);
        EXPECT_FALSE(field->is_static) << opcode_name(field->base.opcode);
    }
}

TEST(Instruction, decodeInstructions_whenOpcodeIsAnIput_returnsAnInstanceWrite)
{
    for (int opcode = 0x59; opcode <= 0x5f; ++opcode) {
        auto insns = decode({unit(static_cast<uint8_t>(opcode), 0x21), 0x0007});

        const auto *field = only<FieldInstruction>(insns);
        ASSERT_NE(field, nullptr) << opcode;
        EXPECT_TRUE(field->is_write) << opcode_name(field->base.opcode);
        EXPECT_FALSE(field->is_static) << opcode_name(field->base.opcode);
    }
}

// The units are the ones dexdump shows for "sget-object v1, field@0000" in classes.dex.
TEST(Instruction, decodeInstructions_whenInsnIsAStaticFieldOp_returnsNoObjectRegister)
{
    auto insns = decode({0x0162, 0x0000});

    const auto *field = only<FieldInstruction>(insns);
    ASSERT_NE(field, nullptr);
    EXPECT_EQ(field->value_reg, 1);
    EXPECT_FALSE(field->object_reg.has_value());
    EXPECT_EQ(field->field_index, 0u);
    EXPECT_TRUE(field->is_static);
}

TEST(Instruction, decodeInstructions_whenOpcodeIsAnSget_returnsAStaticRead)
{
    for (int opcode = 0x60; opcode <= 0x66; ++opcode) {
        auto insns = decode({unit(static_cast<uint8_t>(opcode), 3), 0x0009});

        const auto *field = only<FieldInstruction>(insns);
        ASSERT_NE(field, nullptr) << opcode;
        EXPECT_FALSE(field->is_write) << opcode_name(field->base.opcode);
        EXPECT_TRUE(field->is_static) << opcode_name(field->base.opcode);
    }
}

TEST(Instruction, decodeInstructions_whenOpcodeIsAnSput_returnsAStaticWrite)
{
    for (int opcode = 0x67; opcode <= 0x6d; ++opcode) {
        auto insns = decode({unit(static_cast<uint8_t>(opcode), 3), 0x0009});

        const auto *field = only<FieldInstruction>(insns);
        ASSERT_NE(field, nullptr) << opcode;
        EXPECT_TRUE(field->is_write) << opcode_name(field->base.opcode);
        EXPECT_TRUE(field->is_static) << opcode_name(field->base.opcode);
    }
}

TEST(Instruction, decodeInstructions_whenFieldOpIsWide_returnsPairWidthAndSingleOtherwise)
{
    for (int opcode = 0x52; opcode <= 0x6d; ++opcode) {
        auto insns = decode({unit(static_cast<uint8_t>(opcode), 0x21), 0x0007});

        const auto *field = only<FieldInstruction>(insns);
        ASSERT_NE(field, nullptr) << opcode;
        bool wide = opcode == 0x53 || opcode == 0x5a || opcode == 0x61 || opcode == 0x68;
        EXPECT_EQ(field->width, wide ? OperandWidth::Pair : OperandWidth::Single)
            << opcode_name(field->base.opcode);
    }
}

// The units are the ones dexdump shows for "invoke-virtual {v1, v0}, method@0003" in classes.dex.
TEST(Instruction, decodeInstructions_whenInsnIsInvokeVirtual_returnsItsMethodAndRegisters)
{
    auto insns = decode({0x206e, 0x0003, 0x0001});

    const auto *invoke = only<InvokeInstruction>(insns);
    ASSERT_NE(invoke, nullptr);
    EXPECT_EQ(invoke->base.opcode, 0x6e);
    EXPECT_EQ(invoke->base.size, 3);
    EXPECT_EQ(invoke->method_index, 3u);
    EXPECT_EQ(invoke->arg_regs, (std::vector<uint16_t>{1, 0}));
}

TEST(Instruction, decodeInstructions_whenInsnIsInvokeSuper_returnsItsMethodAndRegisters)
{
    auto insns = decode({0x106f, 0x000a, 0x0002});

    const auto *invoke = only<InvokeInstruction>(insns);
    ASSERT_NE(invoke, nullptr);
    EXPECT_EQ(invoke->base.opcode, 0x6f);
    EXPECT_EQ(invoke->method_index, 10u);
    EXPECT_EQ(invoke->arg_regs, (std::vector<uint16_t>{2}));
}

TEST(Instruction, decodeInstructions_whenInsnIsInvokeDirect_returnsItsMethodAndRegisters)
{
    auto insns = decode({0x2070, 0x0000, 0x0010});

    const auto *invoke = only<InvokeInstruction>(insns);
    ASSERT_NE(invoke, nullptr);
    EXPECT_EQ(invoke->base.opcode, 0x70);
    EXPECT_EQ(invoke->method_index, 0u);
    EXPECT_EQ(invoke->arg_regs, (std::vector<uint16_t>{0, 1}));
}

TEST(Instruction, decodeInstructions_whenInsnIsInvokeStatic_returnsItsMethodAndRegisters)
{
    auto insns = decode({0x3071, 0x002b, 0x0645});

    const auto *invoke = only<InvokeInstruction>(insns);
    ASSERT_NE(invoke, nullptr);
    EXPECT_EQ(invoke->base.opcode, 0x71);
    EXPECT_EQ(invoke->method_index, 0x2bu);
    EXPECT_EQ(invoke->arg_regs, (std::vector<uint16_t>{5, 4, 6}));
}

TEST(Instruction, decodeInstructions_whenInsnIsInvokeInterface_returnsItsMethodAndRegisters)
{
    auto insns = decode({0x1072, 0x0000, 0x0000});

    const auto *invoke = only<InvokeInstruction>(insns);
    ASSERT_NE(invoke, nullptr);
    EXPECT_EQ(invoke->base.opcode, 0x72);
    EXPECT_EQ(invoke->method_index, 0u);
    EXPECT_EQ(invoke->arg_regs, (std::vector<uint16_t>{0}));
}

TEST(Instruction, decodeInstructions_whenInvokeHasNoArgument_returnsNoRegister)
{
    auto insns = decode({0x0071, 0x0001, 0x0000});

    const auto *invoke = only<InvokeInstruction>(insns);
    ASSERT_NE(invoke, nullptr);
    EXPECT_TRUE(invoke->arg_regs.empty());
}

TEST(Instruction, decodeInstructions_whenInvokeHasFiveArguments_takesTheFifthFromUnitZero)
{
    auto insns = decode({0x596e, 0x0003, 0x4321});

    const auto *invoke = only<InvokeInstruction>(insns);
    ASSERT_NE(invoke, nullptr);
    EXPECT_EQ(invoke->arg_regs, (std::vector<uint16_t>{1, 2, 3, 4, 9}));
}

TEST(Instruction, decodeInstructions_whenInvokeCountIsBelowFive_ignoresTheUnusedRegisterNibbles)
{
    auto insns = decode({0x296e, 0x0003, 0x4321});

    const auto *invoke = only<InvokeInstruction>(insns);
    ASSERT_NE(invoke, nullptr);
    EXPECT_EQ(invoke->arg_regs, (std::vector<uint16_t>{1, 2}));
}

TEST(Instruction, decodeInstructions_whenInvokeCountIsAboveFive_returnsFiveRegisters)
{
    auto insns = decode({0x796e, 0x0003, 0x4321});

    const auto *invoke = only<InvokeInstruction>(insns);
    ASSERT_NE(invoke, nullptr);
    EXPECT_EQ(invoke->arg_regs, (std::vector<uint16_t>{1, 2, 3, 4, 9}));
}

TEST(Instruction, decodeInstructions_whenInvokeMethodIndexIsLarge_returnsAllSixteenBits)
{
    auto insns = decode({0x0071, 0xfffe, 0x0000});

    const auto *invoke = only<InvokeInstruction>(insns);
    ASSERT_NE(invoke, nullptr);
    EXPECT_EQ(invoke->method_index, 0xfffeu);
}

TEST(Instruction, decodeInstructions_whenInsnIsARangeInvoke_returnsTheWholeRegisterRange)
{
    auto insns = decode({0x0374, 0x0010, 0x0005});

    const auto *invoke = only<InvokeInstruction>(insns);
    ASSERT_NE(invoke, nullptr);
    EXPECT_EQ(invoke->base.opcode, 0x74);
    EXPECT_EQ(invoke->base.size, 3);
    EXPECT_EQ(invoke->method_index, 0x10u);
    EXPECT_EQ(invoke->arg_regs, (std::vector<uint16_t>{5, 6, 7}));
}

TEST(Instruction, decodeInstructions_whenOpcodeIsAnyRangeInvoke_returnsAnInvokeWithThatOpcode)
{
    for (int opcode = 0x74; opcode <= 0x78; ++opcode) {
        auto insns = decode({unit(static_cast<uint8_t>(opcode), 2), 0x0010, 0x0100});

        const auto *invoke = only<InvokeInstruction>(insns);
        ASSERT_NE(invoke, nullptr) << opcode;
        EXPECT_EQ(invoke->base.opcode, opcode);
        EXPECT_EQ(invoke->method_index, 0x10u);
        EXPECT_EQ(invoke->arg_regs, (std::vector<uint16_t>{0x100, 0x101}));
    }
}

TEST(Instruction, decodeInstructions_whenRangeInvokeHasNoArgument_returnsNoRegister)
{
    auto insns = decode({0x0077, 0x0010, 0x0005});

    const auto *invoke = only<InvokeInstruction>(insns);
    ASSERT_NE(invoke, nullptr);
    EXPECT_TRUE(invoke->arg_regs.empty());
}

TEST(Instruction, decodeInstructions_whenRangeInvokeHas255Arguments_returnsThemAll)
{
    auto insns = decode({0xff74, 0x0010, 0x0001});

    const auto *invoke = only<InvokeInstruction>(insns);
    ASSERT_NE(invoke, nullptr);
    ASSERT_EQ(invoke->arg_regs.size(), 255u);
    EXPECT_EQ(invoke->arg_regs.front(), 1);
    EXPECT_EQ(invoke->arg_regs.back(), 255);
}

TEST(Instruction, decodeInstructions_whenInsnIsInvokePolymorphic_readsRegistersFromTheThirdUnit)
{
    auto insns = decode({0x20fa, 0x0010, 0x0021, 0x0543});

    const auto *invoke = only<InvokeInstruction>(insns);
    ASSERT_NE(invoke, nullptr);
    EXPECT_EQ(invoke->base.opcode, 0xfa);
    EXPECT_EQ(invoke->method_index, 0x10u);
    EXPECT_EQ(invoke->arg_regs, (std::vector<uint16_t>{1, 2}));
}

TEST(Instruction, decodeInstructions_whenInvokePolymorphicHasFiveArguments_returnsThemAll)
{
    auto insns = decode({0x59fa, 0x0010, 0x4321, 0x0020});

    const auto *invoke = only<InvokeInstruction>(insns);
    ASSERT_NE(invoke, nullptr);
    EXPECT_EQ(invoke->arg_regs, (std::vector<uint16_t>{1, 2, 3, 4, 9}));
}

TEST(Instruction, decodeInstructions_whenInsnIsInvokePolymorphic_takesFourUnits)
{
    auto insns = decode({0x20fa, 0x0010, 0x0021, 0x0020, 0x000e});

    ASSERT_EQ(insns.size(), 2u);
    EXPECT_EQ(base_of(insns[0]).size, 4);
    EXPECT_TRUE(std::holds_alternative<ReturnInstruction>(insns[1]));
    EXPECT_EQ(base_of(insns[1]).offset, 4u);
}

TEST(Instruction, decodeInstructions_whenInsnIsInvokePolymorphicRange_readsTheRangeFromTheThirdUnit)
{
    auto insns = decode({0x03fb, 0x0010, 0x0005, 0x0020});

    const auto *invoke = only<InvokeInstruction>(insns);
    ASSERT_NE(invoke, nullptr);
    EXPECT_EQ(invoke->base.opcode, 0xfb);
    EXPECT_EQ(invoke->method_index, 0x10u);
    EXPECT_EQ(invoke->arg_regs, (std::vector<uint16_t>{5, 6, 7}));
}

TEST(Instruction, decodeInstructions_whenInsnIsInvokePolymorphicRange_takesFourUnits)
{
    auto insns = decode({0x03fb, 0x0010, 0x0005, 0x0020, 0x000e});

    ASSERT_EQ(insns.size(), 2u);
    EXPECT_EQ(base_of(insns[0]).size, 4);
    EXPECT_TRUE(std::holds_alternative<ReturnInstruction>(insns[1]));
    EXPECT_EQ(base_of(insns[1]).offset, 4u);
}

TEST(Instruction, decodeInstructions_whenInsnIsInvokeCustom_returnsItsCallSiteAndRegisters)
{
    auto insns = decode({0x20fc, 0x0002, 0x0043});

    const auto *invoke = only<InvokeCustomInstruction>(insns);
    ASSERT_NE(invoke, nullptr);
    EXPECT_EQ(invoke->base.opcode, 0xfc);
    EXPECT_EQ(invoke->base.size, 3);
    EXPECT_EQ(invoke->call_site_index, 2u);
    EXPECT_EQ(invoke->arg_regs, (std::vector<uint16_t>{3, 4}));
}

TEST(Instruction, decodeInstructions_whenInsnIsInvokeCustomRange_returnsItsCallSiteAndRange)
{
    auto insns = decode({0x02fd, 0x0002, 0x0008});

    const auto *invoke = only<InvokeCustomInstruction>(insns);
    ASSERT_NE(invoke, nullptr);
    EXPECT_EQ(invoke->base.opcode, 0xfd);
    EXPECT_EQ(invoke->base.size, 3);
    EXPECT_EQ(invoke->call_site_index, 2u);
    EXPECT_EQ(invoke->arg_regs, (std::vector<uint16_t>{8, 9}));
}

TEST(Instruction, decodeInstructions_whenInsnIsAUnaryOp_returnsFourBitRegisters)
{
    auto insns = decode({0x217b});

    const auto *unary = only<UnaryOpInstruction>(insns);
    ASSERT_NE(unary, nullptr);
    EXPECT_EQ(unary->dest, 1);
    EXPECT_EQ(unary->src, 2);
    EXPECT_EQ(unary->base.size, 1);
}

// The widths are the operand types the Dalvik bytecode reference gives for each opcode.
TEST(Instruction, decodeInstructions_whenInsnIsAUnaryOp_returnsTheWidthsOfItsOperandTypes)
{
    const OperandWidth s = OperandWidth::Single;
    const OperandWidth p = OperandWidth::Pair;
    struct Case
    {
        uint8_t opcode;
        OperandWidth dest;
        OperandWidth src;
    };
    const Case cases[] = {
        {0x7b, s, s}, {0x7c, s, s}, {0x7d, p, p}, {0x7e, p, p}, {0x7f, s, s}, {0x80, p, p},
        {0x81, p, s}, {0x82, s, s}, {0x83, p, s}, {0x84, s, p}, {0x85, s, p}, {0x86, p, p},
        {0x87, s, s}, {0x88, p, s}, {0x89, p, s}, {0x8a, s, p}, {0x8b, p, p}, {0x8c, s, p},
        {0x8d, s, s}, {0x8e, s, s}, {0x8f, s, s},
    };

    for (const auto &c : cases) {
        auto insns = decode({unit(c.opcode, 0x21)});

        const auto *unary = only<UnaryOpInstruction>(insns);
        ASSERT_NE(unary, nullptr) << opcode_name(c.opcode);
        EXPECT_EQ(unary->dest_width, c.dest) << opcode_name(c.opcode);
        EXPECT_EQ(unary->src_width, c.src) << opcode_name(c.opcode);
    }
}

// The units are the ones dexdump shows for "mul-double v0, v0, v2" in shapes.dex.
TEST(Instruction, decodeInstructions_whenInsnIsABinaryOp_returnsDestinationAndBothSources)
{
    auto insns = decode({0x00ad, 0x0200});

    const auto *binary = only<BinaryOpInstruction>(insns);
    ASSERT_NE(binary, nullptr);
    EXPECT_EQ(binary->dest, 0);
    EXPECT_EQ(binary->src_a, 0);
    EXPECT_EQ(binary->src_b, 2);
    EXPECT_EQ(binary->width, OperandWidth::Pair);
    EXPECT_EQ(binary->base.size, 2);
}

TEST(Instruction, decodeInstructions_whenBinaryOpIsWide_returnsPairWidthAndSingleOtherwise)
{
    for (int opcode = 0x90; opcode <= 0xaf; ++opcode) {
        auto insns = decode({unit(static_cast<uint8_t>(opcode), 1), 0x0302});

        const auto *binary = only<BinaryOpInstruction>(insns);
        ASSERT_NE(binary, nullptr) << opcode;
        bool wide = (opcode >= 0x9b && opcode <= 0xa5) || opcode >= 0xab;
        EXPECT_EQ(binary->width, wide ? OperandWidth::Pair : OperandWidth::Single)
            << opcode_name(binary->base.opcode);
    }
}

// The unit is the one dexdump shows for "add-long/2addr v4, v2" in fibonacci.dex.
TEST(Instruction, decodeInstructions_whenInsnIsATwoAddressOp_usesTheDestinationAsFirstSource)
{
    auto insns = decode({0x24bb});

    const auto *binary = only<BinaryOpInstruction>(insns);
    ASSERT_NE(binary, nullptr);
    EXPECT_EQ(binary->dest, 4);
    EXPECT_EQ(binary->src_a, 4);
    EXPECT_EQ(binary->src_b, 2);
    EXPECT_EQ(binary->width, OperandWidth::Pair);
    EXPECT_EQ(binary->base.size, 1);
}

TEST(Instruction, decodeInstructions_whenTwoAddressOpIsWide_returnsPairWidthAndSingleOtherwise)
{
    for (int opcode = 0xb0; opcode <= 0xcf; ++opcode) {
        auto insns = decode({unit(static_cast<uint8_t>(opcode), 0x21)});

        const auto *binary = only<BinaryOpInstruction>(insns);
        ASSERT_NE(binary, nullptr) << opcode;
        bool wide = (opcode >= 0xbb && opcode <= 0xc5) || opcode >= 0xcb;
        EXPECT_EQ(binary->width, wide ? OperandWidth::Pair : OperandWidth::Single)
            << opcode_name(binary->base.opcode);
    }
}

TEST(Instruction, decodeInstructions_whenInsnIsALit16Op_returnsFourBitRegistersAndTheSignedLiteral)
{
    auto insns = decode({0x21d0, 0xfffe});

    const auto *binary = only<BinaryLitInstruction>(insns);
    ASSERT_NE(binary, nullptr);
    EXPECT_EQ(binary->dest, 1);
    EXPECT_EQ(binary->src, 2);
    EXPECT_EQ(binary->literal, -2);
    EXPECT_EQ(binary->base.size, 2);
}

TEST(Instruction, decodeInstructions_whenOpcodeIsAnyLit16Op_returnsABinaryLiteralOp)
{
    for (int opcode = 0xd0; opcode <= 0xd7; ++opcode) {
        auto insns = decode({unit(static_cast<uint8_t>(opcode), 0x21), 0x7fff});

        const auto *binary = only<BinaryLitInstruction>(insns);
        ASSERT_NE(binary, nullptr) << opcode;
        EXPECT_EQ(binary->base.opcode, opcode);
        EXPECT_EQ(binary->literal, 0x7fff);
    }
}

// The units are the ones dexdump shows for "add-int/lit8 v6, v6, #int 1" in fibonacci.dex.
TEST(Instruction, decodeInstructions_whenInsnIsALit8Op_returnsEightBitRegistersAndTheLiteral)
{
    auto insns = decode({0x06d8, 0x0106});

    const auto *binary = only<BinaryLitInstruction>(insns);
    ASSERT_NE(binary, nullptr);
    EXPECT_EQ(binary->dest, 6);
    EXPECT_EQ(binary->src, 6);
    EXPECT_EQ(binary->literal, 1);
    EXPECT_EQ(binary->base.size, 2);
}

TEST(Instruction, decodeInstructions_whenLit8LiteralIsNegative_signExtendsIt)
{
    auto insns = decode({0x01d8, 0x8002});

    const auto *binary = only<BinaryLitInstruction>(insns);
    ASSERT_NE(binary, nullptr);
    EXPECT_EQ(binary->src, 2);
    EXPECT_EQ(binary->literal, -128);
}

TEST(Instruction, decodeInstructions_whenOpcodeIsAnyLit8Op_returnsABinaryLiteralOp)
{
    for (int opcode = 0xd8; opcode <= 0xe2; ++opcode) {
        auto insns = decode({unit(static_cast<uint8_t>(opcode), 1), 0x7f02});

        const auto *binary = only<BinaryLitInstruction>(insns);
        ASSERT_NE(binary, nullptr) << opcode;
        EXPECT_EQ(binary->base.opcode, opcode);
        EXPECT_EQ(binary->literal, 0x7f);
    }
}

TEST(Instruction, decodeInstructions_whenOpcodeIsUnused_returnsANopOfOneUnitWithThatOpcode)
{
    auto insns = decode({0x1273});

    const auto *nop = only<NopInstruction>(insns);
    ASSERT_NE(nop, nullptr);
    EXPECT_EQ(nop->base.opcode, 0x73);
    EXPECT_EQ(nop->base.size, 1);
}

TEST(Instruction, decodeInstructions_whenOpcodeIsAnyUnusedOne_decodesTheNextUnitAsAnInstruction)
{
    std::vector<int> unused = {0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x73, 0x79, 0x7a};
    for (int opcode = 0xe3; opcode <= 0xf9; ++opcode)
        unused.push_back(opcode);

    for (int opcode : unused) {
        auto insns = decode({unit(static_cast<uint8_t>(opcode), 0xff), 0x000e});

        ASSERT_EQ(insns.size(), 2u) << opcode;
        EXPECT_TRUE(std::holds_alternative<NopInstruction>(insns[0])) << opcode;
        EXPECT_TRUE(std::holds_alternative<ReturnInstruction>(insns[1])) << opcode;
        EXPECT_EQ(base_of(insns[1]).offset, 1u) << opcode;
    }
}

TEST(Instruction, decodeInstructions_whenLastInsnIsCutOff_readsTheMissingUnitsAsZero)
{
    auto insns = decode({0x206e});

    const auto *invoke = only<InvokeInstruction>(insns);
    ASSERT_NE(invoke, nullptr);
    EXPECT_EQ(invoke->method_index, 0u);
    EXPECT_EQ(invoke->arg_regs, (std::vector<uint16_t>{0, 0}));
}

TEST(Instruction, decodeInstructions_whenLastInsnIsCutOff_keepsTheFullSizeOfItsFormat)
{
    auto insns = decode({0x000e, 0x0218, 0x0001});

    ASSERT_EQ(insns.size(), 2u);
    const auto *constant = std::get_if<ConstInstruction>(&insns[1]);
    ASSERT_NE(constant, nullptr);
    EXPECT_EQ(constant->value, 1);
    EXPECT_EQ(constant->base.offset, 1u);
    EXPECT_EQ(constant->base.size, 5);
}

TEST(Instruction, decodeInstructions_whenEveryUnitIsAnInvokeOpcodeWithoutOperands_terminates)
{
    std::vector<uint16_t> insns(1000, 0x00fa);

    auto decoded = decode_instructions(insns);

    EXPECT_EQ(decoded.size(), 250u);
}

} // namespace
} // namespace dexsplit
