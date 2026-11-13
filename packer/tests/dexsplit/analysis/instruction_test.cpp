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

} // namespace
} // namespace dexsplit
