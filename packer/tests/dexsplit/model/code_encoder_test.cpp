// Tests for the encoder of method code of the DEX writer.

#include "model/code_encoder.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <format>
#include <gtest/gtest.h>
#include <limits>
#include <optional>
#include <ostream>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "common/access_flags.hpp"
#include "common/ids.hpp"
#include "model/io.hpp"
#include "model/pools.hpp"
#include "model/types.hpp"
#include "raw/opcodes.hpp"
#include "raw/parser.hpp"
#include "raw/parsing_utils.hpp"
#include "raw/types.hpp"
#include "support/models.hpp"

namespace dexsplit::model::detail {
namespace {

using support::call_site;
using support::write_failure;

using Units = std::vector<uint16_t>;
using Names = std::vector<std::string>;

const char *const kWhere = "LT;->m()V";
const AccessFlags kPublicStatic = AccessFlags::Public | AccessFlags::Static;
constexpr int32_t kInt32Min = std::numeric_limits<int32_t>::min();
constexpr int32_t kInt32Max = std::numeric_limits<int32_t>::max();
constexpr int64_t kInt64Min = std::numeric_limits<int64_t>::min();

const std::vector<std::pair<ValueKind, std::string>> kKindSuffixes{
    {ValueKind::Normal, ""},          {ValueKind::Wide, "-wide"}, {ValueKind::Object, "-object"},
    {ValueKind::Boolean, "-boolean"}, {ValueKind::Byte, "-byte"}, {ValueKind::Char, "-char"},
    {ValueKind::Short, "-short"},
};

const std::vector<std::pair<BinaryOp, std::string>> kBinaryNames{
    {BinaryOp::AddInt, "add-int"},       {BinaryOp::SubInt, "sub-int"},
    {BinaryOp::MulInt, "mul-int"},       {BinaryOp::DivInt, "div-int"},
    {BinaryOp::RemInt, "rem-int"},       {BinaryOp::AndInt, "and-int"},
    {BinaryOp::OrInt, "or-int"},         {BinaryOp::XorInt, "xor-int"},
    {BinaryOp::ShlInt, "shl-int"},       {BinaryOp::ShrInt, "shr-int"},
    {BinaryOp::UshrInt, "ushr-int"},     {BinaryOp::AddLong, "add-long"},
    {BinaryOp::SubLong, "sub-long"},     {BinaryOp::MulLong, "mul-long"},
    {BinaryOp::DivLong, "div-long"},     {BinaryOp::RemLong, "rem-long"},
    {BinaryOp::AndLong, "and-long"},     {BinaryOp::OrLong, "or-long"},
    {BinaryOp::XorLong, "xor-long"},     {BinaryOp::ShlLong, "shl-long"},
    {BinaryOp::ShrLong, "shr-long"},     {BinaryOp::UshrLong, "ushr-long"},
    {BinaryOp::AddFloat, "add-float"},   {BinaryOp::SubFloat, "sub-float"},
    {BinaryOp::MulFloat, "mul-float"},   {BinaryOp::DivFloat, "div-float"},
    {BinaryOp::RemFloat, "rem-float"},   {BinaryOp::AddDouble, "add-double"},
    {BinaryOp::SubDouble, "sub-double"}, {BinaryOp::MulDouble, "mul-double"},
    {BinaryOp::DivDouble, "div-double"}, {BinaryOp::RemDouble, "rem-double"},
};

MethodDef method(std::string proto, AccessFlags access)
{
    MethodDef m;
    m.name = "m";
    m.proto = std::move(proto);
    m.access = access;
    return m;
}

Code code_of(std::vector<Item> items, std::vector<TryRange> tries = {})
{
    Code code;
    code.registers = 16;
    code.items = std::move(items);
    code.tries = std::move(tries);
    return code;
}

Pools pools_of(const Code &code)
{
    Pools pools;
    pools.add_code(code, true);
    pools.finish();
    return pools;
}

// The @p count added strings sort before any other string.
Pools pools_with_leading_strings(const Code &code, std::size_t count)
{
    Pools pools;
    pools.add_code(code, true);
    for (std::size_t i = 0; i < count; ++i)
        pools.add_string(std::format("!{:05}", i));
    pools.finish();
    return pools;
}

CodeOut encode(const Code &code, const Pools &pools, bool debug_info = true)
{
    CallSites sites;
    CodeEncoder encoder(pools, sites, kWhere);
    return encoder.encode(method("()V", kPublicStatic), code, debug_info);
}

CodeOut encode(const Code &code, bool debug_info = true)
{
    return encode(code, pools_of(code), debug_info);
}

Error encode_error(const Code &code)
{
    return write_failure([&] { encode(code); });
}

struct Decoded
{
    uint32_t address;
    raw::InsnFields fields;
};

std::vector<Decoded> decode(const Units &insns)
{
    std::vector<Decoded> out;
    for (uint32_t pos = 0; pos < insns.size();) {
        if (auto payload = raw::payload_units(insns, pos)) {
            pos += static_cast<uint32_t>(*payload);
            continue;
        }
        auto fields = raw::decode_insn(insns, pos);
        if (!fields.has_value())
            throw std::runtime_error(std::format("bad instruction at {}", pos));
        out.push_back({pos, *fields});
        pos += raw::opcode_info(fields->opcode).units;
    }
    return out;
}

std::string name_of(const raw::InsnFields &fields)
{
    return std::string(raw::opcode_info(fields.opcode).name);
}

Names names_of(const CodeOut &out)
{
    Names names;
    for (const Decoded &insn : decode(out.insns))
        names.push_back(name_of(insn.fields));
    return names;
}

raw::InsnFields encoded_insn(Insn insn)
{
    return decode(encode(code_of({std::move(insn)})).insns).at(0).fields;
}

std::string encoded_name(Insn insn) { return name_of(encoded_insn(std::move(insn))); }

Units units_from(const CodeOut &out, std::size_t address)
{
    return Units(out.insns.begin() + static_cast<std::ptrdiff_t>(address), out.insns.end());
}

// @p branch, which targets label 0, then @p count nops, then label 0 before a return-void.
Code forward_branch(Insn branch, std::size_t count)
{
    std::vector<Item> items{std::move(branch)};
    items.insert(items.end(), count, Item{Insn{Nop{}}});
    items.push_back(Label{0});
    items.push_back(Insn{ReturnVoid{}});
    return code_of(std::move(items));
}

// Label 0, then @p count nops, then @p branch, which targets label 0.
Code backward_branch(Insn branch, std::size_t count)
{
    std::vector<Item> items{Label{0}};
    items.insert(items.end(), count, Item{Insn{Nop{}}});
    items.push_back(std::move(branch));
    return code_of(std::move(items));
}

// A switch on v0 at 0, return-void at 3, then label k before a return-void at 4 + k.
Code switch_code(std::vector<Switch::Case> cases, uint32_t labels)
{
    std::vector<Item> items{Insn{Switch{0, std::move(cases)}}, Insn{ReturnVoid{}}};
    for (uint32_t id = 0; id < labels; ++id) {
        items.push_back(Label{id});
        items.push_back(Insn{ReturnVoid{}});
    }
    return code_of(std::move(items));
}

// Calls of 3 units at 0, 3 and 6 between labels 0..3, return-void at 9, handlers at 10 and 12.
Code three_calls(std::vector<TryRange> tries)
{
    const Insn call{Invoke{Invoke::Kind::Static, {}, MethodId{"LT;", "m", "()V"}}};
    return code_of({Label{0}, call, Label{1}, call, Label{2}, call, Label{3}, Insn{ReturnVoid{}},
                    Label{4}, Insn{MoveException{0}}, Insn{ReturnVoid{}}, Label{5},
                    Insn{MoveException{0}}, Insn{ReturnVoid{}}},
                   std::move(tries));
}

struct Handler
{
    std::vector<std::pair<std::string, uint32_t>> catches;
    std::optional<uint32_t> catch_all;

    bool operator==(const Handler &) const = default;
};

struct Try
{
    uint32_t start;
    uint32_t count;
    Handler handler;

    bool operator==(const Try &) const = default;
};

std::ostream &operator<<(std::ostream &os, const Try &t)
{
    os << "try [" << t.start << ", +" << t.count << ")";
    for (const auto &[type, address] : t.handler.catches)
        os << " " << type << "->" << address;
    if (t.handler.catch_all)
        os << " all->" << *t.handler.catch_all;
    return os;
}

Handler caught(std::vector<std::pair<std::string, uint32_t>> catches,
               std::optional<uint32_t> catch_all = std::nullopt)
{
    return Handler{std::move(catches), catch_all};
}

Handler handler_at(const CodeOut &out, uint32_t offset, const Pools &pools)
{
    std::span<const uint8_t> bytes = out.handlers;
    const int32_t size = raw::parse_utils::read_sleb128(bytes, offset).value();
    Handler handler;
    for (int32_t i = 0; i < std::abs(size); ++i) {
        uint32_t type = raw::parse_utils::read_uleb128(bytes, offset).value();
        uint32_t address = raw::parse_utils::read_uleb128(bytes, offset).value();
        handler.catches.emplace_back(pools.types().at(type), address);
    }
    if (size <= 0)
        handler.catch_all = raw::parse_utils::read_uleb128(bytes, offset).value();
    return handler;
}

std::vector<Try> tries_of(const CodeOut &out, const Pools &pools)
{
    std::vector<Try> tries;
    for (const CodeOut::Try &t : out.tries)
        tries.push_back({t.start, t.count, handler_at(out, t.handler_off, pools)});
    return tries;
}

std::vector<Try> encoded_tries(const Code &code)
{
    Pools pools = pools_of(code);
    return tries_of(encode(code, pools), pools);
}

raw::DebugInfoItem debug_item(const CodeOut &out)
{
    auto item = raw::parser::parse_debug_info(out.debug, 0);
    if (!item.has_value())
        throw std::runtime_error("bad debug info: " + item.error().message);
    return std::move(*item);
}

// A special opcode is shown as what it stands for: line -4 + (op - 10) % 15, pc (op - 10) / 15.
Names debug_ops(const CodeOut &out, const Pools &pools)
{
    auto string = [&](uint32_t index) {
        return index == raw::NO_INDEX ? std::string("-") : pools.strings().at(index);
    };
    auto type = [&](uint32_t index) {
        return index == raw::NO_INDEX ? std::string("-") : pools.types().at(index);
    };
    Names ops;
    for (const raw::DebugOp &op : debug_item(out).ops) {
        switch (op.opcode) {
        case raw::DBG_ADVANCE_PC:
            ops.push_back(std::format("advance_pc {}", op.addr_diff));
            break;
        case raw::DBG_ADVANCE_LINE:
            ops.push_back(std::format("advance_line {}", op.line_diff));
            break;
        case raw::DBG_START_LOCAL:
            ops.push_back(std::format("start_local v{} {} {}", op.reg, string(op.name_idx),
                                      type(op.type_idx)));
            break;
        case raw::DBG_START_LOCAL_EXTENDED:
            ops.push_back(std::format("start_local_extended v{} {} {} {}", op.reg,
                                      string(op.name_idx), type(op.type_idx), string(op.sig_idx)));
            break;
        case raw::DBG_END_LOCAL:
            ops.push_back(std::format("end_local v{}", op.reg));
            break;
        case raw::DBG_RESTART_LOCAL:
            ops.push_back(std::format("restart_local v{}", op.reg));
            break;
        case raw::DBG_SET_PROLOGUE_END:
            ops.push_back("prologue_end");
            break;
        case raw::DBG_SET_EPILOGUE_BEGIN:
            ops.push_back("epilogue_begin");
            break;
        case raw::DBG_SET_FILE:
            ops.push_back(std::format("set_file {}", string(op.name_idx)));
            break;
        default: {
            int adjusted = op.opcode - raw::DBG_FIRST_SPECIAL;
            ops.push_back(std::format("line {:+} pc +{}", -4 + adjusted % 15, adjusted / 15));
            break;
        }
        }
    }
    return ops;
}

Names encoded_debug_ops(const Code &code)
{
    Pools pools = pools_of(code);
    return debug_ops(encode(code, pools), pools);
}

// Two fields, so the field under test, "LT;->g:I", has index 1.
raw::InsnFields encoded_field_insn(Insn insn)
{
    const Code code =
        code_of({Insn{StaticGet{ValueKind::Normal, 0, FieldId{"LT;", "f", "I"}}}, std::move(insn)});
    return decode(encode(code).insns).at(1).fields;
}

// A nop at 0, then @p count const-wide of 5 units each, in one try range caught at the end.
Code long_try_of_wide_constants(std::size_t count)
{
    std::vector<Item> items{Label{0}, Insn{Nop{}}};
    items.insert(items.end(), count, Item{Insn{ConstWide{0, 0x123456789}}});
    items.push_back(Label{1});
    items.push_back(Insn{ReturnVoid{}});
    return code_of(std::move(items), {TryRange{Label{0}, Label{1}, {}, Label{1}}});
}

Code two_lines_apart(std::size_t units, uint32_t line_delta)
{
    std::vector<Item> items{LineNumber{100}};
    items.insert(items.end(), units, Item{Insn{Nop{}}});
    items.push_back(LineNumber{100 + line_delta});
    items.push_back(Insn{ReturnVoid{}});
    return code_of(std::move(items));
}

TEST(CodeEncoder, encode_whenCodeHasAFrameSize_copiesItToRegisters)
{
    Code code = code_of({Insn{ReturnVoid{}}});
    code.registers = 7;

    EXPECT_EQ(encode(code).registers, 7);
}

TEST(CodeEncoder, encode_whenMethodIsStaticWithoutParameters_setsNoIns)
{
    const Code code = code_of({Insn{ReturnVoid{}}});
    Pools pools = pools_of(code);
    CallSites sites;

    CodeOut out =
        CodeEncoder(pools, sites, kWhere).encode(method("()V", kPublicStatic), code, true);

    EXPECT_EQ(out.ins, 0);
}

TEST(CodeEncoder, encode_whenMethodIsStatic_countsTwoInsPerLongOrDoubleParameter)
{
    const Code code = code_of({Insn{ReturnVoid{}}});
    Pools pools = pools_of(code);
    CallSites sites;

    CodeOut out = CodeEncoder(pools, sites, kWhere)
                      .encode(method("(IJLjava/lang/String;D[J)V", kPublicStatic), code, true);

    EXPECT_EQ(out.ins, 7);
}

TEST(CodeEncoder, encode_whenMethodIsNotStatic_countsOneMoreInForThis)
{
    const Code code = code_of({Insn{ReturnVoid{}}});
    Pools pools = pools_of(code);
    CallSites sites;

    CodeOut out =
        CodeEncoder(pools, sites, kWhere).encode(method("(IJ)V", AccessFlags::Public), code, true);

    EXPECT_EQ(out.ins, 4);
}

TEST(CodeEncoder, encode_whenCodeInvokesNothing_setsNoOuts)
{
    EXPECT_EQ(encode(code_of({Insn{ReturnVoid{}}})).outs, 0);
}

TEST(CodeEncoder, encode_whenCodeInvokesMethods_setsOutsToTheLongestArgumentList)
{
    const MethodId callee{"LT;", "callee", "()V"};
    const Code code = code_of({Insn{Invoke{Invoke::Kind::Static, {0, 1}, callee}},
                               Insn{Invoke{Invoke::Kind::Static, {0, 1, 2, 3, 4}, callee}},
                               Insn{Invoke{Invoke::Kind::Static, {0}, callee}}});

    EXPECT_EQ(encode(code).outs, 5);
}

TEST(CodeEncoder, encode_whenAnInvokeTakesARegisterRange_countsEveryRegisterInOuts)
{
    const Code code = code_of(
        {Insn{Invoke{Invoke::Kind::Static, RegList::range(0, 10), MethodId{"LT;", "c", "()V"}}}});

    EXPECT_EQ(encode(code).outs, 10);
}

TEST(CodeEncoder, encode_whenCodeInvokesPolymorphically_countsItsArgumentsInOuts)
{
    const MethodId invoke{"Ljava/lang/invoke/MethodHandle;", "invoke",
                          "([Ljava/lang/Object;)Ljava/lang/Object;"};
    const Code code = code_of({Insn{InvokePolymorphic{{0, 1, 2}, invoke, "(II)V"}}});

    EXPECT_EQ(encode(code).outs, 3);
}

TEST(CodeEncoder, encode_whenCodeInvokesACallSite_countsItsArgumentsInOuts)
{
    const Code code = code_of({Insn{InvokeCustom{{0, 1}, call_site(0)}}});

    EXPECT_EQ(encode(code).outs, 2);
}

TEST(CodeEncoder, encode_whenCodeFillsANewArray_doesNotCountItsRegistersInOuts)
{
    const Code code = code_of({Insn{FilledNewArray{{0, 1, 2}, "[I"}}});

    EXPECT_EQ(encode(code).outs, 0);
}

TEST(CodeEncoder, encode_whenCodeHasNoInstructions_emitsNoUnits)
{
    EXPECT_TRUE(encode(code_of({})).insns.empty());
}

TEST(CodeEncoder, encode_whenInsnIsNop_writesAZeroUnit)
{
    EXPECT_EQ(encode(code_of({Insn{Nop{}}})).insns, (Units{0x0000}));
}

TEST(CodeEncoder, encode_whenInsnHasOneForm_writesItsOpcodeAndRegisters)
{
    struct Case
    {
        Insn insn;
        std::string name;
        raw::InsnFields operands;
    };
    const std::vector<Case> cases{
        {MoveResult{ValueKind::Normal, 200}, "move-result", {.a = 200}},
        {MoveResult{ValueKind::Wide, 200}, "move-result-wide", {.a = 200}},
        {MoveResult{ValueKind::Object, 200}, "move-result-object", {.a = 200}},
        {MoveException{200}, "move-exception", {.a = 200}},
        {ReturnVoid{}, "return-void", {}},
        {Return{ValueKind::Normal, 200}, "return", {.a = 200}},
        {Return{ValueKind::Wide, 200}, "return-wide", {.a = 200}},
        {Return{ValueKind::Object, 200}, "return-object", {.a = 200}},
        {MonitorEnter{200}, "monitor-enter", {.a = 200}},
        {MonitorExit{200}, "monitor-exit", {.a = 200}},
        {ArrayLength{1, 2}, "array-length", {.a = 1, .b = 2}},
        {Throw{200}, "throw", {.a = 200}},
    };

    for (const Case &c : cases) {
        raw::InsnFields fields = encoded_insn(c.insn);
        raw::InsnFields expected = c.operands;
        expected.opcode = fields.opcode;

        EXPECT_EQ(name_of(fields), c.name);
        EXPECT_TRUE(fields == expected) << c.name;
    }
}

TEST(CodeEncoder, encode_whenMoveRegistersAreBelowV16_usesTheShortForm)
{
    raw::InsnFields fields = encoded_insn(Move{ValueKind::Normal, 15, 14});

    EXPECT_EQ(name_of(fields), "move");
    EXPECT_EQ(fields.a, 15u);
    EXPECT_EQ(fields.b, 14u);
}

TEST(CodeEncoder, encode_whenMoveSourceIsAboveV15_usesTheFrom16Form)
{
    raw::InsnFields fields = encoded_insn(Move{ValueKind::Normal, 1, 65535});

    EXPECT_EQ(name_of(fields), "move/from16");
    EXPECT_EQ(fields.a, 1u);
    EXPECT_EQ(fields.b, 65535u);
}

TEST(CodeEncoder, encode_whenMoveDestinationIsBetweenV16AndV255_usesTheFrom16Form)
{
    EXPECT_EQ(encoded_name(Move{ValueKind::Normal, 16, 1}), "move/from16");
    EXPECT_EQ(encoded_name(Move{ValueKind::Normal, 255, 1}), "move/from16");
}

TEST(CodeEncoder, encode_whenMoveDestinationIsAboveV255_usesThe16Form)
{
    raw::InsnFields fields = encoded_insn(Move{ValueKind::Normal, 256, 1});

    EXPECT_EQ(name_of(fields), "move/16");
    EXPECT_EQ(fields.a, 256u);
    EXPECT_EQ(fields.b, 1u);
}

TEST(CodeEncoder, encode_whenMoveIsWide_usesTheWideOpcodeOfEachForm)
{
    EXPECT_EQ(encoded_name(Move{ValueKind::Wide, 1, 2}), "move-wide");
    EXPECT_EQ(encoded_name(Move{ValueKind::Wide, 1, 300}), "move-wide/from16");
    EXPECT_EQ(encoded_name(Move{ValueKind::Wide, 300, 1}), "move-wide/16");
}

TEST(CodeEncoder, encode_whenMoveIsAnObject_usesTheObjectOpcodeOfEachForm)
{
    EXPECT_EQ(encoded_name(Move{ValueKind::Object, 1, 2}), "move-object");
    EXPECT_EQ(encoded_name(Move{ValueKind::Object, 1, 300}), "move-object/from16");
    EXPECT_EQ(encoded_name(Move{ValueKind::Object, 300, 1}), "move-object/16");
}

TEST(CodeEncoder, encode_whenConstFitsFourBits_usesConst4)
{
    for (int32_t value : {0, 7, -8}) {
        raw::InsnFields fields = encoded_insn(Const{15, value});

        EXPECT_EQ(name_of(fields), "const/4") << value;
        EXPECT_EQ(fields.a, 15u);
        EXPECT_EQ(fields.literal, value);
    }
}

TEST(CodeEncoder, encode_whenConstNeedsMoreThanFourBits_usesConst16)
{
    for (int32_t value : {8, -9, 32767, -32768}) {
        raw::InsnFields fields = encoded_insn(Const{0, value});

        EXPECT_EQ(name_of(fields), "const/16") << value;
        EXPECT_EQ(fields.literal, value);
    }
}

TEST(CodeEncoder, encode_whenConstRegisterIsAboveV15_usesConst16ForASmallValue)
{
    raw::InsnFields fields = encoded_insn(Const{16, 5});

    EXPECT_EQ(name_of(fields), "const/16");
    EXPECT_EQ(fields.a, 16u);
    EXPECT_EQ(fields.literal, 5);
}

TEST(CodeEncoder, encode_whenConstHasOnlyHighBits_usesConstHigh16)
{
    const std::vector<std::pair<int32_t, int64_t>> cases{
        {0x10000, 1}, {0x7FFF0000, 0x7FFF}, {kInt32Min, -32768}, {-65536, -1}};

    for (const auto &[value, stored] : cases) {
        raw::InsnFields fields = encoded_insn(Const{0, value});

        EXPECT_EQ(name_of(fields), "const/high16") << value;
        EXPECT_EQ(fields.literal, stored);
    }
}

TEST(CodeEncoder, encode_whenConstNeedsAllItsBits_usesConst)
{
    for (int32_t value : {32768, -32769, 0x12345, kInt32Max}) {
        raw::InsnFields fields = encoded_insn(Const{0, value});

        EXPECT_EQ(name_of(fields), "const") << value;
        EXPECT_EQ(fields.literal, value);
    }
}

TEST(CodeEncoder, encode_whenConstWideFitsSixteenBits_usesConstWide16)
{
    for (int64_t value : {int64_t{0}, int64_t{7}, int64_t{32767}, int64_t{-32768}}) {
        raw::InsnFields fields = encoded_insn(ConstWide{200, value});

        EXPECT_EQ(name_of(fields), "const-wide/16") << value;
        EXPECT_EQ(fields.a, 200u);
        EXPECT_EQ(fields.literal, value);
    }
}

TEST(CodeEncoder, encode_whenConstWideHasOnlyItsTopSixteenBits_usesConstWideHigh16)
{
    const std::vector<std::pair<int64_t, int64_t>> cases{
        {int64_t{1} << 48, 1}, {kInt64Min, -32768}, {int64_t{0x7FFF} << 48, 0x7FFF}};

    for (const auto &[value, stored] : cases) {
        raw::InsnFields fields = encoded_insn(ConstWide{0, value});

        EXPECT_EQ(name_of(fields), "const-wide/high16") << value;
        EXPECT_EQ(fields.literal, stored);
    }
}

TEST(CodeEncoder, encode_whenConstWideFitsThirtyTwoBits_usesConstWide32)
{
    for (int64_t value : {int64_t{32768}, int64_t{-32769}, int64_t{0x12345678}, int64_t{kInt32Max},
                          int64_t{kInt32Min}}) {
        raw::InsnFields fields = encoded_insn(ConstWide{0, value});

        EXPECT_EQ(name_of(fields), "const-wide/32") << value;
        EXPECT_EQ(fields.literal, value);
    }
}

TEST(CodeEncoder, encode_whenConstWideNeedsAllItsBits_usesConstWide)
{
    for (int64_t value : {int64_t{kInt32Max} + 1, int64_t{kInt32Min} - 1, int64_t{0x123456789},
                          (int64_t{1} << 48) + 1}) {
        raw::InsnFields fields = encoded_insn(ConstWide{0, value});

        EXPECT_EQ(name_of(fields), "const-wide") << value;
        EXPECT_EQ(fields.literal, value);
    }
}

TEST(CodeEncoder, encode_whenCodeMixesConstants_picksTheSmallestEncodingOfEach)
{
    const Code code =
        code_of({Insn{Const{0, 5}}, Insn{Const{0, -8}}, Insn{Const{0, 100}}, Insn{Const{20, 5}},
                 Insn{Const{0, 0x10000}}, Insn{Const{0, 0x12345}}, Insn{ConstWide{0, 7}},
                 Insn{ConstWide{0, int64_t{1} << 48}}, Insn{ConstWide{0, 0x12345678}},
                 Insn{ConstWide{0, 0x123456789}}, Insn{ReturnVoid{}}});

    EXPECT_EQ(names_of(encode(code)),
              (Names{"const/4", "const/4", "const/16", "const/16", "const/high16", "const",
                     "const-wide/16", "const-wide/high16", "const-wide/32", "const-wide",
                     "return-void"}));
}

TEST(CodeEncoder, encode_whenInsnIsConstString_writesTheStringIndex)
{
    const Code code = code_of({Insn{ConstString{0, "a"}}, Insn{ConstString{200, "b"}}});

    raw::InsnFields fields = decode(encode(code).insns)[1].fields;
    raw::InsnFields expected{.opcode = fields.opcode, .a = 200, .index = 1};

    EXPECT_EQ(name_of(fields), "const-string");
    EXPECT_TRUE(fields == expected);
}

TEST(CodeEncoder, encode_whenStringIndexIs65535_usesConstString)
{
    const Code code = code_of({Insn{ConstString{0, "text"}}});
    Pools pools = pools_with_leading_strings(code, 65535);

    raw::InsnFields fields = decode(encode(code, pools).insns)[0].fields;

    EXPECT_EQ(name_of(fields), "const-string");
    EXPECT_EQ(fields.index, 65535u);
}

TEST(CodeEncoder, encode_whenStringIndexIs65536_usesConstStringJumbo)
{
    const Code code = code_of({Insn{ConstString{200, "text"}}});
    Pools pools = pools_with_leading_strings(code, 65536);

    raw::InsnFields fields = decode(encode(code, pools).insns)[0].fields;

    EXPECT_EQ(name_of(fields), "const-string/jumbo");
    EXPECT_EQ(fields.a, 200u);
    EXPECT_EQ(fields.index, 65536u);
}

TEST(CodeEncoder, encode_whenInsnNamesAType_writesTheTypeIndex)
{
    struct Case
    {
        Insn insn;
        std::string name;
        raw::InsnFields operands;
    };
    const std::vector<Case> cases{
        {ConstClass{200, "LT;"}, "const-class", {.a = 200}},
        {CheckCast{200, "LT;"}, "check-cast", {.a = 200}},
        {InstanceOf{1, 2, "LT;"}, "instance-of", {.a = 1, .b = 2}},
        {NewInstance{200, "LT;"}, "new-instance", {.a = 200}},
        {NewArray{1, 2, "LT;"}, "new-array", {.a = 1, .b = 2}},
    };

    for (const Case &c : cases) {
        const Code code = code_of({Insn{ConstString{0, "A"}}, Insn{ConstClass{0, "LA;"}}, c.insn});
        Pools pools = pools_of(code);

        raw::InsnFields fields = decode(encode(code, pools).insns)[2].fields;
        raw::InsnFields expected = c.operands;
        expected.opcode = fields.opcode;
        expected.index = pools.type("LT;");

        ASSERT_NE(pools.type("LT;"), pools.string("LT;"));
        EXPECT_EQ(name_of(fields), c.name);
        EXPECT_TRUE(fields == expected) << c.name;
    }
}

TEST(CodeEncoder, encode_whenInsnIsConstMethodHandle_writesTheHandleIndex)
{
    const MethodHandle put{MethodHandleKind::StaticPut, FieldId{"LT;", "f", "I"}};
    const MethodHandle get{MethodHandleKind::StaticGet, FieldId{"LT;", "f", "I"}};
    const Code code = code_of({Insn{ConstMethodHandle{0, put}}, Insn{ConstMethodHandle{200, get}}});

    raw::InsnFields fields = decode(encode(code).insns)[1].fields;

    EXPECT_EQ(name_of(fields), "const-method-handle");
    EXPECT_EQ(fields.a, 200u);
    EXPECT_EQ(fields.index, 1u);
}

TEST(CodeEncoder, encode_whenInsnIsConstMethodType_writesThePrototypeIndex)
{
    const Code code =
        code_of({Insn{ConstMethodType{0, "()I"}}, Insn{ConstMethodType{200, "(I)V"}}});
    Pools pools = pools_of(code);

    raw::InsnFields fields = decode(encode(code, pools).insns)[1].fields;

    EXPECT_EQ(name_of(fields), "const-method-type");
    EXPECT_EQ(fields.a, 200u);
    EXPECT_EQ(fields.index, pools.proto("(I)V"));
    EXPECT_EQ(fields.index, 1u);
}

TEST(CodeEncoder, encode_whenInsnIsCompare_writesTheOpcodeOfItsOperation)
{
    const std::vector<std::pair<CompareOp, std::string>> cases{
        {CompareOp::CmplFloat, "cmpl-float"},   {CompareOp::CmpgFloat, "cmpg-float"},
        {CompareOp::CmplDouble, "cmpl-double"}, {CompareOp::CmpgDouble, "cmpg-double"},
        {CompareOp::CmpLong, "cmp-long"},
    };

    for (const auto &[op, name] : cases) {
        raw::InsnFields fields = encoded_insn(Compare{op, 200, 201, 202});
        raw::InsnFields expected{.opcode = fields.opcode, .a = 200, .b = 201, .c = 202};

        EXPECT_EQ(name_of(fields), name);
        EXPECT_TRUE(fields == expected) << name;
    }
}

TEST(CodeEncoder, encode_whenInsnIsArrayGet_writesTheOpcodeOfItsKind)
{
    for (const auto &[kind, suffix] : kKindSuffixes) {
        raw::InsnFields fields = encoded_insn(ArrayGet{kind, 200, 201, 202});
        raw::InsnFields expected{.opcode = fields.opcode, .a = 200, .b = 201, .c = 202};

        EXPECT_EQ(name_of(fields), "aget" + suffix);
        EXPECT_TRUE(fields == expected) << suffix;
    }
}

TEST(CodeEncoder, encode_whenInsnIsArrayPut_writesTheOpcodeOfItsKind)
{
    for (const auto &[kind, suffix] : kKindSuffixes) {
        raw::InsnFields fields = encoded_insn(ArrayPut{kind, 200, 201, 202});
        raw::InsnFields expected{.opcode = fields.opcode, .a = 200, .b = 201, .c = 202};

        EXPECT_EQ(name_of(fields), "aput" + suffix);
        EXPECT_TRUE(fields == expected) << suffix;
    }
}

TEST(CodeEncoder, encode_whenInsnIsInstanceGet_writesTheOpcodeOfItsKindAndTheFieldIndex)
{
    for (const auto &[kind, suffix] : kKindSuffixes) {
        raw::InsnFields fields =
            encoded_field_insn(InstanceGet{kind, 1, 2, FieldId{"LT;", "g", "I"}});
        raw::InsnFields expected{.opcode = fields.opcode, .a = 1, .b = 2, .index = 1};

        EXPECT_EQ(name_of(fields), "iget" + suffix);
        EXPECT_TRUE(fields == expected) << suffix;
    }
}

TEST(CodeEncoder, encode_whenInsnIsInstancePut_writesTheOpcodeOfItsKindAndTheFieldIndex)
{
    for (const auto &[kind, suffix] : kKindSuffixes) {
        raw::InsnFields fields =
            encoded_field_insn(InstancePut{kind, 1, 2, FieldId{"LT;", "g", "I"}});
        raw::InsnFields expected{.opcode = fields.opcode, .a = 1, .b = 2, .index = 1};

        EXPECT_EQ(name_of(fields), "iput" + suffix);
        EXPECT_TRUE(fields == expected) << suffix;
    }
}

TEST(CodeEncoder, encode_whenInsnIsStaticGet_writesTheOpcodeOfItsKindAndTheFieldIndex)
{
    for (const auto &[kind, suffix] : kKindSuffixes) {
        raw::InsnFields fields = encoded_field_insn(StaticGet{kind, 200, FieldId{"LT;", "g", "I"}});
        raw::InsnFields expected{.opcode = fields.opcode, .a = 200, .index = 1};

        EXPECT_EQ(name_of(fields), "sget" + suffix);
        EXPECT_TRUE(fields == expected) << suffix;
    }
}

TEST(CodeEncoder, encode_whenInsnIsStaticPut_writesTheOpcodeOfItsKindAndTheFieldIndex)
{
    for (const auto &[kind, suffix] : kKindSuffixes) {
        raw::InsnFields fields = encoded_field_insn(StaticPut{kind, 200, FieldId{"LT;", "g", "I"}});
        raw::InsnFields expected{.opcode = fields.opcode, .a = 200, .index = 1};

        EXPECT_EQ(name_of(fields), "sput" + suffix);
        EXPECT_TRUE(fields == expected) << suffix;
    }
}

TEST(CodeEncoder, encode_whenInsnIsUnary_writesTheOpcodeOfItsOperation)
{
    const std::vector<std::pair<UnaryOp, std::string>> cases{
        {UnaryOp::NegInt, "neg-int"},
        {UnaryOp::NotInt, "not-int"},
        {UnaryOp::NegLong, "neg-long"},
        {UnaryOp::NotLong, "not-long"},
        {UnaryOp::NegFloat, "neg-float"},
        {UnaryOp::NegDouble, "neg-double"},
        {UnaryOp::IntToLong, "int-to-long"},
        {UnaryOp::IntToFloat, "int-to-float"},
        {UnaryOp::IntToDouble, "int-to-double"},
        {UnaryOp::LongToInt, "long-to-int"},
        {UnaryOp::LongToFloat, "long-to-float"},
        {UnaryOp::LongToDouble, "long-to-double"},
        {UnaryOp::FloatToInt, "float-to-int"},
        {UnaryOp::FloatToLong, "float-to-long"},
        {UnaryOp::FloatToDouble, "float-to-double"},
        {UnaryOp::DoubleToInt, "double-to-int"},
        {UnaryOp::DoubleToLong, "double-to-long"},
        {UnaryOp::DoubleToFloat, "double-to-float"},
        {UnaryOp::IntToByte, "int-to-byte"},
        {UnaryOp::IntToChar, "int-to-char"},
        {UnaryOp::IntToShort, "int-to-short"},
    };

    for (const auto &[op, name] : cases) {
        raw::InsnFields fields = encoded_insn(Unary{op, 1, 2});
        raw::InsnFields expected{.opcode = fields.opcode, .a = 1, .b = 2};

        EXPECT_EQ(name_of(fields), name);
        EXPECT_TRUE(fields == expected) << name;
    }
}

TEST(CodeEncoder, encode_whenBinaryHasThreeDifferentRegisters_usesTheThreeAddressForm)
{
    for (const auto &[op, name] : kBinaryNames) {
        raw::InsnFields fields = encoded_insn(Binary{op, 200, 201, 202});
        raw::InsnFields expected{.opcode = fields.opcode, .a = 200, .b = 201, .c = 202};

        EXPECT_EQ(name_of(fields), name);
        EXPECT_TRUE(fields == expected) << name;
    }
}

TEST(CodeEncoder, encode_whenBinaryWritesItsFirstOperandBelowV16_usesTheTwoAddressForm)
{
    for (const auto &[op, name] : kBinaryNames) {
        raw::InsnFields fields = encoded_insn(Binary{op, 15, 15, 14});
        raw::InsnFields expected{.opcode = fields.opcode, .a = 15, .b = 14};

        EXPECT_EQ(name_of(fields), name + "/2addr");
        EXPECT_TRUE(fields == expected) << name;
    }
}

TEST(CodeEncoder, encode_whenBinaryWritesItsFirstOperandAboveV15_usesTheThreeAddressForm)
{
    raw::InsnFields fields = encoded_insn(Binary{BinaryOp::AddInt, 16, 16, 2});

    EXPECT_EQ(name_of(fields), "add-int");
    EXPECT_EQ(fields.a, 16u);
    EXPECT_EQ(fields.b, 16u);
    EXPECT_EQ(fields.c, 2u);
}

TEST(CodeEncoder, encode_whenBinarySecondOperandIsAboveV15_usesTheThreeAddressForm)
{
    EXPECT_EQ(encoded_name(Binary{BinaryOp::AddInt, 1, 1, 16}), "add-int");
}

TEST(CodeEncoder, encode_whenBinaryWritesItsSecondOperand_usesTheThreeAddressForm)
{
    EXPECT_EQ(encoded_name(Binary{BinaryOp::SubInt, 2, 1, 2}), "sub-int");
}

TEST(CodeEncoder, encode_whenLiteralFitsEightBits_usesTheLit8Form)
{
    const std::vector<std::pair<LiteralOp, std::string>> cases{
        {LiteralOp::Add, "add-int/lit8"},   {LiteralOp::Rsub, "rsub-int/lit8"},
        {LiteralOp::Mul, "mul-int/lit8"},   {LiteralOp::Div, "div-int/lit8"},
        {LiteralOp::Rem, "rem-int/lit8"},   {LiteralOp::And, "and-int/lit8"},
        {LiteralOp::Or, "or-int/lit8"},     {LiteralOp::Xor, "xor-int/lit8"},
        {LiteralOp::Shl, "shl-int/lit8"},   {LiteralOp::Shr, "shr-int/lit8"},
        {LiteralOp::Ushr, "ushr-int/lit8"},
    };

    for (const auto &[op, name] : cases) {
        raw::InsnFields fields = encoded_insn(BinaryLiteral{op, 200, 201, -128});
        raw::InsnFields expected{.opcode = fields.opcode, .a = 200, .b = 201, .literal = -128};

        EXPECT_EQ(name_of(fields), name);
        EXPECT_TRUE(fields == expected) << name;
    }
}

TEST(CodeEncoder, encode_whenLiteralNeedsSixteenBits_usesTheLit16Form)
{
    const std::vector<std::pair<LiteralOp, std::string>> cases{
        {LiteralOp::Add, "add-int/lit16"}, {LiteralOp::Rsub, "rsub-int"},
        {LiteralOp::Mul, "mul-int/lit16"}, {LiteralOp::Div, "div-int/lit16"},
        {LiteralOp::Rem, "rem-int/lit16"}, {LiteralOp::And, "and-int/lit16"},
        {LiteralOp::Or, "or-int/lit16"},   {LiteralOp::Xor, "xor-int/lit16"},
    };

    for (const auto &[op, name] : cases) {
        raw::InsnFields fields = encoded_insn(BinaryLiteral{op, 14, 15, -32768});
        raw::InsnFields expected{.opcode = fields.opcode, .a = 14, .b = 15, .literal = -32768};

        EXPECT_EQ(name_of(fields), name);
        EXPECT_TRUE(fields == expected) << name;
    }
}

TEST(CodeEncoder, encode_whenLiteralIsAtTheEightBitLimits_usesTheLit8Form)
{
    EXPECT_EQ(encoded_name(BinaryLiteral{LiteralOp::Add, 1, 2, 127}), "add-int/lit8");
    EXPECT_EQ(encoded_name(BinaryLiteral{LiteralOp::Add, 1, 2, -128}), "add-int/lit8");
}

TEST(CodeEncoder, encode_whenLiteralIsOnePastTheEightBitLimits_usesTheLit16Form)
{
    EXPECT_EQ(encoded_name(BinaryLiteral{LiteralOp::Add, 1, 2, 128}), "add-int/lit16");
    EXPECT_EQ(encoded_name(BinaryLiteral{LiteralOp::Add, 1, 2, -129}), "add-int/lit16");
}

TEST(CodeEncoder, encode_whenAShiftLiteralNeedsSixteenBits_fails)
{
    Error error = encode_error(code_of({Insn{BinaryLiteral{LiteralOp::Shl, 1, 2, 300}}}));

    EXPECT_EQ(error.kind, Error::Kind::Invalid);
    EXPECT_EQ(error.message,
              "LT;->m()V, item 0: the instruction's operands do not fit its encoding");
}

TEST(CodeEncoder, encode_whenARegisterDoesNotFitTheInstruction_failsNamingTheItem)
{
    const Code code = code_of(
        {Insn{Nop{}}, Insn{InstanceGet{ValueKind::Normal, 16, 1, FieldId{"LT;", "f", "I"}}}});

    Error error = encode_error(code);

    EXPECT_EQ(error.kind, Error::Kind::Invalid);
    EXPECT_EQ(error.message,
              "LT;->m()V, item 1: the instruction's operands do not fit its encoding");
}

TEST(CodeEncoder, encode_whenInvokeHasUpToFiveRegistersBelowV16_listsThem)
{
    const std::vector<Reg> regs{15, 3, 9, 1, 12};
    for (std::size_t count = 0; count <= regs.size(); ++count) {
        const RegList args(std::span<const Reg>(regs.data(), count));
        raw::InsnFields expected{.a = static_cast<uint32_t>(count)};
        for (std::size_t i = 0; i < count; ++i)
            expected.args[i] = regs[i];

        raw::InsnFields fields =
            encoded_insn(Invoke{Invoke::Kind::Virtual, args, MethodId{"LT;", "c", "()V"}});
        expected.opcode = fields.opcode;

        EXPECT_EQ(name_of(fields), "invoke-virtual") << count;
        EXPECT_TRUE(fields == expected) << count;
    }
}

TEST(CodeEncoder, encode_whenInsnIsInvoke_writesTheOpcodeOfItsKind)
{
    const std::vector<std::pair<Invoke::Kind, std::string>> cases{
        {Invoke::Kind::Virtual, "invoke-virtual"},     {Invoke::Kind::Super, "invoke-super"},
        {Invoke::Kind::Direct, "invoke-direct"},       {Invoke::Kind::Static, "invoke-static"},
        {Invoke::Kind::Interface, "invoke-interface"},
    };

    for (const auto &[kind, name] : cases) {
        const MethodId callee{"LT;", "c", "()V"};

        EXPECT_EQ(encoded_name(Invoke{kind, {1}, callee}), name);
        EXPECT_EQ(encoded_name(Invoke{kind, {16}, callee}), name + "/range");
    }
}

TEST(CodeEncoder, encode_whenInsnIsInvoke_writesTheMethodIndex)
{
    const Code code =
        code_of({Insn{Invoke{Invoke::Kind::Static, {}, MethodId{"LT;", "a", "()V"}}},
                 Insn{Invoke{Invoke::Kind::Static, {}, MethodId{"LT;", "b", "()V"}}}});

    EXPECT_EQ(decode(encode(code).insns)[1].fields.index, 1u);
}

TEST(CodeEncoder, encode_whenAnInvokeRegisterIsAboveV15_usesTheRangeForm)
{
    raw::InsnFields fields =
        encoded_insn(Invoke{Invoke::Kind::Static, {16}, MethodId{"LT;", "c", "()V"}});
    raw::InsnFields expected{.opcode = fields.opcode, .a = 1, .c = 16};

    EXPECT_EQ(name_of(fields), "invoke-static/range");
    EXPECT_TRUE(fields == expected);
}

TEST(CodeEncoder, encode_whenInvokeHasSixConsecutiveRegisters_usesTheRangeForm)
{
    raw::InsnFields fields = encoded_insn(
        Invoke{Invoke::Kind::Static, RegList::range(3, 6), MethodId{"LT;", "c", "()V"}});
    raw::InsnFields expected{.opcode = fields.opcode, .a = 6, .c = 3};

    EXPECT_EQ(name_of(fields), "invoke-static/range");
    EXPECT_TRUE(fields == expected);
}

TEST(CodeEncoder, encode_whenInvokeHasFiveConsecutiveRegistersBelowV16_listsThem)
{
    EXPECT_EQ(encoded_name(
                  Invoke{Invoke::Kind::Static, RegList::range(3, 5), MethodId{"LT;", "c", "()V"}}),
              "invoke-static");
}

TEST(CodeEncoder, encode_whenInvokeHas255ConsecutiveRegisters_usesTheRangeForm)
{
    raw::InsnFields fields = encoded_insn(
        Invoke{Invoke::Kind::Static, RegList::range(65281, 255), MethodId{"LT;", "c", "()V"}});

    EXPECT_EQ(name_of(fields), "invoke-static/range");
    EXPECT_EQ(fields.a, 255u);
    EXPECT_EQ(fields.c, 65281u);
}

TEST(CodeEncoder, encode_whenInvokeHas256ConsecutiveRegisters_fails)
{
    Error error = encode_error(code_of(
        {Insn{Invoke{Invoke::Kind::Static, RegList::range(0, 256), MethodId{"LT;", "c", "()V"}}}}));

    EXPECT_EQ(error.kind, Error::Kind::Invalid);
    EXPECT_EQ(error.message,
              "LT;->m()V, item 0: argument registers are neither five below v16 nor a run");
}

TEST(CodeEncoder, encode_whenInvokeHasSixRegistersThatAreNotARun_fails)
{
    Error error = encode_error(code_of(
        {Insn{Invoke{Invoke::Kind::Static, {1, 3, 5, 7, 9, 11}, MethodId{"LT;", "c", "()V"}}}}));

    EXPECT_EQ(error.kind, Error::Kind::Invalid);
    EXPECT_EQ(error.message,
              "LT;->m()V, item 0: argument registers are neither five below v16 nor a run");
}

TEST(CodeEncoder, encode_whenInvokeHasAHighRegisterOutsideARun_failsNamingTheItem)
{
    const Code code =
        code_of({Insn{Nop{}}, Label{0},
                 Insn{Invoke{Invoke::Kind::Static, {1, 2, 16}, MethodId{"LT;", "c", "()V"}}}});

    Error error = encode_error(code);

    EXPECT_EQ(error.kind, Error::Kind::Invalid);
    EXPECT_EQ(error.message,
              "LT;->m()V, item 2: argument registers are neither five below v16 nor a run");
}

TEST(CodeEncoder, encode_whenInsnIsFilledNewArray_listsItsRegistersAndTheTypeIndex)
{
    const Code code = code_of({Insn{ConstClass{0, "LA;"}}, Insn{FilledNewArray{{4, 2}, "[I"}}});
    Pools pools = pools_of(code);

    raw::InsnFields fields = decode(encode(code, pools).insns)[1].fields;
    raw::InsnFields expected{
        .opcode = fields.opcode, .a = 2, .index = pools.type("[I"), .args = {4, 2}};

    EXPECT_EQ(name_of(fields), "filled-new-array");
    EXPECT_EQ(expected.index, 1u);
    EXPECT_TRUE(fields == expected);
}

TEST(CodeEncoder, encode_whenFilledNewArrayHasSixConsecutiveRegisters_usesTheRangeForm)
{
    raw::InsnFields fields = encoded_insn(FilledNewArray{RegList::range(20, 6), "[I"});
    raw::InsnFields expected{.opcode = fields.opcode, .a = 6, .c = 20};

    EXPECT_EQ(name_of(fields), "filled-new-array/range");
    EXPECT_TRUE(fields == expected);
}

TEST(CodeEncoder, encode_whenInsnIsInvokePolymorphic_writesTheMethodAndThePrototypeIndex)
{
    const MethodId invoke{"Ljava/lang/invoke/MethodHandle;", "invoke",
                          "([Ljava/lang/Object;)Ljava/lang/Object;"};
    const Code code = code_of({Insn{Invoke{Invoke::Kind::Static, {}, MethodId{"LA;", "a", "()V"}}},
                               Insn{InvokePolymorphic{{4, 2}, invoke, "(I)V"}}});
    Pools pools = pools_of(code);

    raw::InsnFields fields = decode(encode(code, pools).insns)[1].fields;
    raw::InsnFields expected{.opcode = fields.opcode,
                             .a = 2,
                             .index = pools.method(invoke),
                             .proto = pools.proto("(I)V"),
                             .args = {4, 2}};

    ASSERT_NE(expected.index, expected.proto);
    EXPECT_EQ(name_of(fields), "invoke-polymorphic");
    EXPECT_TRUE(fields == expected);
}

TEST(CodeEncoder, encode_whenInvokePolymorphicHasAHighRegister_usesTheRangeForm)
{
    const MethodId invoke{"Ljava/lang/invoke/MethodHandle;", "invoke",
                          "([Ljava/lang/Object;)Ljava/lang/Object;"};
    const Code code = code_of({Insn{InvokePolymorphic{RegList::range(20, 2), invoke, "(I)V"}}});
    Pools pools = pools_of(code);

    raw::InsnFields fields = decode(encode(code, pools).insns)[0].fields;
    raw::InsnFields expected{.opcode = fields.opcode,
                             .a = 2,
                             .c = 20,
                             .index = pools.method(invoke),
                             .proto = pools.proto("(I)V")};

    EXPECT_EQ(name_of(fields), "invoke-polymorphic/range");
    EXPECT_TRUE(fields == expected);
}

TEST(CodeEncoder, encode_whenCallSitesHaveNoShareKey_numbersEachInvokeCustomInOrder)
{
    const Code code =
        code_of({Insn{InvokeCustom{{}, call_site(0)}}, Insn{InvokeCustom{{4, 2}, call_site(0)}}});

    std::vector<Decoded> insns = decode(encode(code).insns);
    raw::InsnFields expected{.opcode = insns[1].fields.opcode, .a = 2, .index = 1, .args = {4, 2}};

    EXPECT_EQ(name_of(insns[0].fields), "invoke-custom");
    EXPECT_EQ(insns[0].fields.index, 0u);
    EXPECT_TRUE(insns[1].fields == expected);
}

TEST(CodeEncoder, encode_whenCallSitesShareAKey_writesOneCallSiteIndex)
{
    const Code code =
        code_of({Insn{InvokeCustom{{}, call_site(0)}}, Insn{InvokeCustom{{}, call_site(7)}},
                 Insn{InvokeCustom{{}, call_site(7)}}});

    std::vector<Decoded> insns = decode(encode(code).insns);

    EXPECT_EQ(insns[1].fields.index, 1u);
    EXPECT_EQ(insns[2].fields.index, 1u);
}

TEST(CodeEncoder, encode_whenCalledForTwoMethods_keepsNumberingCallSitesInTheSameList)
{
    const Code first = code_of({Insn{InvokeCustom{{}, call_site(0)}}});
    const Code second = code_of({Insn{InvokeCustom{{}, call_site(0)}}});
    Pools pools = pools_of(first);
    CallSites sites;
    CodeEncoder(pools, sites, kWhere).encode(method("()V", kPublicStatic), first, true);

    CodeOut out =
        CodeEncoder(pools, sites, kWhere).encode(method("()V", kPublicStatic), second, true);

    EXPECT_EQ(decode(out.insns)[0].fields.index, 1u);
    EXPECT_EQ(sites.list().size(), 2u);
}

TEST(CodeEncoder, encode_whenInvokeCustomHasAHighRegister_usesTheRangeForm)
{
    raw::InsnFields fields = encoded_insn(InvokeCustom{RegList::range(20, 3), call_site(0)});
    raw::InsnFields expected{.opcode = fields.opcode, .a = 3, .c = 20};

    EXPECT_EQ(name_of(fields), "invoke-custom/range");
    EXPECT_TRUE(fields == expected);
}

TEST(CodeEncoder, encode_whenGotoTargetsTheNextInstruction_usesGotoWithOffsetOne)
{
    CodeOut out = encode(forward_branch(Goto{Label{0}}, 0));

    EXPECT_EQ(out.insns, (Units{0x0128, 0x000e}));
}

TEST(CodeEncoder, encode_whenGotoIs127UnitsBeforeItsTarget_usesGoto)
{
    raw::InsnFields fields = decode(encode(forward_branch(Goto{Label{0}}, 126)).insns)[0].fields;

    EXPECT_EQ(name_of(fields), "goto");
    EXPECT_EQ(fields.offset, 127);
}

TEST(CodeEncoder, encode_whenGotoIsMoreThan127UnitsBeforeItsTarget_usesGoto16)
{
    raw::InsnFields fields = decode(encode(forward_branch(Goto{Label{0}}, 127)).insns)[0].fields;

    EXPECT_EQ(name_of(fields), "goto/16");
    EXPECT_EQ(fields.offset, 129);
}

TEST(CodeEncoder, encode_whenGotoIs128UnitsAfterItsTarget_usesGoto)
{
    Decoded last = decode(encode(backward_branch(Goto{Label{0}}, 128)).insns).back();

    EXPECT_EQ(name_of(last.fields), "goto");
    EXPECT_EQ(last.fields.offset, -128);
}

TEST(CodeEncoder, encode_whenGotoIs129UnitsAfterItsTarget_usesGoto16)
{
    Decoded last = decode(encode(backward_branch(Goto{Label{0}}, 129)).insns).back();

    EXPECT_EQ(name_of(last.fields), "goto/16");
    EXPECT_EQ(last.fields.offset, -129);
}

TEST(CodeEncoder, encode_whenGotoIs32767UnitsBeforeItsTarget_usesGoto16)
{
    raw::InsnFields fields = decode(encode(forward_branch(Goto{Label{0}}, 32765)).insns)[0].fields;

    EXPECT_EQ(name_of(fields), "goto/16");
    EXPECT_EQ(fields.offset, 32767);
}

TEST(CodeEncoder, encode_whenGotoIsMoreThan32767UnitsBeforeItsTarget_usesGoto32)
{
    raw::InsnFields fields = decode(encode(forward_branch(Goto{Label{0}}, 32766)).insns)[0].fields;

    EXPECT_EQ(name_of(fields), "goto/32");
    EXPECT_EQ(fields.offset, 32769);
}

TEST(CodeEncoder, encode_whenGotoIs32768UnitsAfterItsTarget_usesGoto16)
{
    Decoded last = decode(encode(backward_branch(Goto{Label{0}}, 32768)).insns).back();

    EXPECT_EQ(name_of(last.fields), "goto/16");
    EXPECT_EQ(last.fields.offset, -32768);
}

TEST(CodeEncoder, encode_whenGotoIs32769UnitsAfterItsTarget_usesGoto32)
{
    Decoded last = decode(encode(backward_branch(Goto{Label{0}}, 32769)).insns).back();

    EXPECT_EQ(name_of(last.fields), "goto/32");
    EXPECT_EQ(last.fields.offset, -32769);
}

TEST(CodeEncoder, encode_whenGotoTargetsItself_usesGoto32WithOffsetZero)
{
    CodeOut out = encode(code_of({Label{0}, Insn{Goto{Label{0}}}}));

    EXPECT_EQ(out.insns, (Units{0x002a, 0, 0}));
}

TEST(CodeEncoder, encode_whenIfIsNearItsTarget_writesItsOpcodeRegistersAndOffset)
{
    const std::vector<std::pair<Condition, std::string>> cases{
        {Condition::Eq, "if-eq"}, {Condition::Ne, "if-ne"}, {Condition::Lt, "if-lt"},
        {Condition::Ge, "if-ge"}, {Condition::Gt, "if-gt"}, {Condition::Le, "if-le"},
    };

    for (const auto &[cond, name] : cases) {
        raw::InsnFields fields =
            decode(encode(forward_branch(If{cond, 14, 15, Label{0}}, 3)).insns)[0].fields;
        raw::InsnFields expected{.opcode = fields.opcode, .a = 14, .b = 15, .offset = 5};

        EXPECT_EQ(name_of(fields), name);
        EXPECT_TRUE(fields == expected) << name;
    }
}

TEST(CodeEncoder, encode_whenIfZeroIsNearItsTarget_writesItsOpcodeRegisterAndOffset)
{
    const std::vector<std::pair<Condition, std::string>> cases{
        {Condition::Eq, "if-eqz"}, {Condition::Ne, "if-nez"}, {Condition::Lt, "if-ltz"},
        {Condition::Ge, "if-gez"}, {Condition::Gt, "if-gtz"}, {Condition::Le, "if-lez"},
    };

    for (const auto &[cond, name] : cases) {
        raw::InsnFields fields =
            decode(encode(forward_branch(IfZero{cond, 200, Label{0}}, 3)).insns)[0].fields;
        raw::InsnFields expected{.opcode = fields.opcode, .a = 200, .offset = 5};

        EXPECT_EQ(name_of(fields), name);
        EXPECT_TRUE(fields == expected) << name;
    }
}

TEST(CodeEncoder, encode_whenIfIs32767UnitsBeforeItsTarget_usesOneIf)
{
    std::vector<Decoded> insns =
        decode(encode(forward_branch(IfZero{Condition::Eq, 0, Label{0}}, 32765)).insns);

    EXPECT_EQ(name_of(insns[0].fields), "if-eqz");
    EXPECT_EQ(insns[0].fields.offset, 32767);
    EXPECT_EQ(name_of(insns[1].fields), "nop");
}

TEST(CodeEncoder, encode_whenIfIsMoreThan32767UnitsBeforeItsTarget_branchesOverAGoto32)
{
    std::vector<Decoded> insns =
        decode(encode(forward_branch(IfZero{Condition::Eq, 0, Label{0}}, 32766)).insns);

    EXPECT_EQ(name_of(insns[0].fields), "if-nez");
    EXPECT_EQ(insns[0].fields.offset, 5);
    EXPECT_EQ(insns[1].address, 2u);
    EXPECT_EQ(name_of(insns[1].fields), "goto/32");
    EXPECT_EQ(insns[1].fields.offset, 32769);
}

TEST(CodeEncoder, encode_whenIfIs32768UnitsAfterItsTarget_usesOneIf)
{
    Decoded last =
        decode(encode(backward_branch(IfZero{Condition::Eq, 0, Label{0}}, 32768)).insns).back();

    EXPECT_EQ(name_of(last.fields), "if-eqz");
    EXPECT_EQ(last.fields.offset, -32768);
}

TEST(CodeEncoder, encode_whenIfIs32769UnitsAfterItsTarget_branchesOverAGoto32)
{
    std::vector<Decoded> insns =
        decode(encode(backward_branch(IfZero{Condition::Eq, 0, Label{0}}, 32769)).insns);
    const Decoded &branch = insns[insns.size() - 2];
    const Decoded &jump = insns.back();

    EXPECT_EQ(branch.address, 32769u);
    EXPECT_EQ(name_of(branch.fields), "if-nez");
    EXPECT_EQ(branch.fields.offset, 5);
    EXPECT_EQ(name_of(jump.fields), "goto/32");
    EXPECT_EQ(jump.fields.offset, -32771);
}

TEST(CodeEncoder, encode_whenAFarIfComparesTwoRegisters_turnsTheConditionAroundAndKeepsThem)
{
    const std::vector<std::pair<Condition, std::string>> cases{
        {Condition::Eq, "if-ne"}, {Condition::Ne, "if-eq"}, {Condition::Lt, "if-ge"},
        {Condition::Ge, "if-lt"}, {Condition::Gt, "if-le"}, {Condition::Le, "if-gt"},
    };

    for (const auto &[cond, name] : cases) {
        raw::InsnFields fields =
            decode(encode(forward_branch(If{cond, 14, 15, Label{0}}, 40000)).insns)[0].fields;
        raw::InsnFields expected{.opcode = fields.opcode, .a = 14, .b = 15, .offset = 5};

        EXPECT_EQ(name_of(fields), name);
        EXPECT_TRUE(fields == expected) << name;
    }
}

TEST(CodeEncoder, encode_whenAFarIfComparesWithZero_turnsTheConditionAroundAndKeepsTheRegister)
{
    const std::vector<std::pair<Condition, std::string>> cases{
        {Condition::Eq, "if-nez"}, {Condition::Ne, "if-eqz"}, {Condition::Lt, "if-gez"},
        {Condition::Ge, "if-ltz"}, {Condition::Gt, "if-lez"}, {Condition::Le, "if-gtz"},
    };

    for (const auto &[cond, name] : cases) {
        raw::InsnFields fields =
            decode(encode(forward_branch(IfZero{cond, 200, Label{0}}, 40000)).insns)[0].fields;
        raw::InsnFields expected{.opcode = fields.opcode, .a = 200, .offset = 5};

        EXPECT_EQ(name_of(fields), name);
        EXPECT_TRUE(fields == expected) << name;
    }
}

TEST(CodeEncoder, encode_whenIfZeroTargetsItself_branchesBackToANop)
{
    const Code code =
        code_of({Label{0}, Insn{IfZero{Condition::Eq, 0, Label{0}}}, Insn{ReturnVoid{}}});

    // nop; if-eqz v0, -1; return-void
    EXPECT_EQ(encode(code).insns, (Units{0x0000, 0x0038, 0xffff, 0x000e}));
}

TEST(CodeEncoder, encode_whenIfTargetsItself_branchesBackToANop)
{
    const Code code =
        code_of({Label{0}, Insn{If{Condition::Lt, 1, 2, Label{0}}}, Insn{ReturnVoid{}}});

    // nop; if-lt v1, v2, -1; return-void
    EXPECT_EQ(encode(code).insns, (Units{0x0000, 0x2134, 0xffff, 0x000e}));
}

TEST(CodeEncoder, encode_whenAnIfTargetsItself_putsLaterLabelsAfterTheAddedNop)
{
    const Code code = code_of({Label{0}, Insn{IfZero{Condition::Eq, 0, Label{0}}}, Label{1},
                               Insn{ReturnVoid{}}, Insn{Goto{Label{1}}}});

    std::vector<Decoded> insns = decode(encode(code).insns);

    EXPECT_EQ(insns.back().address, 4u);
    EXPECT_EQ(insns.back().fields.offset, -1);
}

TEST(CodeEncoder, encode_whenAGrowingBranchPushesAnotherOutOfRange_growsThatOneToo)
{
    std::vector<Item> items{Insn{Goto{Label{0}}}, Insn{Goto{Label{1}}}};
    items.insert(items.end(), 125, Item{Insn{Nop{}}});
    items.push_back(Label{0});
    items.insert(items.end(), 10, Item{Insn{Nop{}}});
    items.push_back(Label{1});
    items.push_back(Insn{ReturnVoid{}});

    std::vector<Decoded> insns = decode(encode(code_of(std::move(items))).insns);

    EXPECT_EQ(name_of(insns[0].fields), "goto/16");
    EXPECT_EQ(insns[0].fields.offset, 129);
    EXPECT_EQ(name_of(insns[1].fields), "goto/16");
    EXPECT_EQ(insns[1].fields.offset, 137);
}

TEST(CodeEncoder, encode_whenAFarIfIsFollowedByAGoto_growsEachBranchAsFarAsItNeeds)
{
    std::vector<Item> items{Insn{IfZero{Condition::Eq, 0, Label{1}}}, Insn{Goto{Label{0}}}};
    items.insert(items.end(), 200, Item{Insn{Nop{}}});
    items.push_back(Label{0});
    items.insert(items.end(), 40000, Item{Insn{Nop{}}});
    items.push_back(Label{1});
    items.push_back(Insn{ReturnVoid{}});

    std::vector<Decoded> insns = decode(encode(code_of(std::move(items))).insns);

    EXPECT_EQ(name_of(insns[0].fields), "if-nez");
    EXPECT_EQ(insns[0].fields.offset, 5);
    EXPECT_EQ(insns[1].address, 2u);
    EXPECT_EQ(name_of(insns[1].fields), "goto/32");
    EXPECT_EQ(insns[1].fields.offset, 5 + 2 + 200 + 40000 - 2);
    EXPECT_EQ(insns[2].address, 5u);
    EXPECT_EQ(name_of(insns[2].fields), "goto/16");
    EXPECT_EQ(insns[2].fields.offset, 2 + 200);
}

TEST(CodeEncoder, encode_whenSwitchKeysAreDense_usesPackedSwitch)
{
    const Code code = switch_code({{3, Label{0}}, {1, Label{1}}, {2, Label{0}}}, 2);

    CodeOut out = encode(code);
    raw::InsnFields fields = decode(out.insns)[0].fields;
    raw::InsnFields expected{.opcode = fields.opcode, .a = 0, .offset = 6};

    EXPECT_EQ(name_of(fields), "packed-switch");
    EXPECT_TRUE(fields == expected);
    // ident, size, first_key, then one target per key from 1 to 3, relative to the switch.
    EXPECT_EQ(units_from(out, 6), (Units{0x0100, 3, 1, 0, 5, 0, 4, 0, 4, 0}));
}

TEST(CodeEncoder, encode_whenSwitchKeysAreSpreadOut_usesSparseSwitchWithSortedKeys)
{
    const Code code = switch_code({{1, Label{0}}, {1000, Label{1}}, {-7, Label{0}}}, 2);

    CodeOut out = encode(code);
    raw::InsnFields fields = decode(out.insns)[0].fields;

    EXPECT_EQ(name_of(fields), "sparse-switch");
    EXPECT_EQ(fields.offset, 6);
    // ident, size, the keys -7, 1 and 1000, then their targets.
    EXPECT_EQ(units_from(out, 6),
              (Units{0x0200, 3, 0xFFF9, 0xFFFF, 1, 0, 1000, 0, 4, 0, 4, 0, 5, 0}));
}

TEST(CodeEncoder, encode_whenAPackedSwitchHasAGap_makesTheGapFallThrough)
{
    const Code code = switch_code({{1, Label{0}}, {3, Label{0}}}, 1);

    CodeOut out = encode(code);

    EXPECT_EQ(name_of(decode(out.insns)[0].fields), "packed-switch");
    // Key 2 has no case: its target is the instruction after the switch, 3 units on.
    EXPECT_EQ(units_from(out, 6), (Units{0x0100, 3, 1, 0, 4, 0, 3, 0, 4, 0}));
}

TEST(CodeEncoder, encode_whenTwoKeysAreFourApart_usesSparseSwitch)
{
    const Code code = switch_code({{1, Label{0}}, {4, Label{0}}}, 1);

    CodeOut out = encode(code);

    EXPECT_EQ(name_of(decode(out.insns)[0].fields), "sparse-switch");
    EXPECT_EQ(units_from(out, 6), (Units{0x0200, 2, 1, 0, 4, 0, 4, 0, 4, 0}));
}

TEST(CodeEncoder, encode_whenSwitchHasOneCase_usesPackedSwitch)
{
    const Code code = switch_code({{5, Label{0}}}, 1);

    CodeOut out = encode(code);

    EXPECT_EQ(name_of(decode(out.insns)[0].fields), "packed-switch");
    EXPECT_EQ(units_from(out, 6), (Units{0x0100, 1, 5, 0, 4, 0}));
}

TEST(CodeEncoder, encode_whenSwitchHasNoCases_usesAnEmptySparseSwitch)
{
    const Code code = switch_code({}, 0);

    CodeOut out = encode(code);
    raw::InsnFields fields = decode(out.insns)[0].fields;

    EXPECT_EQ(name_of(fields), "sparse-switch");
    EXPECT_EQ(fields.offset, 4);
    EXPECT_EQ(units_from(out, 4), (Units{0x0200, 0}));
}

TEST(CodeEncoder, encode_whenAPackedSwitchStartsAtANegativeKey_writesTheKeySignExtended)
{
    const Code code = switch_code({{0, Label{0}}, {-1, Label{0}}}, 1);

    CodeOut out = encode(code);

    EXPECT_EQ(units_from(out, 6), (Units{0x0100, 2, 0xFFFF, 0xFFFF, 4, 0, 4, 0}));
}

TEST(CodeEncoder, encode_whenSwitchKeysAreTheIntLimits_usesSparseSwitch)
{
    const Code code = switch_code({{kInt32Max, Label{0}}, {kInt32Min, Label{0}}}, 1);

    CodeOut out = encode(code);

    EXPECT_EQ(name_of(decode(out.insns)[0].fields), "sparse-switch");
    EXPECT_EQ(units_from(out, 6), (Units{0x0200, 2, 0x0000, 0x8000, 0xFFFF, 0x7FFF, 4, 0, 4, 0}));
}

TEST(CodeEncoder, encode_whenDenseKeysSpan65535Values_usesPackedSwitch)
{
    std::vector<Switch::Case> cases;
    for (int32_t key = 0; key < 65535; ++key)
        cases.push_back({key, Label{0}});

    CodeOut out = encode(switch_code(std::move(cases), 1));

    EXPECT_EQ(name_of(decode(out.insns)[0].fields), "packed-switch");
    EXPECT_EQ(out.insns[7], 0xFFFF);
    EXPECT_EQ(out.insns.size(), 6u + 4 + 2 * 65535);
}

TEST(CodeEncoder, encode_whenDenseKeysSpan65536Values_usesSparseSwitch)
{
    std::vector<Switch::Case> cases;
    for (int32_t key = 0; key < 65534; ++key)
        cases.push_back({key, Label{0}});
    cases.push_back({65535, Label{0}});

    CodeOut out = encode(switch_code(std::move(cases), 1));

    EXPECT_EQ(name_of(decode(out.insns)[0].fields), "sparse-switch");
    EXPECT_EQ(out.insns[7], 0xFFFF);
    EXPECT_EQ(out.insns.size(), 6u + 2 + 4 * 65535);
}

TEST(CodeEncoder, encode_whenSwitchIsNotTheFirstInstruction_writesTargetsRelativeToTheSwitch)
{
    const Code code = code_of({Insn{Nop{}}, Insn{Switch{0, {{1, Label{0}}, {9, Label{0}}}}},
                               Insn{ReturnVoid{}}, Label{0}, Insn{ReturnVoid{}}});

    CodeOut out = encode(code);
    Decoded insn = decode(out.insns)[1];

    EXPECT_EQ(insn.address, 1u);
    EXPECT_EQ(insn.fields.offset, 5);
    EXPECT_EQ(units_from(out, 6), (Units{0x0200, 2, 1, 0, 9, 0, 4, 0, 4, 0}));
}

TEST(CodeEncoder, encode_whenASwitchTargetIsBeforeTheSwitch_writesANegativeOffset)
{
    const Code code =
        code_of({Label{0}, Insn{Nop{}}, Insn{Switch{0, {{1, Label{0}}}}}, Insn{ReturnVoid{}}});

    CodeOut out = encode(code);

    EXPECT_EQ(units_from(out, 6), (Units{0x0100, 1, 1, 0, 0xFFFF, 0xFFFF}));
}

TEST(CodeEncoder, encode_whenTheCodeBeforeAPayloadHasAnOddSize_padsWithANop)
{
    const Code code = switch_code({{5, Label{0}}}, 1);

    CodeOut out = encode(code);

    EXPECT_EQ(out.insns[5], 0x0000);
    EXPECT_EQ(decode(out.insns)[0].fields.offset, 6);
}

TEST(CodeEncoder, encode_whenTheCodeBeforeAPayloadHasAnEvenSize_addsNoPadding)
{
    const Code code = switch_code({{5, Label{0}}, {6, Label{1}}}, 2);

    CodeOut out = encode(code);

    EXPECT_EQ(out.insns[6], raw::PACKED_SWITCH_PAYLOAD);
    EXPECT_EQ(decode(out.insns)[0].fields.offset, 6);
}

TEST(CodeEncoder, encode_whenInsnIsFillArrayData_writesTheRegisterAndThePayloadOffset)
{
    const Code code = code_of({Insn{FillArrayData{200, 1, {1, 2}}}, Insn{ReturnVoid{}}});

    raw::InsnFields fields = decode(encode(code).insns)[0].fields;
    raw::InsnFields expected{.opcode = fields.opcode, .a = 200, .offset = 4};

    EXPECT_EQ(name_of(fields), "fill-array-data");
    EXPECT_TRUE(fields == expected);
}

TEST(CodeEncoder, encode_whenArrayDataHasAnOddNumberOfBytes_padsTheLastUnitWithZero)
{
    const Code code = code_of({Insn{FillArrayData{0, 1, {1, 2, 3}}}, Insn{ReturnVoid{}}});

    // ident, element width, element count (2 units), then the bytes, low byte first.
    EXPECT_EQ(units_from(encode(code), 4), (Units{0x0300, 1, 3, 0, 0x0201, 0x0003}));
}

TEST(CodeEncoder, encode_whenArrayElementsAreTwoBytesWide_countsElementsNotBytes)
{
    const Code code =
        code_of({Insn{FillArrayData{0, 2, {0x34, 0x12, 0x78, 0x56}}}, Insn{ReturnVoid{}}});

    EXPECT_EQ(units_from(encode(code), 4), (Units{0x0300, 2, 2, 0, 0x1234, 0x5678}));
}

TEST(CodeEncoder, encode_whenArrayElementsAreFourBytesWide_writesEachAsTwoUnits)
{
    const Code code =
        code_of({Insn{FillArrayData{0, 4, {0x78, 0x56, 0x34, 0x12}}}, Insn{ReturnVoid{}}});

    EXPECT_EQ(units_from(encode(code), 4), (Units{0x0300, 4, 1, 0, 0x5678, 0x1234}));
}

TEST(CodeEncoder, encode_whenArrayElementsAreEightBytesWide_writesEachAsFourUnits)
{
    const Code code =
        code_of({Insn{FillArrayData{0, 8, {1, 2, 3, 4, 5, 6, 7, 8}}}, Insn{ReturnVoid{}}});

    EXPECT_EQ(units_from(encode(code), 4),
              (Units{0x0300, 8, 1, 0, 0x0201, 0x0403, 0x0605, 0x0807}));
}

TEST(CodeEncoder, encode_whenArrayDataIsEmpty_writesAPayloadWithNoElements)
{
    const Code code = code_of({Insn{FillArrayData{0, 1, {}}}, Insn{ReturnVoid{}}});

    EXPECT_EQ(units_from(encode(code), 4), (Units{0x0300, 1, 0, 0}));
}

TEST(CodeEncoder, encode_whenArrayDataHasMoreThan65535Elements_writesTheCountInTwoUnits)
{
    const Code code =
        code_of({Insn{FillArrayData{0, 1, std::vector<uint8_t>(65536, 0xAB)}}, Insn{ReturnVoid{}}});

    CodeOut out = encode(code);

    EXPECT_EQ(out.insns[6], 0x0000);
    EXPECT_EQ(out.insns[7], 0x0001);
    EXPECT_EQ(out.insns.size(), 4u + 4 + 32768);
}

TEST(CodeEncoder, encode_whenCodeHasTwoPayloads_startsEachAtAnEvenAddress)
{
    const Code code = code_of({Insn{FillArrayData{0, 1, {9}}}, Insn{FillArrayData{1, 1, {8}}},
                               Insn{ReturnVoid{}}, Insn{ReturnVoid{}}});

    CodeOut out = encode(code);
    std::vector<Decoded> insns = decode(out.insns);

    EXPECT_EQ(insns[0].fields.offset, 8);
    EXPECT_EQ(insns[1].fields.offset, 14 - 3);
    EXPECT_EQ(units_from(out, 8),
              (Units{0x0300, 1, 1, 0, 0x0009, 0x0000, 0x0300, 1, 1, 0, 0x0008}));
}

TEST(CodeEncoder, encode_whenCodeFillsAByteArrayAndALongArray_writesBothPayloadsAfterTheCode)
{
    const Code code =
        code_of({Insn{Const{0, 3}}, Insn{NewArray{1, 0, "[B"}},
                 Insn{FillArrayData{1, 1, {1, 2, 3}}}, Insn{NewArray{2, 0, "[J"}},
                 Insn{FillArrayData{2, 8, std::vector<uint8_t>(24, 0xAB)}}, Insn{ReturnVoid{}}});
    Units long_payload{0x0300, 8, 3, 0};
    long_payload.insert(long_payload.end(), 12, 0xABAB);

    CodeOut out = encode(code);
    std::vector<Decoded> insns = decode(out.insns);

    EXPECT_EQ(insns[2].address, 3u);
    EXPECT_EQ(insns[2].fields.offset, 12 - 3);
    EXPECT_EQ(insns[4].address, 8u);
    EXPECT_EQ(insns[4].fields.offset, 18 - 8);
    EXPECT_EQ(Units(out.insns.begin() + 12, out.insns.begin() + 18),
              (Units{0x0300, 1, 3, 0, 0x0201, 0x0003}));
    EXPECT_EQ(units_from(out, 18), long_payload);
}

TEST(CodeEncoder, encode_whenCodeHasNoTryRanges_emitsNoTriesAndNoHandlers)
{
    CodeOut out = encode(three_calls({}));

    EXPECT_TRUE(out.tries.empty());
    EXPECT_TRUE(out.handlers.empty());
}

TEST(CodeEncoder, encode_whenCodeHasOneTryRange_emitsOneTryWithItsHandler)
{
    const Code code =
        three_calls({TryRange{Label{1}, Label{2}, {Catch{"LE;", Label{4}}}, std::nullopt}});

    EXPECT_EQ(encoded_tries(code), (std::vector<Try>{{3, 3, caught({{"LE;", 10}})}}));
}

TEST(CodeEncoder, encode_whenCodeHasOneTryRange_writesTheHandlerListInTheFormatOfTheFile)
{
    const Code code =
        three_calls({TryRange{Label{1}, Label{2}, {Catch{"LE;", Label{4}}}, std::nullopt}});
    Pools pools = pools_of(code);

    CodeOut out = encode(code, pools);

    ASSERT_EQ(out.tries.size(), 1u);
    EXPECT_EQ(out.tries[0].handler_off, 1);
    // One handler; it has one catch: the type index, then the handler address.
    EXPECT_EQ(out.handlers,
              (std::vector<uint8_t>{1, 1, static_cast<uint8_t>(pools.type("LE;")), 10}));
}

TEST(CodeEncoder, encode_whenATryRangeHasOnlyACatchAll_writesAZeroSizeAndTheAddress)
{
    const Code code = three_calls({TryRange{Label{0}, Label{3}, {}, Label{4}}});

    CodeOut out = encode(code);

    EXPECT_EQ(out.handlers, (std::vector<uint8_t>{1, 0, 10}));
}

TEST(CodeEncoder, encode_whenATryRangeHasCatchesAndACatchAll_writesANegativeSize)
{
    const Code code =
        three_calls({TryRange{Label{0}, Label{3}, {Catch{"LE;", Label{4}}}, Label{5}}});
    Pools pools = pools_of(code);

    CodeOut out = encode(code, pools);

    // The size -1 is 0x7f as sleb128.
    EXPECT_EQ(out.handlers,
              (std::vector<uint8_t>{1, 0x7f, static_cast<uint8_t>(pools.type("LE;")), 10, 12}));
}

TEST(CodeEncoder, encode_whenATryRangeHasSeveralCatches_keepsTheirOrder)
{
    const Code code = three_calls({TryRange{
        Label{0}, Label{3}, {Catch{"LZ;", Label{4}}, Catch{"LA;", Label{5}}}, std::nullopt}});

    EXPECT_EQ(encoded_tries(code), (std::vector<Try>{{0, 9, caught({{"LZ;", 10}, {"LA;", 12}})}}));
}

TEST(CodeEncoder, encode_whenATryRangeListsACatchTypeTwice_keepsBoth)
{
    const Code code = three_calls({TryRange{
        Label{0}, Label{3}, {Catch{"LE;", Label{4}}, Catch{"LE;", Label{5}}}, std::nullopt}});

    EXPECT_EQ(encoded_tries(code), (std::vector<Try>{{0, 9, caught({{"LE;", 10}, {"LE;", 12}})}}));
}

TEST(CodeEncoder, encode_whenATryRangeStartsAndEndsAtTheSameLabel_emitsNoTry)
{
    const Code code =
        three_calls({TryRange{Label{1}, Label{1}, {Catch{"LE;", Label{4}}}, std::nullopt}});

    CodeOut out = encode(code);

    EXPECT_TRUE(out.tries.empty());
    EXPECT_TRUE(out.handlers.empty());
}

TEST(CodeEncoder, encode_whenATryRangeCoversNoInstruction_emitsNoTry)
{
    const Code code =
        code_of({Label{0}, Label{1}, Insn{ReturnVoid{}}, Label{2}, Insn{ReturnVoid{}}},
                {TryRange{Label{0}, Label{1}, {Catch{"LE;", Label{2}}}, std::nullopt}});

    CodeOut out = encode(code);

    EXPECT_TRUE(out.tries.empty());
    EXPECT_TRUE(out.handlers.empty());
}

TEST(CodeEncoder, encode_whenATryRangeHasNoHandler_emitsNoTry)
{
    const Code code = three_calls({TryRange{Label{0}, Label{3}, {}, std::nullopt}});

    CodeOut out = encode(code);

    EXPECT_TRUE(out.tries.empty());
    EXPECT_TRUE(out.handlers.empty());
}

TEST(CodeEncoder, encode_whenATryRangeEndsAtTheEndOfTheCode_coversTheLastInstruction)
{
    const Code code = code_of({Label{0}, Insn{Nop{}}, Insn{ReturnVoid{}}, Label{1}},
                              {TryRange{Label{0}, Label{1}, {}, Label{0}}});

    EXPECT_EQ(encoded_tries(code), (std::vector<Try>{{0, 2, caught({}, 0)}}));
}

TEST(CodeEncoder, encode_whenSeparateRangesHaveEqualHandlers_sharesOneHandler)
{
    const Code code =
        three_calls({TryRange{Label{0}, Label{1}, {Catch{"LE;", Label{4}}}, std::nullopt},
                     TryRange{Label{2}, Label{3}, {Catch{"LE;", Label{4}}}, std::nullopt}});

    CodeOut out = encode(code);

    ASSERT_EQ(out.tries.size(), 2u);
    EXPECT_EQ(out.tries[0].start, 0u);
    EXPECT_EQ(out.tries[1].start, 6u);
    EXPECT_EQ(out.tries[0].handler_off, out.tries[1].handler_off);
    EXPECT_EQ(out.handlers[0], 1);
    EXPECT_EQ(out.handlers.size(), 4u);
}

TEST(CodeEncoder, encode_whenSeparateRangesHaveDifferentHandlers_writesBothHandlers)
{
    const Code code =
        three_calls({TryRange{Label{0}, Label{1}, {Catch{"LE;", Label{4}}}, std::nullopt},
                     TryRange{Label{2}, Label{3}, {Catch{"LE;", Label{5}}}, std::nullopt}});

    CodeOut out = encode(code);

    ASSERT_EQ(out.tries.size(), 2u);
    EXPECT_EQ(out.handlers[0], 2);
    EXPECT_EQ(out.tries[0].handler_off, 1);
    EXPECT_EQ(out.tries[1].handler_off, 4);
}

TEST(CodeEncoder, encode_whenNeighbouringRangesHaveEqualHandlers_joinsThemIntoOneTry)
{
    const Code code =
        three_calls({TryRange{Label{0}, Label{1}, {Catch{"LE;", Label{4}}}, std::nullopt},
                     TryRange{Label{1}, Label{3}, {Catch{"LE;", Label{4}}}, std::nullopt}});

    EXPECT_EQ(encoded_tries(code), (std::vector<Try>{{0, 9, caught({{"LE;", 10}})}}));
}

TEST(CodeEncoder, encode_whenNeighbouringRangesHaveDifferentHandlers_keepsTwoTries)
{
    const Code code =
        three_calls({TryRange{Label{0}, Label{1}, {Catch{"LE;", Label{4}}}, std::nullopt},
                     TryRange{Label{1}, Label{3}, {Catch{"LE;", Label{5}}}, std::nullopt}});

    EXPECT_EQ(encoded_tries(code),
              (std::vector<Try>{{0, 3, caught({{"LE;", 10}})}, {3, 6, caught({{"LE;", 12}})}}));
}

TEST(CodeEncoder, encode_whenRangesAreListedOutOfAddressOrder_emitsTriesByAddress)
{
    const Code code =
        three_calls({TryRange{Label{2}, Label{3}, {Catch{"LB;", Label{5}}}, std::nullopt},
                     TryRange{Label{0}, Label{1}, {Catch{"LA;", Label{4}}}, std::nullopt}});

    EXPECT_EQ(encoded_tries(code),
              (std::vector<Try>{{0, 3, caught({{"LA;", 10}})}, {6, 3, caught({{"LB;", 12}})}}));
}

TEST(CodeEncoder, encode_whenATryRangeIsNestedInAnother_flattensThemWithTheFirstListedFirst)
{
    const Code code = three_calls({
        TryRange{Label{1}, Label{2}, {Catch{"Ljava/io/IOException;", Label{5}}}, std::nullopt},
        TryRange{Label{0}, Label{3}, {Catch{"Ljava/lang/Exception;", Label{4}}}, std::nullopt},
    });

    EXPECT_EQ(encoded_tries(code),
              (std::vector<Try>{
                  {0, 3, caught({{"Ljava/lang/Exception;", 10}})},
                  {3, 3, caught({{"Ljava/io/IOException;", 12}, {"Ljava/lang/Exception;", 10}})},
                  {6, 3, caught({{"Ljava/lang/Exception;", 10}})},
              }));
}

TEST(CodeEncoder, encode_whenATryRangeIsNestedInAnother_sharesTheHandlerOfTheOuterPieces)
{
    const Code code = three_calls({
        TryRange{Label{1}, Label{2}, {Catch{"Ljava/io/IOException;", Label{5}}}, std::nullopt},
        TryRange{Label{0}, Label{3}, {Catch{"Ljava/lang/Exception;", Label{4}}}, std::nullopt},
    });

    CodeOut out = encode(code);

    ASSERT_EQ(out.tries.size(), 3u);
    EXPECT_EQ(out.tries[0].handler_off, out.tries[2].handler_off);
    EXPECT_NE(out.tries[0].handler_off, out.tries[1].handler_off);
    EXPECT_EQ(out.handlers[0], 2);
}

TEST(CodeEncoder, encode_whenTheOuterRangeIsListedFirst_putsItsCatchesFirst)
{
    const Code code = three_calls({
        TryRange{Label{0}, Label{3}, {Catch{"LOuter;", Label{4}}}, std::nullopt},
        TryRange{Label{1}, Label{2}, {Catch{"LInner;", Label{5}}}, std::nullopt},
    });

    EXPECT_EQ(encoded_tries(code), (std::vector<Try>{
                                       {0, 3, caught({{"LOuter;", 10}})},
                                       {3, 3, caught({{"LOuter;", 10}, {"LInner;", 12}})},
                                       {6, 3, caught({{"LOuter;", 10}})},
                                   }));
}

TEST(CodeEncoder, encode_whenTryRangesOverlapPartly_splitsTheCodeAtEveryBoundary)
{
    const Code code =
        three_calls({TryRange{Label{0}, Label{2}, {Catch{"LA;", Label{4}}}, std::nullopt},
                     TryRange{Label{1}, Label{3}, {Catch{"LB;", Label{5}}}, std::nullopt}});

    EXPECT_EQ(encoded_tries(code), (std::vector<Try>{
                                       {0, 3, caught({{"LA;", 10}})},
                                       {3, 3, caught({{"LA;", 10}, {"LB;", 12}})},
                                       {6, 3, caught({{"LB;", 12}})},
                                   }));
}

TEST(CodeEncoder, encode_whenTheFirstListedRangeHasACatchAll_dropsTheCatchesOfLaterRanges)
{
    const Code code = three_calls({
        TryRange{Label{1}, Label{2}, {}, Label{5}},
        TryRange{Label{0}, Label{3}, {Catch{"LE;", Label{4}}}, std::nullopt},
    });

    EXPECT_EQ(encoded_tries(code), (std::vector<Try>{
                                       {0, 3, caught({{"LE;", 10}})},
                                       {3, 3, caught({}, 12)},
                                       {6, 3, caught({{"LE;", 10}})},
                                   }));
}

TEST(CodeEncoder, encode_whenALaterRangeHasTheCatchAll_addsItAfterTheEarlierCatches)
{
    const Code code = three_calls({
        TryRange{Label{1}, Label{2}, {Catch{"LE;", Label{5}}}, std::nullopt},
        TryRange{Label{0}, Label{3}, {}, Label{4}},
    });

    EXPECT_EQ(encoded_tries(code), (std::vector<Try>{
                                       {0, 3, caught({}, 10)},
                                       {3, 3, caught({{"LE;", 12}}, 10)},
                                       {6, 3, caught({}, 10)},
                                   }));
}

TEST(CodeEncoder, encode_whenATryRangeIs65535UnitsLong_emitsOneTry)
{
    std::vector<Item> items{Label{0}};
    items.insert(items.end(), 65535, Item{Insn{Nop{}}});
    items.push_back(Label{1});
    items.push_back(Insn{ReturnVoid{}});
    const Code code = code_of(std::move(items), {TryRange{Label{0}, Label{1}, {}, Label{1}}});

    EXPECT_EQ(encoded_tries(code), (std::vector<Try>{{0, 65535, caught({}, 65535)}}));
}

TEST(CodeEncoder, encode_whenATryRangeIs65536UnitsLong_cutsItIntoTwoTries)
{
    std::vector<Item> items{Label{0}};
    items.insert(items.end(), 65536, Item{Insn{Nop{}}});
    items.push_back(Label{1});
    items.push_back(Insn{ReturnVoid{}});
    const Code code = code_of(std::move(items), {TryRange{Label{0}, Label{1}, {}, Label{1}}});

    EXPECT_EQ(encoded_tries(code),
              (std::vector<Try>{{0, 65535, caught({}, 65536)}, {65535, 1, caught({}, 65536)}}));
}

TEST(CodeEncoder, encode_whenTheLimitOfATryFallsInsideAnInstruction_cutsBeforeThatInstruction)
{
    // Instructions start at 1 + 5k: 65535 is inside the one at 65531, 131066 starts one.
    const Code code = long_try_of_wide_constants(30000);

    EXPECT_EQ(encoded_tries(code), (std::vector<Try>{
                                       {0, 65531, caught({}, 150001)},
                                       {65531, 65535, caught({}, 150001)},
                                       {131066, 18935, caught({}, 150001)},
                                   }));
}

TEST(CodeEncoder, encode_whenALongTryRangeIsCut_startsEveryTryAtAnInstruction)
{
    const Code code = long_try_of_wide_constants(30000);

    CodeOut out = encode(code);
    std::set<uint32_t> starts;
    for (const Decoded &insn : decode(out.insns))
        starts.insert(insn.address);

    ASSERT_EQ(out.tries.size(), 3u);
    uint32_t next = 0;
    for (const CodeOut::Try &t : out.tries) {
        EXPECT_TRUE(starts.contains(t.start))
            << "a try starts inside an instruction at " << t.start;
        EXPECT_EQ(t.start, next);
        next = t.start + t.count;
    }
    EXPECT_EQ(next, 150001u);
}

TEST(CodeEncoder, encode_whenALongTryRangeHoldsTwoUnitInstructions_cutsAtAnEvenAddress)
{
    std::vector<Item> items{Label{0}};
    items.insert(items.end(), 40000, Item{Insn{Const{0, 100}}});
    items.push_back(Label{1});
    items.push_back(Insn{ReturnVoid{}});
    const Code code =
        code_of(std::move(items), {TryRange{Label{0}, Label{1}, {Catch{"LE;", Label{1}}}, {}}});

    EXPECT_EQ(encoded_tries(code), (std::vector<Try>{{0, 65534, caught({{"LE;", 80000}})},
                                                     {65534, 14466, caught({{"LE;", 80000}})}}));
}

TEST(CodeEncoder, encode_whenASecondHandlerStartsPast65535Bytes_failsWithTooLarge)
{
    std::vector<Catch> many(40000, Catch{"LE;", Label{4}});
    const Code code =
        three_calls({TryRange{Label{0}, Label{1}, std::move(many), std::nullopt},
                     TryRange{Label{2}, Label{3}, {Catch{"LE;", Label{5}}}, std::nullopt}});

    Error error = encode_error(code);

    EXPECT_EQ(error.kind, Error::Kind::TooLarge);
    EXPECT_EQ(error.message, "LT;->m()V: too many exception handlers");
}

TEST(CodeEncoder, encode_whenDebugInfoIsOff_emitsNoDebugInfo)
{
    Code code = code_of({LineNumber{1}, Insn{ReturnVoid{}}});
    code.parameter_names = {std::string("argument")};

    EXPECT_TRUE(encode(code, false).debug.empty());
}

TEST(CodeEncoder, encode_whenCodeHasNoMarkerAndNoParameterName_emitsNoDebugInfo)
{
    const Code code = code_of({Label{0}, Insn{ReturnVoid{}}});

    EXPECT_TRUE(encode(code, true).debug.empty());
}

TEST(CodeEncoder, encode_whenCodeHasOnlyParameterNames_emitsAHeaderAndNoOpcodes)
{
    Code code = code_of({Insn{ReturnVoid{}}});
    code.parameter_names = {std::string("first"), std::nullopt, std::string("third")};

    CodeOut out = encode(code);

    // line_start 0, 3 parameters as index + 1 ("first" is 0, "third" is 1), end of sequence.
    EXPECT_EQ(out.debug, (std::vector<uint8_t>{0, 3, 1, 0, 2, raw::DBG_END_SEQUENCE}));
}

TEST(CodeEncoder, encode_whenParametersHaveNames_readsBackAsTheirStringIndices)
{
    Code code = code_of({Insn{ConstString{0, "a string before"}}, Insn{ReturnVoid{}}});
    code.parameter_names = {std::nullopt, std::string("named")};
    Pools pools = pools_of(code);

    raw::DebugInfoItem item = debug_item(encode(code, pools));

    EXPECT_EQ(item.parameter_names, (std::vector<uint32_t>{raw::NO_INDEX, pools.string("named")}));
}

TEST(CodeEncoder, encode_whenCodeHasLineNumbers_startsTheLineRegisterAtTheFirstOne)
{
    const Code code =
        code_of({Insn{Nop{}}, LineNumber{42}, Insn{Nop{}}, LineNumber{50}, Insn{ReturnVoid{}}});

    EXPECT_EQ(debug_item(encode(code)).line_start, 42u);
}

TEST(CodeEncoder, encode_whenCodeHasMarkersButNoLineNumber_startsTheLineRegisterAtZero)
{
    const Code code = code_of({PrologueEnd{}, Insn{ReturnVoid{}}});

    EXPECT_EQ(debug_item(encode(code)).line_start, 0u);
}

TEST(CodeEncoder, encode_whenDebugInfoIsEmitted_endsItWithEndSequence)
{
    const Code code = code_of({LineNumber{1}, Insn{ReturnVoid{}}});

    CodeOut out = encode(code);

    // line_start 1, no parameters, the special opcode for line +0 pc +0, end of sequence.
    EXPECT_EQ(out.debug, (std::vector<uint8_t>{1, 0, 0x0e, raw::DBG_END_SEQUENCE}));
}

TEST(CodeEncoder, encode_whenTheFirstLineIsAfterAnInstruction_advancesTheAddressInItsOpcode)
{
    const Code code = code_of({Insn{Nop{}}, LineNumber{42}, Insn{ReturnVoid{}}});

    EXPECT_EQ(encoded_debug_ops(code), (Names{"line +0 pc +1"}));
}

TEST(CodeEncoder, encode_whenTheLineAdvancesByUpToTen_usesOneSpecialOpcode)
{
    const Code code = code_of({LineNumber{10}, Insn{Nop{}}, LineNumber{20}, Insn{ReturnVoid{}}});

    EXPECT_EQ(encoded_debug_ops(code), (Names{"line +0 pc +0", "line +10 pc +1"}));
}

TEST(CodeEncoder, encode_whenTheLineAdvancesByEleven_usesAdvanceLine)
{
    const Code code = code_of({LineNumber{10}, Insn{Nop{}}, LineNumber{21}, Insn{ReturnVoid{}}});

    EXPECT_EQ(encoded_debug_ops(code),
              (Names{"line +0 pc +0", "advance_line 11", "line +0 pc +1"}));
}

TEST(CodeEncoder, encode_whenTheLineGoesBackByUpToFour_usesOneSpecialOpcode)
{
    const Code code = code_of({LineNumber{10}, Insn{Nop{}}, LineNumber{6}, Insn{ReturnVoid{}}});

    EXPECT_EQ(encoded_debug_ops(code), (Names{"line +0 pc +0", "line -4 pc +1"}));
}

TEST(CodeEncoder, encode_whenTheLineGoesBackByFive_usesAdvanceLineWithANegativeDelta)
{
    const Code code = code_of({LineNumber{10}, Insn{Nop{}}, LineNumber{5}, Insn{ReturnVoid{}}});

    EXPECT_EQ(encoded_debug_ops(code),
              (Names{"line +0 pc +0", "advance_line -5", "line +0 pc +1"}));
}

TEST(CodeEncoder, encode_whenTheLineGoesFarBack_writesTheDeltaAsSleb128)
{
    const Code code = code_of({LineNumber{200}, Insn{Nop{}}, LineNumber{3}, Insn{ReturnVoid{}}});

    CodeOut out = encode(code);

    // line_start 200 as uleb128; -197 as sleb128 is BB 7E; 0x1d is line +0 pc +1.
    EXPECT_EQ(out.debug, (std::vector<uint8_t>{0xC8, 0x01, 0, 0x0e, raw::DBG_ADVANCE_LINE, 0xBB,
                                               0x7E, 0x1d, raw::DBG_END_SEQUENCE}));
}

TEST(CodeEncoder, encode_whenAddressAndLineFitTheLastSpecialOpcode_usesIt)
{
    CodeOut out = encode(two_lines_apart(16, 1));

    EXPECT_EQ(out.debug, (std::vector<uint8_t>{100, 0, 0x0e, 0xFF, raw::DBG_END_SEQUENCE}));
}

TEST(CodeEncoder, encode_whenAddressAndLineAreOnePastTheLastSpecialOpcode_usesAdvancePc)
{
    EXPECT_EQ(encoded_debug_ops(two_lines_apart(16, 2)),
              (Names{"line +0 pc +0", "advance_pc 16", "line +2 pc +0"}));
}

TEST(CodeEncoder, encode_whenTheAddressAdvancesBySeventeen_usesAdvancePc)
{
    EXPECT_EQ(encoded_debug_ops(two_lines_apart(17, 0)),
              (Names{"line +0 pc +0", "advance_pc 17", "line +0 pc +0"}));
}

TEST(CodeEncoder, encode_whenLineAndAddressBothAdvanceFar_usesAdvanceLineThenAdvancePc)
{
    EXPECT_EQ(encoded_debug_ops(two_lines_apart(20, 99)),
              (Names{"line +0 pc +0", "advance_line 99", "advance_pc 20", "line +0 pc +0"}));
}

TEST(CodeEncoder, encode_whenALocalStarts_writesItsRegisterNameAndType)
{
    const Code code =
        code_of({LocalStart{3, LocalVariable{"x", "I", std::nullopt}}, Insn{ReturnVoid{}}});

    EXPECT_EQ(encoded_debug_ops(code), (Names{"start_local v3 x I"}));
}

TEST(CodeEncoder, encode_whenALocalHasASignature_usesStartLocalExtended)
{
    const Code code =
        code_of({LocalStart{3, LocalVariable{"list", "Ljava/util/List;", "Ljava/util/List<TT;>;"}},
                 Insn{ReturnVoid{}}});

    EXPECT_EQ(encoded_debug_ops(code),
              (Names{"start_local_extended v3 list Ljava/util/List; Ljava/util/List<TT;>;"}));
}

TEST(CodeEncoder, encode_whenALocalHasNoNameAndNoType_writesNoIndexForBoth)
{
    const Code code =
        code_of({LocalStart{3, LocalVariable{std::nullopt, std::nullopt, std::nullopt}},
                 Insn{ReturnVoid{}}});

    CodeOut out = encode(code);

    EXPECT_EQ(out.debug,
              (std::vector<uint8_t>{0, 0, raw::DBG_START_LOCAL, 3, 0, 0, raw::DBG_END_SEQUENCE}));
}

TEST(CodeEncoder, encode_whenALocalEnds_writesEndLocalWithItsRegister)
{
    const Code code = code_of({LocalEnd{300}, Insn{ReturnVoid{}}});

    EXPECT_EQ(encoded_debug_ops(code), (Names{"end_local v300"}));
}

TEST(CodeEncoder, encode_whenALocalRestarts_writesRestartLocalWithItsRegister)
{
    const Code code = code_of({LocalRestart{300}, Insn{ReturnVoid{}}});

    EXPECT_EQ(encoded_debug_ops(code), (Names{"restart_local v300"}));
}

TEST(CodeEncoder, encode_whenThePrologueEnds_writesSetPrologueEnd)
{
    const Code code = code_of({PrologueEnd{}, Insn{ReturnVoid{}}});

    EXPECT_EQ(encoded_debug_ops(code), (Names{"prologue_end"}));
}

TEST(CodeEncoder, encode_whenTheEpilogueBegins_writesSetEpilogueBegin)
{
    const Code code = code_of({EpilogueBegin{}, Insn{ReturnVoid{}}});

    EXPECT_EQ(encoded_debug_ops(code), (Names{"epilogue_begin"}));
}

TEST(CodeEncoder, encode_whenTheSourceFileChanges_writesSetFileWithTheName)
{
    const Code code = code_of({SetSourceFile{"Other.java"}, Insn{ReturnVoid{}}});

    EXPECT_EQ(encoded_debug_ops(code), (Names{"set_file Other.java"}));
}

TEST(CodeEncoder, encode_whenTheSourceFileIsUnknown_writesSetFileWithNoIndex)
{
    const Code code = code_of({SetSourceFile{std::nullopt}, Insn{ReturnVoid{}}});

    EXPECT_EQ(encoded_debug_ops(code), (Names{"set_file -"}));
}

TEST(CodeEncoder, encode_whenAMarkerFollowsInstructions_advancesTheAddressToItFirst)
{
    const Code code =
        code_of({Insn{Const{0, 100}}, Insn{Nop{}}, PrologueEnd{}, Insn{ReturnVoid{}}});

    EXPECT_EQ(encoded_debug_ops(code), (Names{"advance_pc 3", "prologue_end"}));
}

TEST(CodeEncoder, encode_whenTwoMarkersAreAtTheSameAddress_advancesTheAddressOnce)
{
    const Code code = code_of({Insn{Nop{}}, LocalEnd{0}, LocalRestart{0}, Insn{ReturnVoid{}}});

    EXPECT_EQ(encoded_debug_ops(code), (Names{"advance_pc 1", "end_local v0", "restart_local v0"}));
}

TEST(CodeEncoder, encode_whenAMarkerFollowsTheLastInstruction_placesItAtTheEndOfTheCode)
{
    const Code code = code_of({Insn{Nop{}}, Insn{ReturnVoid{}}, LocalEnd{0}});

    EXPECT_EQ(encoded_debug_ops(code), (Names{"advance_pc 2", "end_local v0"}));
}

TEST(CodeEncoder, encode_whenALineFollowsABranchThatGrew_usesTheFinalAddress)
{
    std::vector<Item> items{Insn{Goto{Label{0}}}, LineNumber{7}};
    items.insert(items.end(), 200, Item{Insn{Nop{}}});
    items.push_back(Label{0});
    items.push_back(Insn{ReturnVoid{}});

    EXPECT_EQ(encoded_debug_ops(code_of(std::move(items))), (Names{"line +0 pc +2"}));
}

TEST(CodeEncoder, encode_whenCodeMixesEveryMarker_emitsThemInItemOrder)
{
    Code code = code_of({
        LineNumber{10},
        PrologueEnd{},
        LineNumber{11},
        Insn{Const{0, 1}},
        LocalStart{0, LocalVariable{"x", "I", std::nullopt}},
        LineNumber{200},
        Insn{Const{0, 2}},
        LocalEnd{0},
        SetSourceFile{"Other.java"},
        LineNumber{3},
        LocalRestart{0},
        EpilogueBegin{},
        LineNumber{4},
        Insn{ReturnVoid{}},
        LocalStart{0, LocalVariable{"list", "Ljava/util/List;", "Ljava/util/List<TT;>;"}},
    });
    code.parameter_names = {std::string("count")};
    Pools pools = pools_of(code);

    CodeOut out = encode(code, pools);

    EXPECT_EQ(debug_item(out).line_start, 10u);
    EXPECT_EQ(debug_item(out).parameter_names, (std::vector<uint32_t>{pools.string("count")}));
    EXPECT_EQ(debug_ops(out, pools),
              (Names{
                  "line +0 pc +0",
                  "prologue_end",
                  "line +1 pc +0",
                  "advance_pc 1",
                  "start_local v0 x I",
                  "advance_line 189",
                  "line +0 pc +0",
                  "advance_pc 1",
                  "end_local v0",
                  "set_file Other.java",
                  "advance_line -197",
                  "line +0 pc +0",
                  "restart_local v0",
                  "epilogue_begin",
                  "line +1 pc +0",
                  "advance_pc 1",
                  "start_local_extended v0 list Ljava/util/List; Ljava/util/List<TT;>;",
              }));
}

TEST(CodeEncoder, encode_whenDebugInfoIsOff_stillEncodesTheInstructions)
{
    const Code code = code_of({LineNumber{10}, Insn{Const{0, 1}}, LocalEnd{0}, Insn{ReturnVoid{}}});

    EXPECT_EQ(encode(code, false).insns, encode(code, true).insns);
}

} // namespace
} // namespace dexsplit::model::detail
