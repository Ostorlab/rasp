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

} // namespace
} // namespace dexsplit::model::detail
