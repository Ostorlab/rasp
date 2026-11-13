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

} // namespace
} // namespace dexsplit::model::detail
