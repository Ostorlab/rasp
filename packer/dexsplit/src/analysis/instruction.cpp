#include "instruction.hpp"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <format>
#include <type_traits>

#include "common/budget.hpp"
#include "raw/opcodes.hpp"

namespace dexsplit {

std::string_view opcode_name(uint8_t opcode) { return raw::opcode_info(opcode).name; }

std::optional<InvokeKind> invoke_kind_from_opcode(uint8_t opcode) {
  switch (opcode) {
    case 0x6e:
    case 0x74:
      return InvokeKind::Virtual;
    case 0x6f:
    case 0x75:
      return InvokeKind::Super;
    case 0x70:
    case 0x76:
      return InvokeKind::Direct;
    case 0x71:
    case 0x77:
      return InvokeKind::Static;
    case 0x72:
    case 0x78:
      return InvokeKind::Interface;
    case 0xfa:
    case 0xfb:
      return InvokeKind::Polymorphic;
    case 0xfc:
    case 0xfd:
      return InvokeKind::Custom;
    default:
      return std::nullopt;
  }
}

std::optional<TypeRefKind> type_ref_kind_from_opcode(uint8_t opcode) {
  switch (opcode) {
    case 0x1c:
      return TypeRefKind::ConstClass;
    case 0x1f:
      return TypeRefKind::CheckCast;
    case 0x20:
      return TypeRefKind::InstanceOf;
    case 0x22:
      return TypeRefKind::NewInstance;
    case 0x23:
      return TypeRefKind::NewArray;
    case 0x24:
    case 0x25:
      return TypeRefKind::FilledNewArray;
    default:
      return std::nullopt;
  }
}

namespace {

budget::String join_regs(std::span<const uint16_t> regs) {
  budget::String out = "{";
  for (std::size_t j = 0; j < regs.size(); ++j) {
    dexsplit::budget::visit();
    if (j) {
      out += ", ";
    }
    out += budget::format("v{}", regs[j]);
  }
  out += '}';
  return out;
}

budget::String operands_of(const Instruction& insn) {
  return std::visit(
      [](const auto& i) -> budget::String {
        using T = std::decay_t<decltype(i)>;
        if constexpr (std::is_same_v<T, NopInstruction>) {
          return "";
        } else if constexpr (std::is_same_v<T, GotoInstruction>) {
          return budget::format("{:+d}", i.branch_offset);
        } else if constexpr (std::is_same_v<T, IfInstruction>) {
          return budget::format("v{}, v{}, {:+d}", i.reg_a, i.reg_b, i.branch_offset);
        } else if constexpr (std::is_same_v<T, IfZeroInstruction>) {
          return budget::format("v{}, {:+d}", i.reg, i.branch_offset);
        } else if constexpr (std::is_same_v<T, SwitchInstruction> || std::is_same_v<T, FillArrayInstruction>) {
          return budget::format("v{}, {:+d}", i.reg, i.payload_offset);
        } else if constexpr (std::is_same_v<T, ReturnInstruction>) {
          return i.reg ? budget::format("v{}", *i.reg) : budget::String{};
        } else if constexpr (std::is_same_v<T, ThrowInstruction> || std::is_same_v<T, MonitorInstruction>) {
          return budget::format("v{}", i.reg);
        } else if constexpr (std::is_same_v<T, MoveInstruction>) {
          // move-result* / move-exception (0x0a-0x0d) have no explicit source.
          if (i.base.opcode >= 0x0a && i.base.opcode <= 0x0d) {
            return budget::format("v{}", i.dest);
          }
          return budget::format("v{}, v{}", i.dest, i.src);
        } else if constexpr (std::is_same_v<T, ConstInstruction>) {
          return budget::format("v{}, #{}", i.dest, i.value);
        } else if constexpr (std::is_same_v<T, ConstStringInstruction>) {
          return budget::format("v{}, string@{}", i.dest, i.string_index);
        } else if constexpr (std::is_same_v<T, ConstClassInstruction>) {
          return budget::format("v{}, type@{}", i.dest, i.type_index);
        } else if constexpr (std::is_same_v<T, ConstHandleInstruction>) {
          return budget::format("v{}, idx@{}", i.dest, i.index);
        } else if constexpr (std::is_same_v<T, TypeInstruction>) {
          budget::String out = budget::format("v{}, type@{}", i.dest, i.type_index);
          if (i.src) {
            out += budget::format(", v{}", *i.src);
          }
          return out;
        } else if constexpr (std::is_same_v<T, FilledNewArrayInstruction>) {
          return budget::format("{} type@{}", join_regs(i.arg_regs), i.type_index);
        } else if constexpr (std::is_same_v<T, CompareInstruction> || std::is_same_v<T, BinaryOpInstruction>) {
          return budget::format("v{}, v{}, v{}", i.dest, i.src_a, i.src_b);
        } else if constexpr (std::is_same_v<T, ArrayOpInstruction>) {
          return budget::format("v{}, v{}[v{}]", i.value_reg, i.array_reg, i.index_reg);
        } else if constexpr (std::is_same_v<T, FieldInstruction>) {
          if (i.object_reg) {
            return budget::format("v{}, v{}.field@{}", i.value_reg, *i.object_reg, i.field_index);
          }
          return budget::format("v{}, field@{}", i.value_reg, i.field_index);
        } else if constexpr (std::is_same_v<T, InvokeInstruction>) {
          return budget::format("method@{} {}", i.method_index, join_regs(i.arg_regs));
        } else if constexpr (std::is_same_v<T, InvokeCustomInstruction>) {
          return budget::format("site@{} {}", i.call_site_index, join_regs(i.arg_regs));
        } else if constexpr (std::is_same_v<T, UnaryOpInstruction>) {
          return budget::format("v{}, v{}", i.dest, i.src);
        } else if constexpr (std::is_same_v<T, BinaryLitInstruction>) {
          return budget::format("v{}, v{}, #{}", i.dest, i.src, i.literal);
        }
        return "";
      },
      insn);
}

}  // namespace

budget::String to_string(const Instruction& insn) {
  budget::String ops = operands_of(insn);
  std::string_view name = opcode_name(base_of(insn).opcode);
  if (ops.empty()) {
    return budget::String(name);
  }
  return budget::format("{} {}", name, ops);
}

// Returns the OperandWidth for a 23x / 12x binary opcode (0x90–0xcf).
static OperandWidth binary_op_width(uint8_t op) {
  if (op >= 0x90 && op <= 0xaf) {
    if (op >= 0x9b && op <= 0xa5) {
      return OperandWidth::Pair;
    }
    if (op >= 0xab && op <= 0xaf) {
      return OperandWidth::Pair;
    }
    return OperandWidth::Single;
  }
  if (op >= 0xb0 && op <= 0xcf) {
    uint8_t off = static_cast<uint8_t>(op - 0xb0);
    if (off >= 0x0b && off <= 0x15) {
      return OperandWidth::Pair;
    }
    if (off >= 0x1b && off <= 0x1f) {
      return OperandWidth::Pair;
    }
    return OperandWidth::Single;
  }
  return OperandWidth::Single;
}

// Decode format 35c argument registers.
// count = (unit0 >> 12) & 0xf, G = (unit0 >> 8) & 0xf, C/D/E/F packed in unit2.
static budget::Vector<uint16_t> decode_35c_regs(uint32_t unit0, uint32_t unit2) {
  uint8_t count = static_cast<uint8_t>((unit0 >> 12U) & 0xfU);
  uint8_t reg_g = static_cast<uint8_t>((unit0 >> 8U) & 0xfU);

  budget::Vector<uint16_t> regs;
  regs.reserve(count);

  const uint8_t packed[5] = {
      static_cast<uint8_t>(unit2 & 0xfU),
      static_cast<uint8_t>((unit2 >> 4U) & 0xfU),
      static_cast<uint8_t>((unit2 >> 8U) & 0xfU),
      static_cast<uint8_t>((unit2 >> 12U) & 0xfU),
      reg_g,
  };
  for (uint8_t i = 0; i < count && i < 5; ++i) {
    dexsplit::budget::visit();
    regs.push_back(packed[i]);
  }

  return regs;
}

// Decode format 3rc argument registers. count = AA (unit0 >> 8), first_reg = unit2.
static budget::Vector<uint16_t> decode_3rc_regs(uint16_t unit0, uint16_t unit2) {
  uint8_t count = static_cast<uint8_t>(unit0 >> 8U);
  uint16_t first_reg = unit2;

  budget::Vector<uint16_t> regs;
  regs.reserve(count);
  for (uint8_t i = 0; i < count; ++i) {
    dexsplit::budget::visit();
    regs.push_back(static_cast<uint16_t>(first_reg + i));
  }

  return regs;
}

// Code units to skip for the payload pseudo-instruction at @p pos: its declared
// size (1 if the header is cut off), never past the end of @p insns.
static uint32_t payload_size(std::span<const uint16_t> insns, uint32_t pos) {
  uint64_t units = raw::payload_units(insns, pos).value_or(1);
  return static_cast<uint32_t>(std::min<uint64_t>(units, insns.size() - pos));
}

static int32_t sex8(uint8_t v) { return static_cast<int32_t>(static_cast<int8_t>(v)); }
static int32_t sex16(uint16_t v) { return static_cast<int32_t>(static_cast<int16_t>(v)); }
static int32_t sex4(uint8_t v) { return (v & 0x8U) ? static_cast<int32_t>(v | 0xfffffff0u) : v; }

// Read a signed 32-bit value from two consecutive code units (little-endian within each).
static int32_t read_s32(std::span<const uint16_t> insns, uint32_t pos) {
  uint32_t lo = insns[pos];
  uint32_t hi = insns[pos + 1];
  return static_cast<int32_t>(lo | (hi << 16U));
}

// Decode the packed/sparse switch payload pointed to by `payload_offset` (in
// code units, relative to the switch instruction at `insn_off`).  On any
// bounds-check failure or sentinel mismatch, leaves `sw.cases` empty.
static void decode_switch_payload(std::span<const uint16_t> insns, uint32_t insn_off, int32_t payload_offset,
                                  SwitchInstruction& sw) {
  int64_t pay64 = static_cast<int64_t>(insn_off) + static_cast<int64_t>(payload_offset);
  if (pay64 < 0 || pay64 + 2 > static_cast<int64_t>(insns.size())) {
    return;
  }
  uint32_t p = static_cast<uint32_t>(pay64);
  uint16_t ident = insns[p];

  if (sw.is_packed) {
    if (ident != 0x0100) {
      return;
    }
    if (static_cast<uint64_t>(p) + 4 > insns.size()) {
      return;
    }
    uint16_t size = insns[p + 1];
    int32_t first_key = read_s32(insns, p + 2);
    if (static_cast<uint64_t>(p) + 4 + static_cast<uint64_t>(size) * 2 > insns.size()) {
      return;
    }
    sw.cases.reserve(size);
    for (uint32_t i = 0; i < size; ++i) {
      dexsplit::budget::visit();
      int32_t target = read_s32(insns, p + 4 + 2 * i);
      sw.cases.push_back({first_key + static_cast<int32_t>(i), target});
    }
  } else {
    if (ident != 0x0200) {
      return;
    }
    if (static_cast<uint64_t>(p) + 2 > insns.size()) {
      return;
    }
    uint16_t size = insns[p + 1];
    if (static_cast<uint64_t>(p) + 2 + static_cast<uint64_t>(size) * 4 > insns.size()) {
      return;
    }
    sw.cases.resize(size);
    for (uint32_t i = 0; i < size; ++i) {
      dexsplit::budget::visit();
      sw.cases[i].key = read_s32(insns, p + 2 + 2 * i);
    }
    for (uint32_t i = 0; i < size; ++i) {
      dexsplit::budget::visit();
      sw.cases[i].target = read_s32(insns, p + 2 + 2 * size + 2 * i);
    }
  }
}

bool is_terminator(const Instruction& insn) {
  return std::visit(
      [](const auto& i) -> bool {
        using T = std::decay_t<decltype(i)>;
        if constexpr (std::is_same_v<T, GotoInstruction> || std::is_same_v<T, IfInstruction> ||
                      std::is_same_v<T, IfZeroInstruction> || std::is_same_v<T, SwitchInstruction> ||
                      std::is_same_v<T, ReturnInstruction> || std::is_same_v<T, ThrowInstruction> ||
                      std::is_same_v<T, MonitorInstruction>) {
          return true;
        }
        return false;
      },
      insn);
}

budget::Vector<Instruction> decode_instructions(std::span<const uint16_t> insns) {
  budget::Vector<Instruction> result;
  uint32_t pos = 0;

  while (pos < static_cast<uint32_t>(insns.size())) {
    dexsplit::budget::visit();
    uint16_t unit0 = insns[pos];
    uint8_t op = static_cast<uint8_t>(unit0 & 0xffU);
    uint8_t hi = static_cast<uint8_t>(unit0 >> 8U);

    // Payload pseudo-instructions: nop (op==0) with non-zero high byte
    if (op == 0x00 && hi != 0) {
      pos += payload_size(insns, pos);
      continue;
    }

    uint8_t sz = raw::opcode_info(op).units;

    // Safe read of additional code units
    uint16_t unit1 = (sz > 1 && pos + 1 < insns.size()) ? insns[pos + 1] : 0;
    uint16_t unit2 = (sz > 2 && pos + 2 < insns.size()) ? insns[pos + 2] : 0;
    uint16_t unit3 = (sz > 3 && pos + 3 < insns.size()) ? insns[pos + 3] : 0;
    uint16_t unit4 = (sz > 4 && pos + 4 < insns.size()) ? insns[pos + 4] : 0;

    InstructionBase base{pos, op, sz};

    if (op == 0x00) {
      result.push_back(NopInstruction{base});
    } else if (op == 0x01 || op == 0x04 || op == 0x07) {
      // format 12x: B|A op → dest=A, src=B
      uint8_t dest = hi & 0x0fU;
      uint8_t src = (static_cast<uint32_t>(hi) >> 4U) & 0x0fU;
      OperandWidth width = (op == 0x04) ? OperandWidth::Pair : OperandWidth::Single;
      result.push_back(MoveInstruction{base, dest, src, width});
    } else if (op == 0x02 || op == 0x05 || op == 0x08) {
      // format 22x: AA op BBBB → dest=AA, src=BBBB
      OperandWidth width = (op == 0x05) ? OperandWidth::Pair : OperandWidth::Single;
      result.push_back(MoveInstruction{base, hi, unit1, width});
    } else if (op == 0x03 || op == 0x06 || op == 0x09) {
      // format 32x: 00 op AAAA BBBB → dest=unit1, src=unit2
      OperandWidth width = (op == 0x06) ? OperandWidth::Pair : OperandWidth::Single;
      result.push_back(MoveInstruction{base, unit1, unit2, width});
    } else if (op >= 0x0a && op <= 0x0d) {
      // move-result / move-result-wide / move-result-object / move-exception
      // format 11x: AA op → dest=AA, src=0 (implicit)
      OperandWidth width = (op == 0x0b) ? OperandWidth::Pair : OperandWidth::Single;
      result.push_back(MoveInstruction{base, hi, 0, width});
    } else if (op == 0x0e) {
      result.push_back(ReturnInstruction{base, std::nullopt, OperandWidth::Single});
    } else if (op >= 0x0f && op <= 0x11) {
      // format 11x: AA op → reg=AA
      OperandWidth width = (op == 0x10) ? OperandWidth::Pair : OperandWidth::Single;
      result.push_back(ReturnInstruction{base, hi, width});
    } else if (op == 0x12) {
      // const/4 format 11n: B|A op → dest=A, val=sign_extend(B,4)
      result.push_back(ConstInstruction{base, static_cast<uint8_t>(hi & 0x0fU),
                                        sex4(static_cast<uint8_t>((static_cast<uint32_t>(hi) >> 4U) & 0x0fU)),
                                        OperandWidth::Single});
    } else if (op == 0x13) {
      // const/16 format 21s
      result.push_back(ConstInstruction{base, hi, sex16(unit1), OperandWidth::Single});
    } else if (op == 0x14) {
      // const format 31i
      int32_t val = static_cast<int32_t>(static_cast<uint32_t>(unit1) | (static_cast<uint32_t>(unit2) << 16U));
      result.push_back(ConstInstruction{base, hi, val, OperandWidth::Single});
    } else if (op == 0x15) {
      // const/high16 format 21h
      int64_t val = static_cast<int64_t>(static_cast<int32_t>(static_cast<uint32_t>(unit1) << 16U));
      result.push_back(ConstInstruction{base, hi, val, OperandWidth::Single});
    } else if (op == 0x16) {
      result.push_back(ConstInstruction{base, hi, sex16(unit1), OperandWidth::Pair});
    } else if (op == 0x17) {
      int32_t lo = static_cast<int32_t>(static_cast<uint32_t>(unit1) | (static_cast<uint32_t>(unit2) << 16U));
      result.push_back(ConstInstruction{base, hi, lo, OperandWidth::Pair});
    } else if (op == 0x18) {
      // const-wide format 51l
      uint64_t lo = static_cast<uint32_t>(unit1) | (static_cast<uint32_t>(unit2) << 16U);
      uint64_t hi64 = static_cast<uint32_t>(unit3) | (static_cast<uint32_t>(unit4) << 16U);
      result.push_back(ConstInstruction{base, hi, static_cast<int64_t>((hi64 << 32U) | lo), OperandWidth::Pair});
    } else if (op == 0x19) {
      // const-wide/high16 format 21h
      result.push_back(
          ConstInstruction{base, hi, static_cast<int64_t>(static_cast<uint64_t>(unit1) << 48U), OperandWidth::Pair});
    } else if (op == 0x1a) {
      result.push_back(ConstStringInstruction{base, hi, unit1});
    } else if (op == 0x1b) {
      uint32_t idx = static_cast<uint32_t>(unit1) | (static_cast<uint32_t>(unit2) << 16U);
      result.push_back(ConstStringInstruction{base, hi, idx});
    } else if (op == 0x1c) {
      result.push_back(ConstClassInstruction{base, hi, unit1});
    } else if (op == 0x1d || op == 0x1e) {
      result.push_back(MonitorInstruction{base, hi, op == 0x1d});
    } else if (op == 0x1f || op == 0x22) {
      // check-cast format 21c: a single in-place register, no separate src.
      result.push_back(TypeInstruction{base, unit1, hi, std::nullopt});
    } else if (op == 0x20 || op == 0x23) {
      // instance-of format 22c: A|B op CCCC → dest=A, src=B
      result.push_back(TypeInstruction{base, unit1, static_cast<uint8_t>(hi & 0x0fU),
                                       static_cast<uint8_t>((static_cast<uint32_t>(hi) >> 4U) & 0x0fU)});
    } else if (op == 0x21) {
      // array-length format 12x
      result.push_back(UnaryOpInstruction{base, static_cast<uint8_t>(hi & 0x0fU),
                                          static_cast<uint8_t>((static_cast<uint32_t>(hi) >> 4U) & 0x0fU),
                                          OperandWidth::Single, OperandWidth::Single});

    } else if (op == 0x24) {
      // filled-new-array format 35c: element registers + array type.
      result.push_back(FilledNewArrayInstruction{base, unit1, decode_35c_regs(unit0, unit2)});
    } else if (op == 0x25) {
      // filled-new-array/range format 3rc: element register range + array type.
      result.push_back(FilledNewArrayInstruction{base, unit1, decode_3rc_regs(unit0, unit2)});
    } else if (op == 0x26) {
      // fill-array-data format 31t
      int32_t off = static_cast<int32_t>(static_cast<uint32_t>(unit1) | (static_cast<uint32_t>(unit2) << 16U));
      result.push_back(FillArrayInstruction{base, hi, off});
    } else if (op == 0x27) {
      result.push_back(ThrowInstruction{base, hi});
    } else if (op == 0x28) {
      // goto format 10t: signed 8-bit offset in hi byte
      result.push_back(GotoInstruction{base, sex8(hi)});
    } else if (op == 0x29) {
      result.push_back(GotoInstruction{base, sex16(unit1)});
    } else if (op == 0x2a) {
      int32_t off = static_cast<int32_t>(static_cast<uint32_t>(unit1) | (static_cast<uint32_t>(unit2) << 16U));
      result.push_back(GotoInstruction{base, off});
    } else if (op == 0x2b || op == 0x2c) {
      // packed-switch / sparse-switch format 31t
      int32_t off = static_cast<int32_t>(static_cast<uint32_t>(unit1) | (static_cast<uint32_t>(unit2) << 16U));
      SwitchInstruction sw{base, off, hi, /*is_packed=*/op == 0x2b, {}};
      decode_switch_payload(insns, base.offset, off, sw);
      result.push_back(std::move(sw));
    } else if (op >= 0x2d && op <= 0x31) {
      // format 23x: AA op CC BB → dest=AA, src_a=BB, src_b=CC
      OperandWidth sw = (op >= 0x2f) ? OperandWidth::Pair : OperandWidth::Single;
      result.push_back(
          CompareInstruction{base, hi, static_cast<uint8_t>(unit1 & 0xffU), static_cast<uint8_t>(unit1 >> 8U), sw});
    } else if (op >= 0x32 && op <= 0x37) {
      // if-* format 22t: A|B op CCCC
      result.push_back(IfInstruction{base, sex16(unit1), static_cast<uint8_t>(hi & 0x0fU),
                                     static_cast<uint8_t>((static_cast<uint32_t>(hi) >> 4U) & 0x0fU)});
    } else if (op >= 0x38 && op <= 0x3d) {
      // if-*z format 21t: AA op BBBB
      result.push_back(IfZeroInstruction{base, sex16(unit1), hi});
    } else if (op >= 0x44 && op <= 0x51) {
      // aget/aput format 23x: AA op CC BB
      OperandWidth width = (op == 0x45 || op == 0x4c) ? OperandWidth::Pair : OperandWidth::Single;
      result.push_back(ArrayOpInstruction{base, hi, static_cast<uint8_t>(unit1 & 0xffU),
                                          static_cast<uint8_t>(unit1 >> 8U), op >= 0x4bU, width});
    } else if (op >= 0x52 && op <= 0x5f) {
      // iget/iput format 22c: A|B op CCCC
      OperandWidth width = (op == 0x53 || op == 0x5a) ? OperandWidth::Pair : OperandWidth::Single;
      result.push_back(FieldInstruction{base, unit1, static_cast<uint8_t>(hi & 0x0fU),
                                        static_cast<uint8_t>((static_cast<uint32_t>(hi) >> 4U) & 0x0fU), false,
                                        op >= 0x59U, width});
    } else if (op >= 0x60 && op <= 0x6d) {
      // sget/sput format 21c: AA op BBBB
      OperandWidth width = (op == 0x61 || op == 0x68) ? OperandWidth::Pair : OperandWidth::Single;
      result.push_back(FieldInstruction{base, unit1, hi, std::nullopt, true, op >= 0x67, width});
    } else if ((op >= 0x6e && op <= 0x72) || op == 0xfa) {
      // invoke-* format 35c
      result.push_back(InvokeInstruction{base, unit1, decode_35c_regs(unit0, unit2)});
    } else if ((op >= 0x74 && op <= 0x78) || op == 0xfb) {
      // invoke-*/range format 3rc
      result.push_back(InvokeInstruction{base, unit1, decode_3rc_regs(unit0, unit2)});
    } else if (op >= 0x7b && op <= 0x8f) {
      // unary ops format 12x: B|A op → dest=A, src=B
      uint8_t dest = static_cast<uint8_t>(hi & 0x0fU);
      uint8_t src = static_cast<uint8_t>((static_cast<uint32_t>(hi) >> 4U) & 0x0fU);
      OperandWidth dest_w, src_w;
      switch (op) {
        case 0x7b:
        case 0x7c:
          dest_w = OperandWidth::Single;
          src_w = OperandWidth::Single;
          break;
        case 0x7d:
        case 0x7e:
          dest_w = OperandWidth::Pair;
          src_w = OperandWidth::Pair;
          break;
        case 0x7f:
          dest_w = OperandWidth::Single;
          src_w = OperandWidth::Single;
          break;
        case 0x80:
          dest_w = OperandWidth::Pair;
          src_w = OperandWidth::Pair;
          break;
        case 0x81:
          dest_w = OperandWidth::Pair;
          src_w = OperandWidth::Single;
          break;
        case 0x82:
          dest_w = OperandWidth::Single;
          src_w = OperandWidth::Single;
          break;
        case 0x83:
          dest_w = OperandWidth::Pair;
          src_w = OperandWidth::Single;
          break;
        case 0x84:
        case 0x85:
          dest_w = OperandWidth::Single;
          src_w = OperandWidth::Pair;
          break;
        case 0x86:
          dest_w = OperandWidth::Pair;
          src_w = OperandWidth::Pair;
          break;
        case 0x87:
          dest_w = OperandWidth::Single;
          src_w = OperandWidth::Single;
          break;
        case 0x88:
        case 0x89:
          dest_w = OperandWidth::Pair;
          src_w = OperandWidth::Single;
          break;
        case 0x8a:
          dest_w = OperandWidth::Single;
          src_w = OperandWidth::Pair;
          break;
        case 0x8b:
          dest_w = OperandWidth::Pair;
          src_w = OperandWidth::Pair;
          break;
        case 0x8c:
          dest_w = OperandWidth::Single;
          src_w = OperandWidth::Pair;
          break;
        default:
          dest_w = OperandWidth::Single;
          src_w = OperandWidth::Single;
          break;
      }
      result.push_back(UnaryOpInstruction{base, dest, src, dest_w, src_w});
    } else if (op >= 0x90 && op <= 0xaf) {
      // binary ops format 23x: AA op CC BB
      result.push_back(BinaryOpInstruction{base, hi, static_cast<uint8_t>(unit1 & 0xffU),
                                           static_cast<uint8_t>(unit1 >> 8U), binary_op_width(op)});
    } else if (op >= 0xb0 && op <= 0xcf) {
      // binary /2addr format 12x: B|A op → dest=src_a=A, src_b=B
      uint8_t dest = static_cast<uint8_t>(hi & 0x0fU);
      result.push_back(BinaryOpInstruction{
          base, dest, dest, static_cast<uint8_t>((static_cast<uint32_t>(hi) >> 4U) & 0x0fU), binary_op_width(op)});
    } else if (op >= 0xd0 && op <= 0xd7) {
      // binary lit16 format 22s: A|B op CCCC
      result.push_back(BinaryLitInstruction{base, static_cast<uint8_t>(hi & 0x0fU),
                                            static_cast<uint8_t>((static_cast<uint32_t>(hi) >> 4U) & 0x0fU),
                                            static_cast<int16_t>(unit1)});
    } else if (op >= 0xd8 && op <= 0xe2) {
      // binary lit8 format 22b: AA op BB CC
      result.push_back(BinaryLitInstruction{base, hi, static_cast<uint8_t>(unit1 & 0xffU),
                                            static_cast<int16_t>(sex8(static_cast<uint8_t>(unit1 >> 8U)))});

    } else if (op == 0xfc) {
      // invoke-custom format 35c
      result.push_back(InvokeCustomInstruction{base, unit1, decode_35c_regs(unit0, unit2)});
    } else if (op == 0xfd) {
      // invoke-custom/range format 3rc
      result.push_back(InvokeCustomInstruction{base, unit1, decode_3rc_regs(unit0, unit2)});
    } else if (op == 0xfe || op == 0xff) {
      // const-method-handle / const-method-type format 21c
      result.push_back(ConstHandleInstruction{base, hi, unit1});
    } else {
      throw std::invalid_argument("unsupported analysis opcode");
    }

    pos += sz;
  }

  return result;
}

}  // namespace dexsplit
