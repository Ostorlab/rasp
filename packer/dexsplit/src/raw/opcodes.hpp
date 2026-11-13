#include "common/budget.hpp"
#pragma once

#include <array>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "raw/error.hpp"

/** The Dalvik instruction set at the encoding level: one table describing all
 *  256 opcodes, and a decoder / encoder between code units and the operand
 *  fields each instruction format defines.
 *
 *  This is the single source of opcode names, formats and sizes: the analysis
 *  decoder, the call-graph's invoke scanner and the editable model all use it. */
namespace dexsplit::raw {

/** Instruction formats, named as in the Dalvik bytecode spec ("Instruction
 *  formats"): the first digit is the size in 16-bit code units, the second the
 *  number of registers, the letter the kind of extra data. */
enum class Format : uint8_t {
  F10x,   ///< op
  F12x,   ///< op vA, vB (4-bit registers)
  F11n,   ///< op vA, #+B (4-bit literal)
  F11x,   ///< op vAA
  F10t,   ///< op +AA (8-bit branch offset)
  F20t,   ///< op +AAAA
  F22x,   ///< op vAA, vBBBB
  F21t,   ///< op vAA, +BBBB
  F21s,   ///< op vAA, #+BBBB
  F21h,   ///< op vAA, #+BBBB0000 / #+BBBB000000000000
  F21c,   ///< op vAA, kind@BBBB
  F23x,   ///< op vAA, vBB, vCC
  F22b,   ///< op vAA, vBB, #+CC
  F22t,   ///< op vA, vB, +CCCC
  F22s,   ///< op vA, vB, #+CCCC
  F22c,   ///< op vA, vB, kind@CCCC
  F32x,   ///< op vAAAA, vBBBB
  F30t,   ///< op +AAAAAAAA
  F31t,   ///< op vAA, +BBBBBBBB (payload offset)
  F31i,   ///< op vAA, #+BBBBBBBB
  F31c,   ///< op vAA, string@BBBBBBBB
  F35c,   ///< op {vC, vD, vE, vF, vG}, kind@BBBB
  F3rc,   ///< op {vCCCC .. vNNNN}, kind@BBBB
  F45cc,  ///< op {vC, vD, vE, vF, vG}, meth@BBBB, proto@HHHH
  F4rcc,  ///< op {vCCCC .. vNNNN}, meth@BBBB, proto@HHHH
  F51l,   ///< op vAA, #+BBBBBBBBBBBBBBBB
  Unused  ///< not a valid opcode in a DEX file
};

/** The pool an instruction's index operand refers to.  invoke-polymorphic has
 *  two: a method (`index`) and a proto (`proto` in InsnFields). */
enum class RefKind : uint8_t {
  None,
  String,
  Type,
  Field,
  Method,
  Proto,
  CallSite,
  MethodHandle,
};

struct OpcodeInfo {
  std::string_view name;  ///< Mnemonic, e.g. "invoke-virtual/range"; "unused-NN" if unused.
  Format format;
  RefKind ref;
  uint8_t units;  ///< Size in 16-bit code units: format_units(format).
};

namespace detail {
extern const std::array<OpcodeInfo, 256> opcode_table;
}  // namespace detail

/** Description of @p opcode. */
inline const OpcodeInfo& opcode_info(uint8_t opcode) { return detail::opcode_table[opcode]; }

/** Size of an instruction of format @p format, in 16-bit code units
 *  (1 for Format::Unused, so a scanner can step over a bad opcode). */
uint32_t format_units(Format format);

/** Code unit that starts a payload pseudo-instruction: op 0x00 (nop) with
 *  the payload kind in the high byte. */
inline constexpr uint16_t PACKED_SWITCH_PAYLOAD = 0x0100;
inline constexpr uint16_t SPARSE_SWITCH_PAYLOAD = 0x0200;
inline constexpr uint16_t FILL_ARRAY_DATA_PAYLOAD = 0x0300;

/** Declared size in code units of the payload starting at @p pos, from its
 *  header; nullopt if insns[pos] is not a payload ident or the header is cut
 *  off.  The payload's data may still run past the end of @p insns: callers
 *  that need the whole payload check that themselves. */
std::optional<uint64_t> payload_units(std::span<const uint16_t> insns, uint32_t pos);

/** One instruction as its format's operand fields.  Which fields a format
 *  uses follows the Dalvik spec's notation:
 *    - `a`, `b`, `c`: the registers vA/vAA/vAAAA, vB/vBB/vBBBB, vC/vCC.
 *      For 35c/45cc, `a` is the argument count and the registers are
 *      `args[0..a)` (C, D, E, F, G).  For 3rc/4rcc, `a` is the count and `c`
 *      the first register.
 *    - `literal`: the stored literal, sign-extended (11n, 21s, 21h, 22b, 22s,
 *      31i, 51l).  For 21h it is the 16 stored bits; the shift is the
 *      opcode's meaning, not the format's.
 *    - `offset`: the signed branch or payload offset in code units (10t, 20t,
 *      30t, 21t, 22t, 31t).
 *    - `index`: the pool index (21c, 22c, 31c, 35c, 3rc, 45cc, 4rcc).
 *    - `proto`: the second index of 45cc / 4rcc. */
struct InsnFields {
  uint8_t opcode = 0;
  uint32_t a = 0;
  uint32_t b = 0;
  uint32_t c = 0;
  int64_t literal = 0;
  int32_t offset = 0;
  uint32_t index = 0;
  uint32_t proto = 0;
  std::array<uint16_t, 5> args{};

  bool operator==(const InsnFields&) const = default;
};

/** Decode the instruction at @p pos.  Fails if the opcode is unused, if the
 *  instruction is cut off by the end of @p insns, if a 35c/45cc argument
 *  count exceeds 5, or if insns[pos] starts a payload (op 0x00 with a
 *  non-zero high byte).  Bits a format leaves unused are ignored. */
std::expected<InsnFields, ParseError> decode_insn(std::span<const uint16_t> insns, uint32_t pos);

/** Append the code units of @p fields, in the format of its opcode.  Returns
 *  false, and appends nothing, if the opcode is unused or a field does not
 *  fit its format (a register, literal, offset or index too wide, more than 5
 *  arguments in 35c/45cc, or a payload ident as a nop). */
bool encode_insn(const InsnFields& fields, budget::Vector<uint16_t>& out);

}  // namespace dexsplit::raw
