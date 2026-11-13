#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace dexsplit {

/** Distinguishes 32-bit (single-register) from 64-bit (register-pair) operands. */
enum class OperandWidth : uint8_t {
    Single, ///< 32-bit value — occupies 1 register
    Pair,   ///< 64-bit value — occupies register pair (vN:vN+1)
};

/** Kind of invoke instruction at a call site, derived from the opcode. */
enum class InvokeKind : uint8_t {
    Virtual,     ///< invoke-virtual / invoke-virtual/range          (0x6e, 0x74)
    Super,       ///< invoke-super / invoke-super/range              (0x6f, 0x75)
    Direct,      ///< invoke-direct / invoke-direct/range            (0x70, 0x76)
    Static,      ///< invoke-static / invoke-static/range            (0x71, 0x77)
    Interface,   ///< invoke-interface / invoke-interface/range      (0x72, 0x78)
    Polymorphic, ///< invoke-polymorphic / invoke-polymorphic/range  (0xfa, 0xfb)
    Custom,      ///< invoke-custom / invoke-custom/range            (0xfc, 0xfd)
};

/** Map a Dalvik invoke opcode to its InvokeKind.  Returns std::nullopt for any
 *  opcode that is not a recognised invoke. */
std::optional<InvokeKind> invoke_kind_from_opcode(uint8_t opcode);

/** What a type-referencing instruction does with its type operand. */
enum class TypeRefKind : uint8_t {
    ConstClass,     ///< const-class                                              (0x1c)
    CheckCast,      ///< check-cast                                               (0x1f)
    InstanceOf,     ///< instance-of                                              (0x20)
    NewInstance,    ///< new-instance                                            (0x22)
    NewArray,       ///< new-array — descriptor is the *array* type, e.g. "[I"   (0x23)
    FilledNewArray, ///< filled-new-array / filled-new-array/range          (0x24, 0x25)
};

/** Map a type-referencing opcode to its TypeRefKind.  Returns std::nullopt for
 *  any opcode that does not carry a type operand (e.g. array-length). */
std::optional<TypeRefKind> type_ref_kind_from_opcode(uint8_t opcode);

/** Fields shared by every concrete instruction type. */
struct InstructionBase
{
    uint32_t offset; ///< Code unit offset from the start of the method's insns[]
    uint8_t opcode;  ///< Raw opcode byte
    uint8_t size;    ///< Instruction width in 16-bit code units (1–5)
};

/** nop (0x00). */
struct NopInstruction
{
    InstructionBase base;
};

/** goto, goto/16, goto/32 (0x28–0x2a). */
struct GotoInstruction
{
    InstructionBase base;
    int32_t branch_offset; ///< Signed, relative to instruction start, in code units
};

/** if-eq .. if-le (0x32–0x37). */
struct IfInstruction
{
    InstructionBase base;
    int32_t branch_offset;
    uint8_t reg_a;
    uint8_t reg_b;
};

/** if-eqz .. if-lez (0x38–0x3d). */
struct IfZeroInstruction
{
    InstructionBase base;
    int32_t branch_offset;
    uint8_t reg;
};

/** A single case of a packed-switch / sparse-switch payload. */
struct SwitchCase
{
    int32_t key;    ///< Integer key compared against the switch register.
    int32_t target; ///< Code-unit offset relative to the switch instruction's start.
};

/** packed-switch, sparse-switch (0x2b–0x2c). */
struct SwitchInstruction
{
    InstructionBase base;
    int32_t payload_offset; ///< Signed, relative to instruction start
    uint8_t reg;
    bool is_packed; ///< true for packed-switch (0x2b), false for sparse-switch (0x2c)
    /** Decoded case table.  Empty if the payload was malformed or out of bounds. */
    std::vector<SwitchCase> cases;
};

/** return-void, return, return-wide, return-object (0x0e–0x11). */
struct ReturnInstruction
{
    InstructionBase base;
    std::optional<uint8_t> reg; ///< nullopt for return-void
    OperandWidth width;
};

/** throw (0x27). */
struct ThrowInstruction
{
    InstructionBase base;
    uint8_t reg;
};

/** move, move-wide, move-object, move-result, move-exception (0x01–0x0d). */
struct MoveInstruction
{
    InstructionBase base;
    uint16_t dest;
    uint16_t src; ///< 0 for move-result / move-exception (implicit source)
    OperandWidth width;
};

/** const/4 .. const-wide/high16 (0x12–0x19). */
struct ConstInstruction
{
    InstructionBase base;
    uint8_t dest;
    int64_t value; ///< Widened to 64 bits for all variants
    OperandWidth width;
};

/** const-string, const-string/jumbo (0x1a–0x1b). */
struct ConstStringInstruction
{
    InstructionBase base;
    uint8_t dest;
    uint32_t string_index;
};

/** const-class (0x1c). */
struct ConstClassInstruction
{
    InstructionBase base;
    uint8_t dest;
    uint32_t type_index;
};

/** const-method-handle, const-method-type (0xfe–0xff). */
struct ConstHandleInstruction
{
    InstructionBase base;
    uint8_t dest;
    uint32_t index; ///< method_handle or proto index
};

/** check-cast, instance-of, new-instance, new-array (0x1f–0x23). */
struct TypeInstruction
{
    InstructionBase base;
    uint32_t type_index;
    uint8_t dest;               ///< The register operated on: the cast register (check-cast),
                                ///< result (instance-of / new-array), or new object (new-instance).
    std::optional<uint8_t> src; ///< instance-of: object reg; new-array: size reg.
                                ///< nullopt for check-cast and new-instance (single register).
};

/** filled-new-array, filled-new-array/range (0x24–0x25): build an array of
 *  `type_index` from the element registers, like an invoke's argument list. */
struct FilledNewArrayInstruction
{
    InstructionBase base;
    uint32_t type_index;            ///< Array type (e.g. type@N for "[I").
    std::vector<uint16_t> arg_regs; ///< Element registers, decoded from 35c/3rc.
};

/** monitor-enter, monitor-exit (0x1d–0x1e). */
struct MonitorInstruction
{
    InstructionBase base;
    uint8_t reg;
    bool is_enter; ///< true = monitor-enter, false = monitor-exit
};

/** fill-array-data (0x26). */
struct FillArrayInstruction
{
    InstructionBase base;
    uint8_t reg;
    int32_t payload_offset; ///< Relative to instruction start
};

/** cmpl-float, cmpg-float, cmpl-double, cmpg-double, cmp-long (0x2d–0x31). */
struct CompareInstruction
{
    InstructionBase base;
    uint8_t dest; ///< Result is always Single (int)
    uint8_t src_a;
    uint8_t src_b;
    OperandWidth src_width; ///< Pair for double/long; Single for float
};

/** aget*, aput* (0x44–0x51). */
struct ArrayOpInstruction
{
    InstructionBase base;
    uint8_t value_reg;
    uint8_t array_reg;
    uint8_t index_reg;
    bool is_write; ///< true for aput*
    OperandWidth width;
};

/** iget*, iput*, sget*, sput* (0x52–0x6d). */
struct FieldInstruction
{
    InstructionBase base;
    uint32_t field_index;
    uint8_t value_reg;
    std::optional<uint8_t> object_reg; ///< Present for instance fields; nullopt for static
    bool is_static;
    bool is_write; ///< true for iput*/sput*
    OperandWidth width;
};

/** invoke-virtual/super/direct/static/interface and their /range variants (0x6e–0x78). */
struct InvokeInstruction
{
    InstructionBase base;
    uint32_t method_index;
    std::vector<uint16_t> arg_regs; ///< Full register list decoded from 35c/3rc format
};

/** invoke-custom, invoke-custom/range (0xfc–0xfd). */
struct InvokeCustomInstruction
{
    InstructionBase base;
    uint32_t call_site_index;
    std::vector<uint16_t> arg_regs;
};

/** neg-int, not-int, int-to-long, long-to-int, etc. (0x7b–0x8f). */
struct UnaryOpInstruction
{
    InstructionBase base;
    uint8_t dest;
    uint8_t src;
    OperandWidth dest_width;
    OperandWidth src_width;
};

/** add-int, sub-int, ..., rem-double/2addr (0x90–0xcf). */
struct BinaryOpInstruction
{
    InstructionBase base;
    uint8_t dest;
    uint8_t src_a;
    uint8_t src_b; ///< For /2addr: src_a == dest, src_b is the other operand
    OperandWidth width;
};

/** add-int/lit16, rsub-int, ..., ushr-int/lit8 (0xd0–0xe2). */
struct BinaryLitInstruction
{
    InstructionBase base;
    uint8_t dest;
    uint8_t src;
    int16_t literal; ///< Sign-extended from 8 or 16 bits
};

/** A single decoded Dalvik instruction. */
using Instruction =
    std::variant<NopInstruction, GotoInstruction, IfInstruction, IfZeroInstruction,
                 SwitchInstruction, ReturnInstruction, ThrowInstruction, MoveInstruction,
                 ConstInstruction, ConstStringInstruction, ConstClassInstruction,
                 ConstHandleInstruction, TypeInstruction, FilledNewArrayInstruction,
                 MonitorInstruction, FillArrayInstruction, CompareInstruction, ArrayOpInstruction,
                 FieldInstruction, InvokeInstruction, InvokeCustomInstruction, UnaryOpInstruction,
                 BinaryOpInstruction, BinaryLitInstruction>;

/** Extract the common base fields without std::visit boilerplate. */
inline const InstructionBase &base_of(const Instruction &insn)
{
    return std::visit([](const auto &i) -> const InstructionBase & { return i.base; }, insn);
}

/** Returns true for goto / if-* / switch / return / throw (basic block terminators). */
bool is_terminator(const Instruction &insn);

/** Mnemonic for a raw Dalvik opcode byte (e.g. 0x6e -> "invoke-virtual").
 *  Unused / reserved opcodes return "unused-XX".  Always a valid, static view. */
std::string_view opcode_name(uint8_t opcode);

/** Render one decoded instruction as "<mnemonic> <operands>" (no leading code
 *  offset).  Constant-pool operands appear as raw indices — string@N, type@N,
 *  method@N, field@N, site@N — because this function has no AnalysisContext to
 *  resolve them; use the analysis layer when you need resolved names. */
std::string to_string(const Instruction &insn);

/** Decode a raw insns[] array (16-bit code units) into typed instructions.
 *
 *  Payload pseudo-instructions (packed-switch/sparse-switch/fill-array-data
 *  data blocks) are detected and skipped — they do not appear in the result.
 *
 *  @param insns  Raw code units from CodeItem::insns.
 *  @return       Vector of typed instructions in execution order. */
std::vector<Instruction> decode_instructions(std::span<const uint16_t> insns);

} // namespace dexsplit
