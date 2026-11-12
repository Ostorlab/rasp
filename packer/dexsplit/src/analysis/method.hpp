#pragma once

#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include "common/ids.hpp" // MethodId, FieldId
#include "instruction.hpp" // Instruction, InvokeKind, TypeRefKind

namespace dexsplit {

namespace detail {
struct AnalysisContextImpl;
} // namespace detail

/** One outgoing call site in a method's body. */
struct MethodCall
{
    uint32_t code_offset; ///< Code-unit offset of the invoke instruction.
    MethodId target;      ///< Declared callee (no class-hierarchy resolution).
    InvokeKind kind;      ///< The kind of invoke instruction.
};

/** One field read or write in a method's body. */
struct FieldAccess
{
    uint32_t code_offset; ///< Code-unit offset of the field instruction.
    FieldId field;        ///< The accessed field.
    bool is_write;        ///< true for iput*/sput*.
    bool is_static;       ///< true for sget*/sput*.
};

/** One type reference (const-class / check-cast / instance-of / new-instance /
 *  new-array / filled-new-array) in a method's body. */
struct TypeUse
{
    uint32_t code_offset;        ///< Code-unit offset of the instruction.
    std::string_view descriptor; ///< Referenced type descriptor; context-lifetime.
    TypeRefKind kind;            ///< What the instruction does with the type.
};

/** A lightweight, non-owning handle to a single DEX method.
 *
 *  Instances come from Class::methods().  The handle stores the absolute
 *  method_ids index and the code offset that come from the EncodedMethod entry
 *  in class_data_item. */
class Method
{
  public:
    /** @param method_abs_idx  Absolute index into the DEX file's method_ids table.
     *  @param code_off        Byte offset of the code_item, or 0 for abstract/native. */
    Method(std::shared_ptr<const detail::AnalysisContextImpl> impl, std::size_t dex_idx,
           uint32_t method_abs_idx, uint32_t code_off);

    /** Decoded bytecode for this method, as a view into a per-context cache.
     *  Repeated calls return the same span; the storage stays alive for as long
     *  as any handle into the same context.  Empty for abstract/native methods. */
    std::span<const Instruction> instructions() const;

    /** The methods this body calls, each by its declared target, in code order.
     *  Empty for abstract/native methods. */
    std::vector<MethodCall> calls() const;

    /** The fields this body reads or writes, in code order.  Empty for
     *  abstract/native methods. */
    std::vector<FieldAccess> field_accesses() const;

    /** The types this body references (const-class / check-cast / instance-of /
     *  new-instance / new-array / filled-new-array), in code order.  Empty for
     *  abstract/native methods. */
    std::vector<TypeUse> type_uses() const;

  private:
    std::shared_ptr<const detail::AnalysisContextImpl> impl_;
    std::size_t dex_idx_;
    uint32_t method_abs_idx_;
    uint32_t code_off_;
};

} // namespace dexsplit
