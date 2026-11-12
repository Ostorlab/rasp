#include "method.hpp"

#include <type_traits>
#include <variant>

#include "analysis_context_impl.hpp"
#include "common/budget.hpp"

namespace dexsplit {

Method::Method(std::shared_ptr<const detail::AnalysisContextImpl> impl, DexIndex dex_idx, uint32_t, uint32_t code_off)
    : impl_(std::move(impl)), dex_idx_(dex_idx), code_off_(code_off) {}

std::span<const Instruction> Method::instructions() const {
  budget::Scope scope(impl_->request);
  return impl_->get_instructions(dex_idx_, code_off_);
}

budget::Vector<MethodCall> Method::calls() const {
  budget::Scope scope(impl_->request);
  budget::Vector<MethodCall> out;
  for (const auto& insn : instructions()) {
    dexsplit::budget::visit();
    if (const auto* iv = std::get_if<InvokeInstruction>(&insn)) {
      if (auto kind = invoke_kind_from_opcode(iv->base.opcode)) {
        out.push_back({iv->base.offset, impl_->method_id_of(dex_idx_, iv->method_index), *kind});
      }
    }
  }
  return out;
}

budget::Vector<FieldAccess> Method::field_accesses() const {
  budget::Scope scope(impl_->request);
  budget::Vector<FieldAccess> out;
  for (const auto& insn : instructions()) {
    dexsplit::budget::visit();
    if (const auto* f = std::get_if<FieldInstruction>(&insn)) {
      out.push_back({f->base.offset, impl_->field_id_of(dex_idx_, f->field_index), f->is_write, f->is_static});
    }
  }
  return out;
}

budget::Vector<TypeUse> Method::type_uses() const {
  budget::Scope scope(impl_->request);
  budget::Vector<TypeUse> out;
  for (const auto& insn : instructions()) {
    dexsplit::budget::visit();
    std::visit(
        [&](const auto& v) {
          using T = std::decay_t<decltype(v)>;
          if constexpr (std::is_same_v<T, ConstClassInstruction>) {
            out.push_back({v.base.offset, impl_->type_descriptor_of(dex_idx_, v.type_index), TypeRefKind::ConstClass});
          } else if constexpr (std::is_same_v<T, TypeInstruction>) {
            if (auto kind = type_ref_kind_from_opcode(v.base.opcode)) {
              out.push_back({v.base.offset, impl_->type_descriptor_of(dex_idx_, v.type_index), *kind});
            }
          } else if constexpr (std::is_same_v<T, FilledNewArrayInstruction>) {
            out.push_back(
                {v.base.offset, impl_->type_descriptor_of(dex_idx_, v.type_index), TypeRefKind::FilledNewArray});
          }
        },
        insn);
  }
  return out;
}

}  // namespace dexsplit
