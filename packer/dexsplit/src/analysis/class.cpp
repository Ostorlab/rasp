#include "class.hpp"

#include "analysis_context_impl.hpp"
#include "raw/parser.hpp"

namespace dexsplit {

Class::Class(std::shared_ptr<const detail::AnalysisContextImpl> impl, std::size_t dex_idx,
             uint32_t class_def_idx)
    : impl_(std::move(impl)), dex_idx_(dex_idx), class_def_idx_(class_def_idx)
{
}

std::string_view Class::name() const
{
    const auto &cdef = impl_->dex_files()[dex_idx_].class_defs()[class_def_idx_];
    return impl_->type_descriptor_of(dex_idx_, cdef.class_idx);
}

std::optional<ClassRef> Class::superclass() const
{
    const auto &cdef = impl_->dex_files()[dex_idx_].class_defs()[class_def_idx_];
    if (cdef.superclass_idx == raw::NO_INDEX)
        return std::nullopt;
    return ClassRef(impl_->type_descriptor_of(dex_idx_, cdef.superclass_idx));
}

std::vector<ClassRef> Class::interfaces() const
{
    const auto &cdef = impl_->dex_files()[dex_idx_].class_defs()[class_def_idx_];
    if (cdef.interfaces_off == 0)
        return {};

    auto type_list = raw::parser::parse_type_list(impl_->buffer_of(dex_idx_), cdef.interfaces_off);
    if (!type_list.has_value())
        return {};

    std::vector<ClassRef> refs;
    refs.reserve(type_list->type_ids.size());
    for (auto type_idx : type_list->type_ids)
        refs.emplace_back(impl_->type_descriptor_of(dex_idx_, type_idx));
    return refs;
}

std::vector<Method> Class::methods() const
{
    const auto &cdef = impl_->dex_files()[dex_idx_].class_defs()[class_def_idx_];
    const auto *cd = impl_->get_class_data(dex_idx_, cdef.class_data_off);
    if (!cd)
        return {};

    std::vector<Method> result;
    result.reserve(cd->direct_methods.size() + cd->virtual_methods.size());
    for (const auto &em : cd->direct_methods)
        result.emplace_back(impl_, dex_idx_, em.method_idx, em.code_off);
    for (const auto &em : cd->virtual_methods)
        result.emplace_back(impl_, dex_idx_, em.method_idx, em.code_off);
    return result;
}

} // namespace dexsplit
