#include "analysis_context.hpp"

#include "analysis_context_impl.hpp"
#include "raw/parser.hpp"

namespace dexsplit {

using detail::AnalysisContextImpl;
using detail::ManagedBuffer;

AnalysisContext::AnalysisContext(std::shared_ptr<AnalysisContextImpl> impl) : impl_(std::move(impl))
{
}

// The analysis layer never eagerly decodes the string pool; string_of()
// decodes and caches each string on first use.
static constexpr raw::parser::ParseOptions kLazyParse{.decode_strings = false};

std::expected<AnalysisContext, std::string>
AnalysisContext::from_dex_buffers(const std::vector<std::span<const uint8_t>> &buffers)
{
    auto impl = std::make_shared<AnalysisContextImpl>();
    for (std::size_t i = 0; i < buffers.size(); ++i) {
        std::vector<uint8_t> owned(buffers[i].begin(), buffers[i].end());
        ManagedBuffer buffer(std::move(owned));
        auto dex = raw::parser::parse_buffer(buffer.bytes(), kLazyParse);
        if (!dex.has_value())
            return std::unexpected("dex " + std::to_string(i) + ": " + dex.error().message);
        impl->dex_files_vec.push_back(std::move(dex.value()));
        impl->slots.push_back(std::make_unique<AnalysisContextImpl::DexSlot>(std::move(buffer)));
    }
    return AnalysisContext(std::move(impl));
}

std::vector<Class> AnalysisContext::classes() const
{
    std::vector<Class> result;
    for (std::size_t i = 0; i < impl_->dex_files_vec.size(); ++i) {
        const auto &dex = impl_->dex_files_vec[i];
        for (uint32_t j = 0; j < static_cast<uint32_t>(dex.class_defs().size()); ++j)
            result.emplace_back(impl_, i, j);
    }
    return result;
}

namespace detail {

std::span<const uint8_t> AnalysisContextImpl::buffer_of(std::size_t dex_idx) const
{
    return slots[dex_idx]->buffer.bytes();
}

std::string_view AnalysisContextImpl::string_of(std::size_t dex_idx, uint32_t string_idx) const
{
    auto string_ids = dex_files_vec[dex_idx].string_ids();
    if (string_idx >= string_ids.size())
        return {};

    auto &slot = *slots[dex_idx];
    std::lock_guard<std::mutex> lock(slot.strings_mutex);

    auto it = slot.string_cache.find(string_idx);
    if (it != slot.string_cache.end())
        return it->second;

    uint32_t data_off = string_ids[string_idx];
    std::string value;
    if (auto r = raw::parser::parse_string(slot.buffer.bytes(), data_off); r.has_value())
        value = std::move(r->first);

    auto [ins, _] = slot.string_cache.emplace(string_idx, std::move(value));
    return ins->second;
}

std::string_view AnalysisContextImpl::type_descriptor_of(std::size_t dex_idx,
                                                         uint32_t type_idx) const
{
    auto type_ids = dex_files_vec[dex_idx].type_ids();
    if (type_idx >= type_ids.size())
        return {};
    return string_of(dex_idx, type_ids[type_idx]);
}

const raw::ProtoIdItem *AnalysisContextImpl::proto_item(std::size_t dex_idx,
                                                       uint32_t proto_index) const
{
    auto items = dex_files_vec[dex_idx].proto_ids();
    return proto_index < items.size() ? &items[proto_index] : nullptr;
}

const raw::ClassDataItem *AnalysisContextImpl::get_class_data(std::size_t dex_idx,
                                                             uint32_t class_data_off) const
{
    if (class_data_off == 0)
        return nullptr;

    auto &slot = *slots[dex_idx];
    std::lock_guard<std::mutex> lock(slot.class_data_mutex);

    auto it = slot.class_data_cache.find(class_data_off);
    if (it != slot.class_data_cache.end())
        return &it->second;

    auto result = raw::parser::parse_class_data(slot.buffer.bytes(), class_data_off);
    if (!result.has_value())
        return nullptr;

    auto [ins_it, ok] = slot.class_data_cache.emplace(class_data_off, std::move(result.value()));
    return &ins_it->second;
}

const raw::CodeItem *AnalysisContextImpl::get_code_item(std::size_t dex_idx,
                                                       uint32_t code_off) const
{
    if (code_off == 0)
        return nullptr;

    auto &slot = *slots[dex_idx];
    std::lock_guard<std::mutex> lock(slot.code_item_mutex);

    auto it = slot.code_item_cache.find(code_off);
    if (it != slot.code_item_cache.end())
        return &it->second;

    auto result = raw::parser::parse_code_item(slot.buffer.bytes(), code_off);
    if (!result.has_value())
        return nullptr;

    auto [ins_it, ok] = slot.code_item_cache.emplace(code_off, std::move(result.value()));
    return &ins_it->second;
}

std::span<const Instruction> AnalysisContextImpl::get_instructions(std::size_t dex_idx,
                                                                  uint32_t code_off) const
{
    if (code_off == 0)
        return {};

    const auto *ci = get_code_item(dex_idx, code_off);
    if (!ci)
        return {};

    auto &slot = *slots[dex_idx];
    std::lock_guard<std::mutex> lock(slot.instructions_mutex);

    auto it = slot.instructions_cache.find(code_off);
    if (it != slot.instructions_cache.end())
        return it->second;

    auto [ins_it, ok] = slot.instructions_cache.emplace(code_off, decode_instructions(ci->insns));
    return ins_it->second;
}

const std::string &AnalysisContextImpl::proto_descriptor_of(std::size_t dex_idx,
                                                           uint32_t proto_idx) const
{
    static const std::string kEmpty;
    auto proto_ids = dex_files_vec[dex_idx].proto_ids();
    if (proto_idx >= proto_ids.size())
        return kEmpty;

    uint64_t key = (static_cast<uint64_t>(dex_idx) << 32) | proto_idx;
    {
        std::lock_guard<std::mutex> lock(proto_cache_mutex);
        if (auto it = proto_descriptor_cache.find(key); it != proto_descriptor_cache.end())
            return it->second;
    }

    std::string out = build_proto_descriptor(dex_idx, proto_idx);

    std::lock_guard<std::mutex> lock(proto_cache_mutex);
    return proto_descriptor_cache.emplace(key, std::move(out)).first->second;
}

std::string AnalysisContextImpl::build_proto_descriptor(std::size_t dex_idx,
                                                       uint32_t proto_idx) const
{
    const auto *proto = proto_item(dex_idx, proto_idx);
    if (!proto)
        return {};

    std::string out;
    out.push_back('(');
    if (proto->parameters_off != 0) {
        auto type_list = raw::parser::parse_type_list(buffer_of(dex_idx), proto->parameters_off);
        if (type_list.has_value()) {
            for (auto type_idx : type_list->type_ids)
                out.append(type_descriptor_of(dex_idx, type_idx));
        }
        else {
            out.append("<unparseable>");
        }
    }
    out.push_back(')');
    out.append(type_descriptor_of(dex_idx, proto->return_type_idx));
    return out;
}

MethodId AnalysisContextImpl::method_id_of(std::size_t dex_idx, uint32_t method_index) const
{
    auto method_ids = dex_files_vec[dex_idx].method_ids();
    if (method_index >= method_ids.size())
        return MethodId{};
    const auto &mid = method_ids[method_index];
    return MethodId{
        std::string(type_descriptor_of(dex_idx, mid.class_idx)),
        std::string(string_of(dex_idx, mid.name_idx)),
        proto_descriptor_of(dex_idx, mid.proto_idx),
    };
}

FieldId AnalysisContextImpl::field_id_of(std::size_t dex_idx, uint32_t field_index) const
{
    auto field_ids = dex_files_vec[dex_idx].field_ids();
    if (field_index >= field_ids.size())
        return FieldId{};
    const auto &fid = field_ids[field_index];
    return FieldId{
        std::string(type_descriptor_of(dex_idx, fid.class_idx)),
        std::string(string_of(dex_idx, fid.name_idx)),
        std::string(type_descriptor_of(dex_idx, fid.type_idx)),
    };
}

} // namespace detail

} // namespace dexsplit
