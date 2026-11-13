#include "analysis_context.hpp"

#include "analysis_context_impl.hpp"
#include "common/budget.hpp"
#include "model/io.hpp"
#include "raw/parser.hpp"

namespace dexsplit {

using detail::AnalysisContextImpl;
using detail::ManagedBuffer;

AnalysisContext::AnalysisContext(std::shared_ptr<AnalysisContextImpl> impl) : impl_(std::move(impl)) {}

// The analysis layer never eagerly decodes the string pool; string_of()
// decodes and caches each string on first use.
static constexpr raw::parser::ParseOptions kLazyParse{.decode_strings = false};

std::expected<AnalysisContext, budget::String> AnalysisContext::from_dex_buffers(
    const budget::Vector<std::span<const uint8_t>>& buffers) {
  budget::Scope scope;
  if (buffers.size() > budget::kFiles) {
    return std::unexpected("DEX file count limit");
  }
  std::size_t total = 0;
  budget::Vector<model::Dex> models;
  for (const auto& bytes : buffers) {
    budget::visit();
    if (bytes.size() > budget::kDexBytes || bytes.size() > budget::kTotalBytes - total) {
      return std::unexpected("DEX input byte limit");
    }
    total += bytes.size();
    auto result = model::read(bytes);
    if (!result) {
      return std::unexpected(result.error().message);
    }
    models.push_back(std::move(*result));
  }
  budget::Vector<const model::Dex*> pointers;
  for (const auto& model : models) {
    pointers.push_back(&model);
  }
  return from_models(pointers);
}

std::expected<AnalysisContext, budget::String> AnalysisContext::from_models(
    const budget::Vector<const model::Dex*>& models) {
  budget::Scope scope(models.empty() || models.front() == nullptr ? nullptr : models.front()->request);
  if (models.size() > budget::kFiles) {
    return std::unexpected("DEX file count limit");
  }
  auto impl = budget::make_shared<AnalysisContextImpl>();
  for (const auto* model : models) {
    budget::visit();
    if (model == nullptr || model->original == nullptr) {
      return std::unexpected("analysis requires a fully read immutable model source");
    }
    if (model->request != budget::active) {
      return std::unexpected("analyze models from one Request");
    }
    const auto& bytes = *model->original;
    ManagedBuffer buffer(budget::Vector<uint8_t>(bytes.begin(), bytes.end()));
    auto dex = raw::parser::parse_buffer(buffer.bytes(), kLazyParse);
    if (!dex) {
      return std::unexpected(dex.error().message);
    }
    dex->compact_for_analysis();
    impl->dex_files_vec.push_back(std::move(*dex));
    impl->slots.push_back(budget::make_shared<AnalysisContextImpl::DexSlot>(std::move(buffer)));
  }
  return AnalysisContext(std::move(impl));
}

budget::Vector<Class> AnalysisContext::classes() const {
  budget::Scope scope(impl_->request);
  budget::Vector<Class> result;
  for (std::size_t i = 0; i < impl_->dex_files_vec.size(); ++i) {
    dexsplit::budget::visit();
    const auto& dex = impl_->dex_files_vec[i];
    for (uint32_t j = 0; j < static_cast<uint32_t>(dex.class_defs().size()); ++j) {
      dexsplit::budget::visit();
      result.emplace_back(impl_, DexIndex{i}, j);
    }
  }
  return result;
}

namespace detail {

std::span<const uint8_t> AnalysisContextImpl::buffer_of(DexIndex dex_idx) const {
  return slots[dex_idx.value]->buffer.bytes();
}

std::string_view AnalysisContextImpl::string_of(DexIndex dex_idx, uint32_t string_idx) const {
  auto string_ids = dex_files_vec[dex_idx.value].string_ids();
  if (string_idx >= string_ids.size()) {
    return {};
  }

  auto& slot = *slots[dex_idx.value];
  std::lock_guard<std::mutex> lock(slot.strings_mutex);

  auto it = slot.string_cache.find(string_idx);
  if (it != slot.string_cache.end()) {
    return it->second;
  }

  uint32_t data_off = string_ids[string_idx];
  budget::String value;
  if (auto r = raw::parser::parse_string(slot.buffer.bytes(), data_off); r.has_value()) {
    value = std::move(r->first);
  }

  auto [ins, _] = slot.string_cache.emplace(string_idx, std::move(value));
  return ins->second;
}

std::string_view AnalysisContextImpl::type_descriptor_of(DexIndex dex_idx, uint32_t type_idx) const {
  auto type_ids = dex_files_vec[dex_idx.value].type_ids();
  if (type_idx >= type_ids.size()) {
    return {};
  }
  return string_of(dex_idx, type_ids[type_idx]);
}

const raw::MethodIdItem* AnalysisContextImpl::method_item(DexIndex dex_idx, uint32_t method_index) const {
  auto items = dex_files_vec[dex_idx.value].method_ids();
  return method_index < items.size() ? &items[method_index] : nullptr;
}

const raw::FieldIdItem* AnalysisContextImpl::field_item(DexIndex dex_idx, uint32_t field_index) const {
  auto items = dex_files_vec[dex_idx.value].field_ids();
  return field_index < items.size() ? &items[field_index] : nullptr;
}

const raw::ProtoIdItem* AnalysisContextImpl::proto_item(DexIndex dex_idx, uint32_t proto_index) const {
  auto items = dex_files_vec[dex_idx.value].proto_ids();
  return proto_index < items.size() ? &items[proto_index] : nullptr;
}

const raw::ClassDataItem* AnalysisContextImpl::get_class_data(DexIndex dex_idx, uint32_t class_data_off) const {
  if (class_data_off == 0) {
    return nullptr;
  }

  auto& slot = *slots[dex_idx.value];
  std::lock_guard<std::mutex> lock(slot.class_data_mutex);

  auto it = slot.class_data_cache.find(class_data_off);
  if (it != slot.class_data_cache.end()) {
    return &it->second;
  }

  auto result = raw::parser::parse_class_data(slot.buffer.bytes(), class_data_off);
  if (!result.has_value()) {
    return nullptr;
  }

  auto [ins_it, ok] = slot.class_data_cache.emplace(class_data_off, std::move(result.value()));
  return &ins_it->second;
}

std::span<const Instruction> AnalysisContextImpl::get_instructions(DexIndex dex_idx, uint32_t code_off) const {
  if (code_off == 0) {
    return {};
  }

  const auto units = dex_files_vec[dex_idx.value].instruction_units(code_off);
  if (units == 0) {
    return {};
  }

  auto& slot = *slots[dex_idx.value];
  std::lock_guard<std::mutex> lock(slot.instructions_mutex);

  auto it = slot.instructions_cache.find(code_off);
  if (it != slot.instructions_cache.end()) {
    return it->second;
  }

  // The extent was structurally validated against these same privately owned immutable bytes.
  const auto bytes = slot.buffer.bytes();
  const auto start = static_cast<std::size_t>(code_off) + 16;
  if (start > bytes.size() || units > (bytes.size() - start) / 2) {
    throw std::invalid_argument("validated instruction extent is outside its owned buffer");
  }
  budget::Vector<uint16_t> words(units);
  for (uint32_t i = 0; i < units; ++i) {
    budget::visit();
    const auto at = start + 2 * static_cast<std::size_t>(i);
    words[i] = static_cast<uint16_t>(bytes[at] | (uint32_t{bytes[at + 1U]} << 8U));
  }
  auto [ins_it, ok] = slot.instructions_cache.emplace(code_off, decode_instructions(words));
  return ins_it->second;
}

const budget::String& AnalysisContextImpl::proto_descriptor_of(DexIndex dex_idx, uint32_t proto_idx) const {
  static const budget::String kEmpty{budget::Allocator<char>{nullptr}};
  auto proto_ids = dex_files_vec[dex_idx.value].proto_ids();
  if (proto_idx >= proto_ids.size()) {
    return kEmpty;
  }

  uint64_t key = (static_cast<uint64_t>(dex_idx.value) << 32U) | proto_idx;
  {
    std::lock_guard<std::mutex> lock(proto_cache_mutex);
    if (auto it = proto_descriptor_cache.find(key); it != proto_descriptor_cache.end()) {
      return it->second;
    }
  }

  budget::String out = build_proto_descriptor(dex_idx, proto_idx);

  std::lock_guard<std::mutex> lock(proto_cache_mutex);
  return proto_descriptor_cache.emplace(key, std::move(out)).first->second;
}

budget::String AnalysisContextImpl::build_proto_descriptor(DexIndex dex_idx, uint32_t proto_idx) const {
  const auto* proto = proto_item(dex_idx, proto_idx);
  if (!proto) {
    return {};
  }

  budget::String out;
  out.push_back('(');
  if (proto->parameters_off != 0) {
    auto type_list = raw::parser::parse_type_list(buffer_of(dex_idx), proto->parameters_off);
    if (type_list.has_value()) {
      for (auto type_idx : type_list->type_ids) {
        dexsplit::budget::visit();
        out.append(type_descriptor_of(dex_idx, type_idx));
      }
    } else {
      out.append("<unparseable>");
    }
  }
  out.push_back(')');
  out.append(type_descriptor_of(dex_idx, proto->return_type_idx));
  return out;
}

MethodId AnalysisContextImpl::method_id_of(DexIndex dex_idx, uint32_t method_index) const {
  auto method_ids = dex_files_vec[dex_idx.value].method_ids();
  if (method_index >= method_ids.size()) {
    return MethodId{};
  }
  const auto& mid = method_ids[method_index];
  return MethodId{
      budget::String(type_descriptor_of(dex_idx, mid.class_idx)),
      budget::String(string_of(dex_idx, mid.name_idx)),
      proto_descriptor_of(dex_idx, mid.proto_idx),
  };
}

FieldId AnalysisContextImpl::field_id_of(DexIndex dex_idx, uint32_t field_index) const {
  auto field_ids = dex_files_vec[dex_idx.value].field_ids();
  if (field_index >= field_ids.size()) {
    return FieldId{};
  }
  const auto& fid = field_ids[field_index];
  return FieldId{
      budget::String(type_descriptor_of(dex_idx, fid.class_idx)),
      budget::String(string_of(dex_idx, fid.name_idx)),
      budget::String(type_descriptor_of(dex_idx, fid.type_idx)),
  };
}

}  // namespace detail

}  // namespace dexsplit
