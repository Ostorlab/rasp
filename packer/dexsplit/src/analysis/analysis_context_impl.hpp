#include "common/budget.hpp"
#include "dex_index.hpp"
#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "common/ids.hpp"
#include "instruction.hpp"
#include "raw/types.hpp"

namespace dexsplit::detail {

/** Owns a DEX file's bytes on the heap.
 *
 *  The splitter feeds already-decompressed DEX bytes in from memory, so there
 *  is one owner: a heap buffer the context copies in and keeps for its life. */
class ManagedBuffer {
 public:
  ManagedBuffer() = default;
  /** Take ownership of @p heap as this buffer's bytes. */
  explicit ManagedBuffer(budget::Vector<uint8_t> heap) : heap_(std::move(heap)) {}

  /** A read-only view of the owned bytes. */
  std::span<const uint8_t> bytes() const { return {heap_.data(), heap_.size()}; }

 private:
  budget::Vector<uint8_t> heap_;
};

/** Private implementation backing AnalysisContext.  Held via shared_ptr by both
 *  the AnalysisContext wrapper and every handle (Class / Method) derived from
 *  it, so handles stay valid for as long as any reference is alive. */
struct AnalysisContextImpl {
  std::shared_ptr<budget::State> request = budget::active;
  /** One loaded DEX file: its parsed tables, bytes, and the lazy caches the
   *  handles fill on demand. */
  struct DexSlot {
    ManagedBuffer buffer;                                                         ///< The DEX bytes.
    mutable std::mutex class_data_mutex;                                          ///< Guards class_data_cache.
    mutable budget::UnorderedMap<uint32_t, raw::ClassDataItem> class_data_cache;  ///< By offset.
    mutable std::mutex code_item_mutex;                                           ///< Guards code_item_cache.
    mutable budget::UnorderedMap<uint32_t, raw::CodeItem> code_item_cache;        ///< By offset.
    mutable std::mutex instructions_mutex;                                        ///< Guards instructions_cache.
    mutable budget::UnorderedMap<uint32_t, budget::Vector<Instruction>> instructions_cache;  ///< By offset.
    mutable std::mutex strings_mutex;                                                        ///< Guards string_cache.
    mutable budget::UnorderedMap<uint32_t, budget::String> string_cache;  ///< Decoded, by string index.

    /** Wrap an owned DEX buffer in a slot with empty caches. */
    explicit DexSlot(ManagedBuffer buf) : buffer(std::move(buf)) {}
  };

  budget::Vector<raw::DexFile> dex_files_vec;      ///< One parsed DEX per loaded file, in load order.
  budget::Vector<std::shared_ptr<DexSlot>> slots;  ///< Parallel to dex_files_vec.

  /** Full "(...)ret" prototype descriptors, keyed by (dex_idx << 32) | proto_idx. */
  mutable std::mutex proto_cache_mutex;
  mutable budget::UnorderedMap<uint64_t, budget::String> proto_descriptor_cache;

  /** The parsed DEX files, in load order. */
  const budget::Vector<raw::DexFile>& dex_files() const { return dex_files_vec; }

  /** The bytes of DEX file @p dex_idx. */
  std::span<const uint8_t> buffer_of(DexIndex dex_idx) const;

  /** The string at @p string_idx of DEX file @p dex_idx, decoded and cached.
   *  Empty for an out-of-range or malformed index. */
  std::string_view string_of(DexIndex dex_idx, uint32_t string_idx) const;

  /** The type descriptor at @p type_idx of DEX file @p dex_idx.  Empty for an
   *  out-of-range index. */
  std::string_view type_descriptor_of(DexIndex dex_idx, uint32_t type_idx) const;

  /** The method_ids entry at @p method_index, or nullptr when out of range. */
  const raw::MethodIdItem* method_item(DexIndex dex_idx, uint32_t method_index) const;

  /** The field_ids entry at @p field_index, or nullptr when out of range. */
  const raw::FieldIdItem* field_item(DexIndex dex_idx, uint32_t field_index) const;

  /** The proto_ids entry at @p proto_index, or nullptr when out of range. */
  const raw::ProtoIdItem* proto_item(DexIndex dex_idx, uint32_t proto_index) const;

  /** The parsed class_data at @p class_data_off, cached, or nullptr when
   *  @p class_data_off is 0 or the item is malformed. */
  const raw::ClassDataItem* get_class_data(DexIndex dex_idx, uint32_t class_data_off) const;

  /** The parsed code_item at @p code_off, cached, or nullptr when @p code_off
   *  is 0 or the item is malformed. */
  const raw::CodeItem* get_code_item(DexIndex dex_idx, uint32_t code_off) const;

  /** The decoded instructions of the code_item at @p code_off, cached.  Empty
   *  when @p code_off is 0 or the item is malformed. */
  std::span<const Instruction> get_instructions(DexIndex dex_idx, uint32_t code_off) const;

  /** The full prototype descriptor ("(ILjava/lang/String;)V") for
   *  proto_ids[@p proto_idx], cached; the reference lives for the impl's life. */
  const budget::String& proto_descriptor_of(DexIndex dex_idx, uint32_t proto_idx) const;

  /** The same descriptor, built fresh and not cached.  Empty for an
   *  out-of-range proto index. */
  budget::String build_proto_descriptor(DexIndex dex_idx, uint32_t proto_idx) const;

  /** The canonical MethodId for method_ids[@p method_index]. */
  MethodId method_id_of(DexIndex dex_idx, uint32_t method_index) const;

  /** The canonical FieldId for field_ids[@p field_index]. */
  FieldId field_id_of(DexIndex dex_idx, uint32_t field_index) const;
};

}  // namespace dexsplit::detail
