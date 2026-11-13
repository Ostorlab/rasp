/// Builds and reads the dex store: parses the decrypted class map into an index, and reads and decrypts one dex on
/// demand. The map, the key, the read, and the decrypt all stay in native code.

#include "payload/dex_store.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "apk/archive.h"
#include "payload/assets.h"
#include "payload/cipher.h"

namespace rasp::android::payload {

namespace {

/// Indexes the decrypted class map into `store`.
///
/// It adds each dex the map names to `dexes`, with its entry name and its classes, and the dex index of each class to
/// `dex_of_class`. See open_dex_store for the line format and the skip and first-wins rules.
///
/// @param text The decrypted map text.
/// @param store The store to fill.
void index_map(std::string_view text, DexStore& store) {
  std::unordered_map<std::string, std::size_t> index_of_path;
  for (const auto piece : std::views::split(text, '\n')) {
    const std::string_view line(piece.begin(), piece.end());
    const std::size_t comma = line.find(',');
    if (comma == std::string_view::npos || comma == 0 || comma + 1 == line.size()) {
      continue;
    }
    const std::string_view name = line.substr(0, comma);
    const std::string_view path = line.substr(comma + 1);

    const auto [slot, added] = index_of_path.try_emplace(std::string(path), store.dexes.size());
    if (added) {
      store.dexes.push_back(EncryptedDex{.entry = std::string(kAssetPrefix) + std::string(path), .classes = {}});
    }
    const std::size_t index = slot->second;
    if (store.dex_of_class.try_emplace(std::string(name), index).second) {
      store.dexes[index].classes.emplace_back(name);
    }
  }
}

}  // namespace

std::optional<DexStore> open_dex_store(std::string apk, std::span<const std::uint8_t> key) {
  const std::optional<std::vector<std::uint8_t>> frame = rasp::android::apk::read_stored_entry(apk, kMapEntry);
  if (!frame.has_value()) {
    return std::nullopt;
  }
  const std::optional<std::vector<std::uint8_t>> map = decrypt(key, *frame);
  if (!map.has_value()) {
    return std::nullopt;
  }

  DexStore store;
  store.apk = std::move(apk);
  store.key.assign(key.begin(), key.end());
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  index_map(std::string_view(reinterpret_cast<const char*>(map->data()), map->size()), store);
  return store;
}

const EncryptedDex* dex_of(const DexStore& store, const std::string& class_name) {
  const auto found = store.dex_of_class.find(class_name);
  if (found == store.dex_of_class.end() || found->second >= store.dexes.size()) {
    return nullptr;
  }
  return &store.dexes[found->second];
}

std::optional<std::vector<std::uint8_t>> decrypt_dex(const DexStore& store, const EncryptedDex& dex) {
  const std::optional<std::vector<std::uint8_t>> frame = rasp::android::apk::read_stored_entry(store.apk, dex.entry);
  if (!frame.has_value()) {
    return std::nullopt;
  }
  return decrypt(store.key, *frame);
}

}  // namespace rasp::android::payload
