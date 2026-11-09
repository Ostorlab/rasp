/// Builds and reads the dex store: parses the decrypted class map into an index, and reads and decrypts one dex on
/// demand. The map, the keys, the reads, and the decryption all stay in native code, and the decrypted map is wiped
/// once it is indexed.

#include "payload/dex_store.h"

#include <array>
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
#include "payload/key_schedule.h"
#include "rasp/util/obfuscation.h"

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

/// The frame key of the encrypted entry `frame` holds, derived for `entry`.
///
/// @param master The stage's master key: the root for the map, the guarded master for a dex.
/// @param frame The frame, which starts with its nonce.
/// @param entry The frame's full APK entry name.
/// @return The frame key. Nothing when the frame is too short to hold a nonce, or the derivation fails.
[[nodiscard]] std::optional<Key> key_of(const Key& master, std::span<const std::uint8_t> frame,
                                        std::string_view entry) {
  if (frame.size() < kNonceSize + kTagSize) {
    return std::nullopt;
  }
  return frame_key(master, frame.first(kNonceSize), entry);
}

}  // namespace

std::optional<DexStore> open_dex_store(std::string apk, const Key& root) {
  static constexpr std::array<std::string_view, 3> kObfuscatedLiterals = {kMapEntry, kJProgramEntry, kAssetPrefix};
  rasp::util::anchor_literals(kObfuscatedLiterals);
  const std::optional<std::vector<std::uint8_t>> frame = rasp::android::apk::read_stored_entry(apk, kMapEntry);
  if (!frame.has_value()) {
    return std::nullopt;
  }
  const std::optional<Key> map_key = key_of(root, *frame, kMapEntry);
  if (!map_key.has_value()) {
    return std::nullopt;
  }
  std::optional<std::vector<std::uint8_t>> map = decrypt(*map_key, *frame);
  if (!map.has_value()) {
    return std::nullopt;
  }
  const std::optional<Key> seed = seed_from(root, *frame);
  if (!seed.has_value()) {
    return std::nullopt;
  }

  DexStore store;
  store.apk = std::move(apk);
  store.seed = *seed;
  // The Java program is sealed under the root like the map: the loader needs it before the stub can arm. An app the
  // packer built without one ships no entry, and its store then arms from a zero share.
  const std::optional<std::vector<std::uint8_t>> program_frame =
      rasp::android::apk::read_stored_entry(store.apk, kJProgramEntry);
  if (program_frame.has_value()) {
    const std::optional<Key> program_key = key_of(root, *program_frame, kJProgramEntry);
    std::optional<std::vector<std::uint8_t>> program =
        program_key.has_value() ? decrypt(*program_key, *program_frame) : std::nullopt;
    if (program.has_value()) {
      store.j_program = std::move(*program);
    }
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  index_map(std::string_view(reinterpret_cast<const char*>(map->data()), map->size()), store);
  wipe(*map);
  return store;
}

void arm_j_store(DexStore& store, const Key& j_share) {
  const std::optional<Key> armed = armed_master(store.seed, j_share);
  if (armed.has_value()) {
    store.armed = *armed;
  }
}

const EncryptedDex* dex_of(const DexStore& store, const std::string& class_name) {
  const auto found = store.dex_of_class.find(class_name);
  if (found == store.dex_of_class.end() || found->second >= store.dexes.size()) {
    return nullptr;
  }
  return &store.dexes[found->second];
}

std::optional<std::vector<std::uint8_t>> decrypt_dex(const DexStore& store, const EncryptedDex& dex) {
  if (!store.armed.has_value()) {
    return std::nullopt;
  }
  const std::optional<std::vector<std::uint8_t>> frame = rasp::android::apk::read_stored_entry(store.apk, dex.entry);
  if (!frame.has_value()) {
    return std::nullopt;
  }
  const Sensors sensors = observe_sensors();
  const std::optional<Key> master = guarded_master(*store.armed, sensor_block(sensors));
  if (!master.has_value()) {
    return std::nullopt;
  }
  const std::optional<Key> key = key_of(*master, *frame, dex.entry);
  if (!key.has_value()) {
    return std::nullopt;
  }
  return decrypt(*key, *frame);
}

}  // namespace rasp::android::payload
