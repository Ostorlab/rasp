/// Canonical little-endian manifest codec for the supported little-endian ABI1 targets.
#include "manifest.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <span>

#include "encoding.h"

namespace rasp::keys {
namespace {
constexpr std::array<std::uint8_t, 8> kMagic{'R', 'A', 'S', 'P', 'S', 'K', '0', '1'};
constexpr std::size_t kRecordsOffset = 96;
constexpr std::size_t kDigestOffset = kManifestBytes - 32;
static_assert(sizeof(Record) == 248 && std::endian::native == std::endian::little);
/// All non-record bytes are validated rather than ignored as extension points.
bool zero(std::span<const std::uint8_t> input) {
  return std::ranges::all_of(input, [](auto value) { return value == 0; });
}
}  // namespace
bool encode_manifest(const Manifest& manifest, std::span<std::uint8_t> output) {
  if (output.size() != kManifestBytes || !nonzero(manifest.generation)) {
    return false;
  }
  std::ranges::fill(output, 0);
  std::ranges::copy(kMagic, output.begin());
  output[8] = 1;
  output[13] = 32;
  std::memcpy(output.subspan(16).data(), std::span(manifest.generation.bytes).data(), 16);
  std::ranges::copy(manifest.application_sha256, output.subspan(32).begin());
  std::uint8_t count = 0;
  for (std::size_t index = 0; index < manifest.records.size(); ++index) {
    const auto& record = std::span(manifest.records)[index];
    if (record.state != KeyState::kEmpty) {
      ++count;
    }
    std::memcpy(output.subspan(kRecordsOffset + (index * sizeof(Record))).data(), &record, sizeof(record));
  }
  output[64] = count;
  return digest(output.first(kDigestOffset), std::span<std::uint8_t, 32>(output.last<32>()));
}
bool decode_manifest(std::span<const std::uint8_t> input, Manifest& output) {
  std::memset(&output, 0, sizeof(output));
  std::array<std::uint8_t, 32> hash{};
  if (input.size() != kManifestBytes || !std::ranges::equal(input.first<8>(), kMagic) || input[8] != 1 ||
      !zero(input.subspan(9, 4)) || input[13] != 32 || !zero(input.subspan(14, 2)) || !zero(input.subspan(65, 31)) ||
      !zero(input.subspan(kRecordsOffset + (32 * sizeof(Record)),
                          kDigestOffset - kRecordsOffset - (32 * sizeof(Record)))) ||
      !digest(input.first(kDigestOffset), hash) || !std::ranges::equal(hash, input.last<32>())) {
    return false;
  }
  std::memcpy(std::span(output.generation.bytes).data(), input.subspan(16).data(), 16);
  std::ranges::copy(input.subspan(32, 32), output.application_sha256.begin());
  std::uint8_t count = 0;
  for (std::size_t index = 0; index < output.records.size(); ++index) {
    auto& record = std::span(output.records)[index];
    std::memcpy(&record, input.subspan(kRecordsOffset + (index * sizeof(Record))).data(), sizeof(record));
    if (record.state != KeyState::kEmpty) {
      if (record.state != KeyState::kReserved && record.state != KeyState::kLive &&
          record.state != KeyState::kDeletePending) {
        return false;
      }
      if (!nonzero(record.info.key_id) || record.reserved != 0 || !zero(record.state_padding)) {
        return false;
      }
      for (std::size_t prior = 0; prior < index; ++prior) {
        if (same(record.info.key_id, std::span(output.records)[prior].info.key_id)) {
          return false;
        }
      }
      ++count;
    } else if (!zero(input.subspan(kRecordsOffset + (index * sizeof(Record)), sizeof(Record)))) {
      return false;
    }
  }
  return nonzero(output.generation) && count == input[64];
}
}  // namespace rasp::keys
