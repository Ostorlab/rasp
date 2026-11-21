#include "config/slots.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "config/slot_storage.h"
#include "rasp/config.h"

namespace rasp::android::config {

namespace {

/// The magic a slot starts with until the packer writes it.
constexpr std::array<std::uint8_t, 8> kMagic = {0x9C, 'R', 'A', 'S', 'P', 'S', 'L', 'T'};

/// Copies a slot out of its volatile storage, so every byte is read from the library as the packer left it.
template <std::size_t N>
[[nodiscard]] std::array<std::uint8_t, N> copy(const std::array<volatile std::uint8_t, N>& slot) {
  std::array<std::uint8_t, N> bytes{};
  for (std::size_t index = 0; index < N; ++index) {
    bytes.at(index) = slot.at(index);
  }
  return bytes;
}

/// Whether `bytes` still start with the slot magic, so the packer never wrote them.
template <std::size_t N>
[[nodiscard]] bool unwritten(const std::array<std::uint8_t, N>& bytes) {
  for (std::size_t index = 0; index < kMagic.size(); ++index) {
    if (bytes.at(index) != kMagic.at(index)) {
      return false;
    }
  }
  return true;
}

/// A written slot's bytes, or nothing.
template <std::size_t N>
[[nodiscard]] std::optional<std::array<std::uint8_t, N>> written(const std::array<volatile std::uint8_t, N>& slot) {
  const std::array<std::uint8_t, N> bytes = copy(slot);
  if (unwritten(bytes)) {
    return std::nullopt;
  }
  return bytes;
}

template <std::size_t N>
void append(std::vector<std::uint8_t>& out, const std::array<std::uint8_t, N>& bytes) {
  out.insert(out.end(), bytes.begin(), bytes.end());
}

}  // namespace

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters): both are slot byte spans the reader passes in a fixed order.
Config decode_config(std::span<const std::uint8_t> build_id, std::span<const std::uint8_t> checks) {
  Config config;
  for (const std::uint8_t byte : build_id) {
    if (byte == 0) {
      break;
    }
    config.build_id.push_back(static_cast<char>(byte));
  }
  std::uint64_t mask = 0;
  for (std::size_t index = 0; index < sizeof(mask) && index < checks.size(); ++index) {
    mask |= std::uint64_t{checks[index]} << (8U * index);
  }
  config.checks_mask = mask;
  return config;
}

SlotKey unmask_share(const SlotKey& masked, const SlotKey& pad) {
  SlotKey share{};
  for (std::size_t index = 0; index < share.size(); ++index) {
    share.at(index) = static_cast<std::uint8_t>(masked.at(index) ^ pad.at(index));
  }
  return share;
}

Config read_config() {
  const auto build = written(kBuildIdSlot);
  const auto checks = written(kChecksSlot);
  if (!build || !checks) {
    return {};
  }
  return decode_config(*build, *checks);
}

std::optional<std::array<std::uint8_t, kProgramSlotSize>> fold_program() { return written(kProgramSlot); }

std::optional<SlotKey> text_digest() { return written(kDigestSlot); }

std::optional<SlotKey> keystore_share() {
  const auto masked = written(share_slot);
  const auto pad = written(kPadSlot);
  if (!masked || !pad) {
    return std::nullopt;
  }
  return unmask_share(*masked, *pad);
}

std::optional<std::vector<std::uint8_t>> region() {
  const auto build = written(kBuildIdSlot);
  const auto checks = written(kChecksSlot);
  const auto program = written(kProgramSlot);
  const auto digest = written(kDigestSlot);
  const auto pad = written(kPadSlot);
  const auto decoy0 = written(kDecoySlot0);
  const auto decoy1 = written(kDecoySlot1);
  const auto decoy2 = written(kDecoySlot2);
  if (!build || !checks || !program || !digest || !pad || !decoy0 || !decoy1 || !decoy2) {
    return std::nullopt;
  }
  std::vector<std::uint8_t> bytes;
  append(bytes, *build);
  append(bytes, *checks);
  append(bytes, *program);
  append(bytes, *digest);
  append(bytes, *pad);
  append(bytes, *decoy0);
  append(bytes, *decoy1);
  append(bytes, *decoy2);
  return bytes;
}

}  // namespace rasp::android::config
