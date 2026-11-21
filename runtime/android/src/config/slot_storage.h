/// The slots the packer writes the runtime's per-app values into. Each lives in a translation unit of its own.

#pragma once

#include <array>
#include <cstdint>

#include "config/slots.h"

namespace rasp::android::config {

extern const std::array<volatile std::uint8_t, kBuildIdSlotSize> kBuildIdSlot;
extern const std::array<volatile std::uint8_t, kChecksSlotSize> kChecksSlot;
extern const std::array<volatile std::uint8_t, kProgramSlotSize> kProgramSlot;
extern const std::array<volatile std::uint8_t, kDigestSlotSize> kDigestSlot;
extern const std::array<volatile std::uint8_t, kPadSlotSize> kPadSlot;
extern const std::array<volatile std::uint8_t, kDecoySlotSize> kDecoySlot0;
extern const std::array<volatile std::uint8_t, kDecoySlotSize> kDecoySlot1;
extern const std::array<volatile std::uint8_t, kDecoySlotSize> kDecoySlot2;
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the packer writes it in the file.
extern std::array<volatile std::uint8_t, kShareSlotSize> share_slot;

}  // namespace rasp::android::config
