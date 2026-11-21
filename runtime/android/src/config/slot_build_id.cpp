#include <array>
#include <cstdint>

#include "config/slot_storage.h"
#include "config/slots.h"

namespace rasp::android::config {

const std::array<volatile std::uint8_t, kBuildIdSlotSize> kBuildIdSlot{
    0x9c, 'R', 'A', 'S', 'P', 'S', 'L', 'T', 'b', 'u', 'i', 'l', 'd',
};

}  // namespace rasp::android::config
