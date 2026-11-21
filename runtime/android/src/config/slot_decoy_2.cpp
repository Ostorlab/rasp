#include <array>
#include <cstdint>

#include "config/slot_storage.h"
#include "config/slots.h"

namespace rasp::android::config {

const std::array<volatile std::uint8_t, kDecoySlotSize> kDecoySlot2{
    0x9c, 'R', 'A', 'S', 'P', 'S', 'L', 'T', 'd', 'e', 'c', 'o', 'y', '2',
};

}  // namespace rasp::android::config
