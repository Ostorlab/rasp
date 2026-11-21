#include <array>
#include <cstdint>

#include "config/slot_storage.h"
#include "config/slots.h"

namespace rasp::android::config {

const std::array<volatile std::uint8_t, kPadSlotSize> kPadSlot{
    0x9c, 'R', 'A', 'S', 'P', 'S', 'L', 'T', 'p', 'a', 'd',
};

}  // namespace rasp::android::config
