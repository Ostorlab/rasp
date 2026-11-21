#include <array>
#include <cstdint>

#include "config/slot_storage.h"
#include "config/slots.h"

namespace rasp::android::config {

const std::array<volatile std::uint8_t, kChecksSlotSize> kChecksSlot{
    0x9c, 'R', 'A', 'S', 'P', 'S', 'L', 'T', 'c', 'h', 'e', 'c', 'k', 's',
};

}  // namespace rasp::android::config
