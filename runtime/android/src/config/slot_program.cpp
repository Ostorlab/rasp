#include <array>
#include <cstdint>

#include "config/slot_storage.h"
#include "config/slots.h"

namespace rasp::android::config {

const std::array<volatile std::uint8_t, kProgramSlotSize> kProgramSlot{
    0x9c, 'R', 'A', 'S', 'P', 'S', 'L', 'T', 'p', 'r', 'o', 'g', 'r', 'a', 'm',
};

}  // namespace rasp::android::config
