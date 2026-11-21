#include <array>
#include <cstdint>

#include "config/slot_storage.h"
#include "config/slots.h"

namespace rasp::android::config {

const std::array<volatile std::uint8_t, kDigestSlotSize> kDigestSlot{
    0x9c, 'R', 'A', 'S', 'P', 'S', 'L', 'T', 'd', 'i', 'g', 'e', 's', 't',
};

}  // namespace rasp::android::config
