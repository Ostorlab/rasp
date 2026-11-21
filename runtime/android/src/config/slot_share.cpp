#include <array>
#include <cstdint>

#include "config/slot_storage.h"
#include "config/slots.h"

namespace rasp::android::config {

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the packer writes it in the file.
std::array<volatile std::uint8_t, kShareSlotSize> share_slot{
    0x9c, 'R', 'A', 'S', 'P', 'S', 'L', 'T', 's', 'h', 'a', 'r', 'e',
};

}  // namespace rasp::android::config
