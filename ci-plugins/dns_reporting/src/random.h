/// Portable random-byte fill: getrandom on Linux/Android, arc4random_buf on Apple.

#pragma once

#include <cstddef>
#include <cstdint>

namespace rasp::plugins::dns_reporting {

/// Fills a buffer with random bytes. Returns false when the entropy source fails.
[[nodiscard]] bool fill_random(std::uint8_t* buf, std::size_t len);

}  // namespace rasp::plugins::dns_reporting
