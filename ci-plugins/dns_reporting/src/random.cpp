/// Portable random-byte fill: getrandom on Linux/Android, arc4random_buf on Apple.

#include "random.h"

#include <cstddef>
#include <cstdint>
#ifdef __APPLE__
#include <cstdlib>
#else
#include <cerrno>
#include <sys/random.h>
#endif

namespace rasp::plugins::dns_reporting {

bool fill_random(std::uint8_t* buf, std::size_t len) {
#ifdef __APPLE__
  arc4random_buf(buf, len);
  return true;
#else
  std::size_t done = 0;
  while (done < len) {
    const ssize_t n = getrandom(buf + done, len - done, 0);  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return false;
    }
    done += static_cast<std::size_t>(n);
  }
  return true;
#endif
}

}  // namespace rasp::plugins::dns_reporting
