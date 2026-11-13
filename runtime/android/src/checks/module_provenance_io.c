/// Fixed-signature POSIX open boundary; keeps variadic libc APIs out of the C++ collector.
#include "module_provenance_io.h"

#include <errno.h>
#include <fcntl.h>

/// Opens only the collector's own process maps with nonblocking/close-on-exec semantics.
__attribute__((visibility("hidden"))) int rasp_module_open_maps(void) {
  const int descriptor = open("/proc/self/maps", O_RDONLY | O_CLOEXEC | O_NONBLOCK);
  return descriptor < 0 ? -errno : descriptor;
}
