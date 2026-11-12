/// Portable test-only OS boundaries. Actual platform implementations compile in platform consumers.
#include <stdint.h>

#include "rasp/host_events.h"

int32_t rasp_host_clock_v1(int64_t* out) {
  *out = 1000000000;
  return 1;
}
int32_t rasp_host_is_owner_thread_v1(void) { return 1; }
