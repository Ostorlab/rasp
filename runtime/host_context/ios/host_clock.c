/// Optional Apple host boundaries; public continuous clock and main-thread identity only.
#include <mach/kern_return.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "../src/clock_math.h"
#include "rasp/host_events.h"

int32_t rasp_host_clock_v1(int64_t* out) {
  if (out == NULL) {
    return 0;
  }
  mach_timebase_info_data_t base = {0};
  if (mach_timebase_info(&base) != KERN_SUCCESS || base.numer == 0 || base.denom == 0) {
    return 0;
  }
  return rasp_host_clock_convert(mach_continuous_time(),
                                 (struct RaspHostTimebase){.numerator = base.numer, .denominator = base.denom}, out);
}
int32_t rasp_host_is_owner_thread_v1(void) { return pthread_main_np() == 1 ? 1 : 0; }
