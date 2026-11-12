/// Optional native Android host clock/main-thread boundaries; not linked into librasp.
#include <linux/time.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

#include "../src/clock_math.h"
#include "rasp/host_events.h"

int32_t rasp_host_clock_v1(int64_t* out) {
  if (out == NULL) {
    return 0;
  }
  struct timespec tick = {0};
  if (clock_gettime(CLOCK_BOOTTIME, &tick) != 0 || tick.tv_sec < 0 || tick.tv_nsec < 0 || tick.tv_nsec >= 1000000000) {
    return 0;
  }
  int64_t integral = 0;
  if (rasp_host_clock_convert((uint64_t)tick.tv_sec,
                              (struct RaspHostTimebase){.numerator = 1000000000, .denominator = 1}, &integral) != 1 ||
      integral > INT64_MAX - tick.tv_nsec) {
    return 0;
  }
  *out = integral + tick.tv_nsec;
  return 1;
}
int32_t rasp_host_is_owner_thread_v1(void) { return gettid() == getpid() ? 1 : 0; }
