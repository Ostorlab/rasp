/// Private bounded arithmetic shared by the actual host platform clock adapters.
#include "clock_math.h"

#include <stddef.h>
#include <stdint.h>

int32_t rasp_host_clock_convert(uint64_t ticks, struct RaspHostTimebase base, int64_t* out) {
  if (out == NULL || base.numerator == 0 || base.denominator == 0) {
    return 0;
  }
  const uint64_t whole = ticks / base.denominator;
  const uint64_t remainder = ticks % base.denominator;
  if (whole > (uint64_t)INT64_MAX / base.numerator) {
    return 0;
  }
  const uint64_t integral = whole * base.numerator;
  const uint64_t fraction = remainder * base.numerator / base.denominator;
  if (fraction > (uint64_t)INT64_MAX - integral) {
    return 0;
  }
  *out = (int64_t)(integral + fraction);
  return 1;
}
