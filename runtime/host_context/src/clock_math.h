/// Private host-source checked integer conversion; not a runtime export or public event field.
#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/// Named positive clock ratio, normally supplied by the platform, never an event.
struct RaspHostTimebase {
  /// Numerator and denominator; zero is unavailable.
  uint32_t numerator, denominator;
};
/// Convert without intermediate overflow; floor fractional nanoseconds.
/// @param ticks Unsigned OS ticks. @param base Nonzero OS ratio. @param out Borrowed writable result.
/// @return1 for a nonnegative signed64 result, otherwise0 with no valid output.
__attribute__((visibility("hidden"))) int32_t rasp_host_clock_convert(uint64_t ticks, struct RaspHostTimebase base,
                                                                      int64_t* out);
#ifdef __cplusplus
}
#endif
