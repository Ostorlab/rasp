/// Platform clock adapter using the shared checked POSIX implementation.
#include "rasp/posix/cycle_clock.h"

#include "rasp/cycle.h"
namespace rasp {
CycleClockReading read_cycle_clock() { return posix::read_cycle_clock(); }
}  // namespace rasp
