#ifndef RASP_WEAVE_H
#define RASP_WEAVE_H
#include "guard.h"
/* Configure once before worker threads start. Region bytes must remain readable for
 * the process lifetime; expected_root comes from the trusted build manifest, not
 * from hashing the current potentially modified bytes. At most 16 regions. */
int rasp_weave_configure(const rasp_region_t *regions, size_t count, const uint8_t expected_root[32]);
/* Stable compiler hook (or pass RASP_PROBE_SYMBOL when per-build names are enabled).
 * Returns zero for expected bytes; otherwise a nonzero value folded into results. */
uint64_t rasp_guard_probe(uint64_t site);
#endif
