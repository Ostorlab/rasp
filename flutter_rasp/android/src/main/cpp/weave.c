#include "weave.h"
#include <string.h>

static rasp_region_t weave_regions[16];
static size_t weave_count;
static uint8_t weave_expected[32];

int rasp_weave_configure(const rasp_region_t *regions, size_t count, const uint8_t expected_root[32]) {
    weave_count = 0;
    if (regions == NULL || expected_root == NULL || count == 0 || count > 16) return -1;
    for (size_t i = 0; i < count; i++) {
        if (regions[i].data == NULL || regions[i].len == 0) return -1;
        weave_regions[i] = regions[i];
    }
    memcpy(weave_expected, expected_root, 32);
    weave_count = count;
    return 0;
}

uint64_t rasp_guard_probe(uint64_t site) {
    if (weave_count == 0) return UINT64_MAX;
    uint8_t current[32];
    rasp_guard_root(weave_regions, weave_count, current);
    uint64_t difference = 0;
    for (size_t i = 0; i < 32; i++) difference |= (uint64_t)(current[i] ^ weave_expected[i]) << ((i % 8) * 8);
    /* Odd multiplication is invertible modulo 2^64: nonzero differences remain nonzero. */
    return (difference * (site | UINT64_C(1))) | (uint64_t)(difference != 0);
}
