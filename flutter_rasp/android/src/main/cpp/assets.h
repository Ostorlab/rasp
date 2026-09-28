#ifndef RASP_ASSETS_H
#define RASP_ASSETS_H
#include "guard.h"
/* Tables are generated for the expected integrity root. The live root is computed
 * from readable regions on each open and derives an independent authentication key.
 * Return plaintext length, or -1 with out untouched. In/out must not overlap. */
int rasp_asset_open(const uint32_t *type2, const uint8_t *last, const uint8_t base_key[32],
                    const rasp_region_t *regions, size_t region_count, const char *identity,
                    const uint8_t *package, size_t package_len, uint8_t *out, size_t out_len);
/* Authenticate and execute a packaged arithmetic VM artifact (opcode table || code).
 * Never executes unauthenticated bytecode; result remains untouched on failure. */
int rasp_asset_vm_run(const uint32_t *type2, const uint8_t *last, const uint8_t base_key[32],
                      const rasp_region_t *regions, size_t region_count, const char *identity,
                      const uint8_t *package, size_t package_len, const uint32_t inputs[8],
                      uint32_t max_steps, uint32_t *result);
#endif
