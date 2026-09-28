#ifndef RASP_INTEGRITY_H
#define RASP_INTEGRITY_H

#include "hardening.h"
#include "literals.h"

#include <stddef.h>
#include <stdint.h>

#include "sha256.h"

/* Runtime code-integrity root (design §8).
 *
 * Computes the guard-mesh root over byte ranges of the file at `path`:
 *   acc = SHA256("raxp/guard-mesh/v1"); for each region: acc = SHA256(acc || SHA256(region bytes)).
 * This mirrors the hardener's codehash.so_integrity_root / guardmesh.guard_root over the same file and the
 * same regions, so the device's runtime root equals the build-time root registered with the trust service.
 * The report is then sealed with HMAC(build_key, root) (see rasp_guard_fold_key), so a tampered `.so` derives
 * a different key and the trust service refuses the report — fail-closed with no on-device branch.
 *
 * Region bytes are streamed from the file, so a large `.text` need not be held in memory. Hashing the file
 * (not mapped memory) makes the root independent of load-time relocations. Returns 0 on success, -1 on any
 * argument or file/seek/read error. */

typedef struct {
    uint64_t offset;
    uint64_t length;
} rasp_file_region_t;

int rasp_integrity_root_from_file(const char *path, const rasp_file_region_t *regions, size_t count,
                                  uint8_t out[RASP_SHA256_DIGEST_LEN]);

#endif
