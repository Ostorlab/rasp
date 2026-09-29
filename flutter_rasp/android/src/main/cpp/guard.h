#ifndef RASP_GUARD_H
#define RASP_GUARD_H

#include "hardening.h"
#include "literals.h"

#include <stddef.h>
#include <stdint.h>

#include "sha256.h"

/* Guard mesh: mutually-hashing integrity guards (design §6).
 *
 * Each guard hashes a region of the binary; the guards chain into a single integrity root so the result
 * depends on every region and on their order — patch any guarded region and the root changes. The design's
 * key property is that the root feeds *data, not branches*: it is folded into keys/offsets, so a tampered
 * binary derives the wrong value and fails closed rather than hitting an `if (tampered)` an attacker can flip.
 *
 * `rasp_guard_root` and `rasp_guard_offset` mirror the hardener's guardmesh.py byte-for-byte; the cross-
 * language test asserts they agree over identical regions. */

typedef struct {
    const uint8_t *data;
    size_t len;
} rasp_region_t;

/* Writes the 32-byte integrity root over `count` regions:
 *   acc = SHA256("raxp/guard-mesh/v1"); for each region: acc = SHA256(acc || SHA256(region)). */
void rasp_guard_root(const rasp_region_t *regions, size_t count, uint8_t out[RASP_SHA256_DIGEST_LEN]);

/* Derives an offset in [0, modulus) from the guard root (big-endian over the first 8 bytes). "Results
 * feeding data": a single flipped byte in any region changes the offset. `modulus` must be non-zero. */
uint64_t rasp_guard_offset(const rasp_region_t *regions, size_t count, uint64_t modulus);

/* Integrity-derived key (design §8): out = HMAC-SHA256(base_key, guard_root(regions)). Folding the guard
 * root into the key means a tampered binary derives a different, useless key — the operation (e.g. sealing
 * the report) then fails the server's MAC check with no local "if (tampered)" branch to patch out.
 *
 * The server, which cannot hash the device's memory, derives the same key from the integrity root registered
 * for the build at hardening time (see the hardener's manifest and guardmesh.fold_key). */
void rasp_guard_fold_key(const uint8_t *base_key, size_t base_key_len, const rasp_region_t *regions,
                         size_t count, uint8_t out[RASP_SHA256_DIGEST_LEN]);

#endif
