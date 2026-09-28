#ifndef RASP_REPORT_H
#define RASP_REPORT_H

#include "hardening.h"
#include "literals.h"

#include <stddef.h>
#include <stdint.h>

#include "signals.h"

#define RASP_REPORT_VERSION "rasp-report-1"

/* Seals a RASP report for the trust service.
 *
 * Runs every native detector, then serializes a canonical JSON report that carries the build id, the
 * server's challenge nonce, a device timestamp, and the native signals followed by the `managed_signals_json`
 * splice (a compact JSON array `[...]` of managed-layer signals, or NULL/`[]` for none). The exact report
 * bytes are then MAC'd with the per-build key (HMAC-SHA256), and the result is written to `out` as the
 * envelope `{"report":"<canonical>","mac":"<hex>"}`.
 *
 * Returns the number of bytes written (excluding the terminator), or -1 if `out` is too small or the input
 * is malformed. `build_key` is the raw MAC key; `nonce` is base64 as received from the trust service.
 */
int rasp_seal_report(const char *managed_signals_json, const char *nonce, int64_t ts_millis,
                     const char *build_id, const uint8_t *build_key, size_t build_key_len,
                     char *out, size_t out_len);

/* Serializes a signal list as a JSON array with string threat names (report form). Exposed for tests. */
int rasp_signals_to_report_json(const rasp_signal_list_t *list, char *out, size_t out_len);

/* Extracts the inner items of a compact JSON array (`[a,b]` -> `a,b`), trimming surrounding spaces. Returns
 * a pointer into `array_json` and sets `*len`; returns NULL and `*len`=0 for NULL, empty or non-array input.
 * Exposed for tests. */
const char *rasp_json_array_inner(const char *array_json, size_t *len);

#endif
