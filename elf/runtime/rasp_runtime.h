#ifndef RASP_RUNTIME_H
#define RASP_RUNTIME_H
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Fresh local scan and backend authorization of these exact payload bytes.
 * Returns 0 on allow, -1 (errno EACCES/EINVAL) on deny or invalid input.
 * Calls must originate in the initializing process; fork is unsupported. */
__attribute__((visibility("default"))) int rasp_checkpoint(const void *payload, size_t length);
/* Prepare signed checkpoint evidence for forwarding with the exact request
 * payload to a customer backend. Obtains a fresh challenge but does not call
 * /v1/authorize or consume the nonce. The backend must verify before acting.
 * Returns the positive document byte count (including final LF, excluding NUL)
 * or -1. Output is NUL-terminated; provide 8192 bytes for all supported evidence.
 * Requires an online endpoint and clean local scan. Invalid inputs, offline,
 * threats, transport failure, insufficient capacity, and fork return failure.
 * A valid nonempty output buffer is cleared on failure. */
__attribute__((visibility("default"))) int rasp_prepare_request(const void *payload, size_t length, char *evidence, size_t capacity);
#ifdef __cplusplus
}
#endif
#endif
