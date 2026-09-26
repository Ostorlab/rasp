#ifndef RASP_SIGNALS_H
#define RASP_SIGNALS_H

#include <stddef.h>

#define RASP_MAX_SIGNALS 64
#define RASP_EVIDENCE_LEN 160

/* Threat classes shared with the Kotlin layer (see ThreatType.kt). */
typedef enum {
    RASP_THREAT_ROOT = 0,
    RASP_THREAT_EMULATOR = 1,
    RASP_THREAT_DEBUGGER = 2,
    RASP_THREAT_HOOKING = 3,
} rasp_threat_t;

typedef struct {
    rasp_threat_t threat;
    const char *detector;
    int confidence; /* 0-100 */
    char evidence[RASP_EVIDENCE_LEN];
} rasp_signal_t;

typedef struct {
    rasp_signal_t items[RASP_MAX_SIGNALS];
    size_t count;
} rasp_signal_list_t;

void rasp_signals_add(rasp_signal_list_t *list, rasp_threat_t threat,
                      const char *detector, int confidence,
                      const char *evidence);

/* Serializes the list as a JSON array. Returns bytes written, or -1 if the buffer is too small. */
int rasp_signals_to_json(const rasp_signal_list_t *list, char *out, size_t out_len);

#endif
