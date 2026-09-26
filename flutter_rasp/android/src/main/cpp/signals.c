#include "signals.h"

#include <stdio.h>
#include <string.h>

void rasp_signals_add(rasp_signal_list_t *list, rasp_threat_t threat,
                      const char *detector, int confidence,
                      const char *evidence) {
    if (list->count >= RASP_MAX_SIGNALS) {
        return;
    }
    /* One signal per detector is enough; the first evidence found is kept. */
    for (size_t i = 0; i < list->count; i++) {
        if (strcmp(list->items[i].detector, detector) == 0) {
            return;
        }
    }
    rasp_signal_t *signal = &list->items[list->count++];
    signal->threat = threat;
    signal->detector = detector;
    signal->confidence = confidence;
    snprintf(signal->evidence, sizeof(signal->evidence), "%s", evidence ? evidence : "");
}

/* Writes `value` as a JSON string body, escaping quotes, backslashes and control characters. */
static int append_escaped(char *out, size_t out_len, size_t *pos, const char *value) {
    for (const char *c = value; *c; c++) {
        char escaped[8];
        unsigned char ch = (unsigned char)*c;
        if (ch == '"' || ch == '\\') {
            snprintf(escaped, sizeof(escaped), "\\%c", ch);
        } else if (ch < 0x20) {
            snprintf(escaped, sizeof(escaped), "\\u%04x", ch);
        } else {
            escaped[0] = (char)ch;
            escaped[1] = '\0';
        }
        size_t len = strlen(escaped);
        if (*pos + len >= out_len) {
            return -1;
        }
        memcpy(out + *pos, escaped, len);
        *pos += len;
    }
    return 0;
}

static int append_raw(char *out, size_t out_len, size_t *pos, const char *value) {
    size_t len = strlen(value);
    if (*pos + len >= out_len) {
        return -1;
    }
    memcpy(out + *pos, value, len);
    *pos += len;
    return 0;
}

int rasp_signals_to_json(const rasp_signal_list_t *list, char *out, size_t out_len) {
    size_t pos = 0;
    char number[48];

    if (append_raw(out, out_len, &pos, "[") < 0) {
        return -1;
    }
    for (size_t i = 0; i < list->count; i++) {
        const rasp_signal_t *signal = &list->items[i];
        snprintf(number, sizeof(number), "{\"threat\":%d,\"confidence\":%d,", signal->threat,
                 signal->confidence);
        if ((i > 0 && append_raw(out, out_len, &pos, ",") < 0) ||
            append_raw(out, out_len, &pos, number) < 0 ||
            append_raw(out, out_len, &pos, "\"detector\":\"") < 0 ||
            append_escaped(out, out_len, &pos, signal->detector) < 0 ||
            append_raw(out, out_len, &pos, "\",\"evidence\":\"") < 0 ||
            append_escaped(out, out_len, &pos, signal->evidence) < 0 ||
            append_raw(out, out_len, &pos, "\"}") < 0) {
            return -1;
        }
    }
    if (append_raw(out, out_len, &pos, "]") < 0) {
        return -1;
    }
    out[pos] = '\0';
    return (int)pos;
}
