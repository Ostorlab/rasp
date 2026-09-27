#include "report.h"

#include <stdio.h>
#include <string.h>

#include "detectors.h"
#include "sha256.h"

/* Appends one signal as {"threat":"name","confidence":N,"detector":"d","evidence":"e"}. */
static int append_signal(char *out, size_t out_len, size_t *pos, const rasp_signal_t *s) {
    char number[96];
    snprintf(number, sizeof(number), "{\"threat\":\"%s\",\"confidence\":%d,\"detector\":\"",
             rasp_threat_name(s->threat), s->confidence);
    return rasp_json_append_raw(out, out_len, pos, number) < 0 ||
                   rasp_json_append_escaped(out, out_len, pos, s->detector) < 0 ||
                   rasp_json_append_raw(out, out_len, pos, "\",\"evidence\":\"") < 0 ||
                   rasp_json_append_escaped(out, out_len, pos, s->evidence) < 0 ||
                   rasp_json_append_raw(out, out_len, pos, "\"}") < 0
               ? -1
               : 0;
}

int rasp_signals_to_report_json(const rasp_signal_list_t *list, char *out, size_t out_len) {
    size_t pos = 0;
    if (rasp_json_append_raw(out, out_len, &pos, "[") < 0) {
        return -1;
    }
    for (size_t i = 0; i < list->count; i++) {
        if ((i > 0 && rasp_json_append_raw(out, out_len, &pos, ",") < 0) ||
            append_signal(out, out_len, &pos, &list->items[i]) < 0) {
            return -1;
        }
    }
    if (rasp_json_append_raw(out, out_len, &pos, "]") < 0) {
        return -1;
    }
    out[pos] = '\0';
    return (int)pos;
}

const char *rasp_json_array_inner(const char *array_json, size_t *len) {
    *len = 0;
    if (array_json == NULL) {
        return NULL;
    }
    const char *start = array_json;
    while (*start == ' ' || *start == '\t' || *start == '\n' || *start == '\r') {
        start++;
    }
    if (*start != '[') {
        return NULL;
    }
    start++;
    const char *end = array_json + strlen(array_json);
    while (end > start && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\n' || end[-1] == '\r')) {
        end--;
    }
    if (end <= start || end[-1] != ']') {
        return NULL;
    }
    end--;  /* drop the closing bracket */
    /* trim inner whitespace */
    while (start < end && (*start == ' ' || *start == '\t' || *start == '\n' || *start == '\r')) {
        start++;
    }
    while (end > start && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\n' || end[-1] == '\r')) {
        end--;
    }
    if (end <= start) {
        return NULL;  /* empty array */
    }
    *len = (size_t)(end - start);
    return start;
}

int rasp_seal_report(const char *managed_signals_json, const char *nonce, int64_t ts_millis,
                     const char *build_id, const uint8_t *build_key, size_t build_key_len,
                     char *out, size_t out_len) {
    if (nonce == NULL || build_id == NULL || build_key == NULL) {
        return -1;
    }

    rasp_signal_list_t list = {.count = 0};
    rasp_run_all(&list);

    /* Build the canonical report string into a scratch buffer. */
    char report[RASP_MAX_SIGNALS * (RASP_EVIDENCE_LEN * 2 + 96) + 256];
    size_t pos = 0;
    char header[128];
    snprintf(header, sizeof(header), "{\"v\":\"%s\",\"buildId\":\"", RASP_REPORT_VERSION);
    if (rasp_json_append_raw(report, sizeof(report), &pos, header) < 0 ||
        rasp_json_append_escaped(report, sizeof(report), &pos, build_id) < 0 ||
        rasp_json_append_raw(report, sizeof(report), &pos, "\",\"nonce\":\"") < 0 ||
        rasp_json_append_escaped(report, sizeof(report), &pos, nonce) < 0 ||
        rasp_json_append_raw(report, sizeof(report), &pos, "\",\"ts\":") < 0) {
        return -1;
    }
    char ts[32];
    snprintf(ts, sizeof(ts), "%lld", (long long)ts_millis);
    if (rasp_json_append_raw(report, sizeof(report), &pos, ts) < 0 ||
        rasp_json_append_raw(report, sizeof(report), &pos, ",\"signals\":[") < 0) {
        return -1;
    }

    int native = 0;
    for (size_t i = 0; i < list.count; i++) {
        if ((native > 0 && rasp_json_append_raw(report, sizeof(report), &pos, ",") < 0) ||
            append_signal(report, sizeof(report), &pos, &list.items[i]) < 0) {
            return -1;
        }
        native++;
    }

    size_t managed_len = 0;
    const char *managed = rasp_json_array_inner(managed_signals_json, &managed_len);
    if (managed != NULL && managed_len > 0) {
        if (native > 0 && rasp_json_append_raw(report, sizeof(report), &pos, ",") < 0) {
            return -1;
        }
        if (pos + managed_len >= sizeof(report)) {
            return -1;
        }
        memcpy(report + pos, managed, managed_len);
        pos += managed_len;
    }
    if (rasp_json_append_raw(report, sizeof(report), &pos, "]}") < 0) {
        return -1;
    }
    report[pos] = '\0';

    uint8_t mac[RASP_SHA256_DIGEST_LEN];
    rasp_hmac_sha256(build_key, build_key_len, (const uint8_t *)report, pos, mac);
    char mac_hex[RASP_SHA256_DIGEST_LEN * 2 + 1];
    rasp_hex_encode(mac, sizeof(mac), mac_hex);

    size_t out_pos = 0;
    if (rasp_json_append_raw(out, out_len, &out_pos, "{\"report\":\"") < 0 ||
        rasp_json_append_escaped(out, out_len, &out_pos, report) < 0 ||
        rasp_json_append_raw(out, out_len, &out_pos, "\",\"mac\":\"") < 0 ||
        rasp_json_append_raw(out, out_len, &out_pos, mac_hex) < 0 ||
        rasp_json_append_raw(out, out_len, &out_pos, "\"}") < 0) {
        return -1;
    }
    out[out_pos] = '\0';
    return (int)out_pos;
}
