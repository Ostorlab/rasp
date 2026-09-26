/* Host unit tests for the native core: gcc -I../../main/cpp native_test.c ../../main/cpp/{detectors,signals}.c */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "detectors.h"
#include "signals.h"

static void test_parse_tracer_pid(void) {
    assert(rasp_parse_tracer_pid("Name:\tapp\nTracerPid:\t0\nUid:\t1\n") == 0);
    assert(rasp_parse_tracer_pid("Name:\tapp\nTracerPid:\t4242\n") == 4242);
    assert(rasp_parse_tracer_pid("Name:\tapp\n") == -1);
}

static void test_match_any(void) {
    const char *needles[] = {"frida", "xposed"};
    assert(strcmp(rasp_match_any("7f00-7f10 r-xp /data/local/tmp/frida-agent.so", needles, 2), "frida") == 0);
    assert(rasp_match_any("7f00-7f10 r-xp /system/lib64/libc.so", needles, 2) == NULL);
}

static void test_signals_dedupe_and_json(void) {
    rasp_signal_list_t list = {.count = 0};
    rasp_signals_add(&list, RASP_THREAT_ROOT, "native.su_binary", 90, "/system/xbin/su");
    rasp_signals_add(&list, RASP_THREAT_ROOT, "native.su_binary", 90, "/sbin/su");
    rasp_signals_add(&list, RASP_THREAT_HOOKING, "native.maps", 90, "path \"quoted\"\\");
    assert(list.count == 2);

    char json[1024];
    assert(rasp_signals_to_json(&list, json, sizeof(json)) > 0);
    assert(strcmp(json,
                  "[{\"threat\":0,\"confidence\":90,\"detector\":\"native.su_binary\",\"evidence\":\"/system/xbin/su\"},"
                  "{\"threat\":3,\"confidence\":90,\"detector\":\"native.maps\",\"evidence\":\"path \\\"quoted\\\"\\\\\"}]") == 0);

    char tiny[8];
    assert(rasp_signals_to_json(&list, tiny, sizeof(tiny)) == -1);
}

static void test_run_all_on_host(void) {
    /* Smoke test: must not crash, and a plain host process is not traced. */
    rasp_signal_list_t list = {.count = 0};
    rasp_run_all(&list);
    for (size_t i = 0; i < list.count; i++) {
        assert(strcmp(list.items[i].detector, "native.tracer_pid") != 0);
    }
}

int main(void) {
    test_parse_tracer_pid();
    test_match_any();
    test_signals_dedupe_and_json();
    test_run_all_on_host();
    printf("native tests passed\n");
    return 0;
}
