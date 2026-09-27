/* Host unit tests for the native core:
 *   gcc -I../../main/cpp native_test.c ../../main/cpp/{detectors,signals,sha256,report}.c */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "detectors.h"
#include "guard.h"
#include "report.h"
#include "sha256.h"
#include "signals.h"
#include "strobf.h"

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

static void test_report_json_uses_names(void) {
    rasp_signal_list_t list = {.count = 0};
    rasp_signals_add(&list, RASP_THREAT_HOOKING, "native.maps", 90, "frida");
    char json[512];
    assert(rasp_signals_to_report_json(&list, json, sizeof(json)) > 0);
    assert(strcmp(json, "[{\"threat\":\"hooking\",\"confidence\":90,\"detector\":\"native.maps\",\"evidence\":\"frida\"}]") == 0);
}

static void test_json_array_inner(void) {
    size_t len = 0;
    const char *inner = rasp_json_array_inner("[a,b,c]", &len);
    assert(inner != NULL && len == 5 && strncmp(inner, "a,b,c", 5) == 0);
    assert(rasp_json_array_inner("[]", &len) == NULL && len == 0);
    assert(rasp_json_array_inner("  [ ] ", &len) == NULL && len == 0);
    assert(rasp_json_array_inner(NULL, &len) == NULL);
    inner = rasp_json_array_inner("  [ {\"x\":1} ] ", &len);
    assert(inner != NULL && len == 7 && strncmp(inner, "{\"x\":1}", 7) == 0);
    assert(rasp_json_array_inner("not an array", &len) == NULL);
}

static void test_sha256_known_answer(void) {
    /* FIPS 180-4 example: SHA-256("abc"). */
    uint8_t out[RASP_SHA256_DIGEST_LEN];
    rasp_sha256((const uint8_t *)"abc", 3, out);
    char hex[RASP_SHA256_DIGEST_LEN * 2 + 1];
    rasp_hex_encode(out, sizeof(out), hex);
    assert(strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0);

    uint8_t empty[RASP_SHA256_DIGEST_LEN];
    rasp_sha256((const uint8_t *)"", 0, empty);
    rasp_hex_encode(empty, sizeof(empty), hex);
    assert(strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0);
}

static void test_hmac_sha256_known_answer(void) {
    /* RFC 4231 test case 2. */
    uint8_t out[RASP_SHA256_DIGEST_LEN];
    rasp_hmac_sha256((const uint8_t *)"Jefe", 4, (const uint8_t *)"what do ya want for nothing?", 28, out);
    char hex[RASP_SHA256_DIGEST_LEN * 2 + 1];
    rasp_hex_encode(out, sizeof(out), hex);
    assert(strcmp(hex, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843") == 0);
}

static void test_seal_report_structure(void) {
    /* On the host no real threats fire, so native signals are empty; the managed splice must still land and
     * the envelope must carry a 64-hex MAC over the report. */
    uint8_t key[32];
    for (int i = 0; i < 32; i++) {
        key[i] = (uint8_t)i;
    }
    char out[8192];
    int n = rasp_seal_report("[{\"threat\":\"tamper\",\"confidence\":90,\"detector\":\"d\",\"evidence\":\"e\"}]",
                             "AAAA", 123456789LL, "build-x", key, sizeof(key), out, sizeof(out));
    assert(n > 0);
    assert(strstr(out, "\"report\":\"") != NULL);
    assert(strstr(out, "\\\"buildId\\\":\\\"build-x\\\"") != NULL);
    assert(strstr(out, "\\\"nonce\\\":\\\"AAAA\\\"") != NULL);
    assert(strstr(out, "tamper") != NULL);
    /* mac is 64 lowercase hex chars */
    const char *mac = strstr(out, "\"mac\":\"");
    assert(mac != NULL);
    mac += strlen("\"mac\":\"");
    for (int i = 0; i < 64; i++) {
        char c = mac[i];
        assert((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
    }
    assert(mac[64] == '"');
}

static void test_guard_mesh_known_answer(void) {
    /* Known answers from the hardener's guardmesh.py over the same regions (cross-language reference). */
    const uint8_t r1[] = {0};                 /* empty region: len 0 */
    const uint8_t r2[] = {'a', 'b', 'c'};
    const uint8_t r3[] = {0x00, 0x01, 0x02};
    rasp_region_t regions[3] = {{r1, 0}, {r2, 3}, {r3, 3}};

    uint8_t root[RASP_SHA256_DIGEST_LEN];
    rasp_guard_root(regions, 3, root);
    char hex[RASP_SHA256_DIGEST_LEN * 2 + 1];
    rasp_hex_encode(root, sizeof(root), hex);
    assert(strcmp(hex, "42d544dbe00b9b6a4e567625542fc3b155a72f23a2b5e20d6308bf7690d0dc5f") == 0);

    assert(rasp_guard_offset(regions, 3, 1000) == 162);

    /* Results feed data, not branches: a single flipped byte changes the root and the offset. */
    uint8_t r2t[] = {'a', 'b', 'd'};
    regions[1].data = r2t;
    uint8_t root2[RASP_SHA256_DIGEST_LEN];
    rasp_guard_root(regions, 3, root2);
    rasp_hex_encode(root2, sizeof(root2), hex);
    assert(strcmp(hex, "8c1c54f8b5ebf5d74cb99ea4feb0c638d040b7985cec24dd7848126ab4ff0a71") == 0);
    assert(rasp_guard_offset(regions, 3, 1000) != 162);
}

static void test_strobf_decode(void) {
    /* Known cipher from the hardener's strenc.py: obfuscate("nativeScan", key=0..31, idx=1). */
    const uint8_t key[RASP_STRING_KEY_LEN] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
    const uint8_t cipher[] = {0x68, 0x6b, 0x7e, 0x67, 0x78, 0x6f, 0x59, 0x65, 0x67, 0x74};
    char out[sizeof(cipher) + 1];
    rasp_strobf_decode(cipher, sizeof(cipher), 1, key, out);
    assert(strcmp(out, "nativeScan") == 0);

    /* Self-inverse: re-encoding the plaintext reproduces the cipher. */
    uint8_t again[sizeof(cipher)];
    char tmp[sizeof(cipher) + 1];
    rasp_strobf_decode((const uint8_t *)out, sizeof(cipher), 1, key, tmp);
    memcpy(again, tmp, sizeof(cipher));
    assert(memcmp(again, cipher, sizeof(cipher)) == 0);
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
    test_report_json_uses_names();
    test_json_array_inner();
    test_sha256_known_answer();
    test_hmac_sha256_known_answer();
    test_seal_report_structure();
    test_guard_mesh_known_answer();
    test_strobf_decode();
    test_run_all_on_host();
    printf("native tests passed\n");
    return 0;
}
