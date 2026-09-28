/* _GNU_SOURCE exposes dladdr/Dl_info on glibc (the host build); it is harmless on Android bionic, where they
 * are always declared. Must precede the first system header. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <jni.h>
#include <stdlib.h>
#include <string.h>

#include "build_config.h"
#include "detectors.h"
#include "report.h"
#include "sha256.h"

#if defined(__has_include)
/* When the hardener has generated integrity_regions.h, the report is sealed with the integrity-derived key
 * HMAC(build_key, guard_root(own .so regions)) instead of the raw build key (design §8). A tampered binary
 * derives a different key and the trust service refuses the report. */
#if __has_include("integrity_regions.h")
#include <dlfcn.h>

#include "integrity.h"
#include "integrity_regions.h"
#define RASP_INTEGRITY 1
#endif
#endif

#define JSON_BUFFER_LEN (RASP_MAX_SIGNALS * (RASP_EVIDENCE_LEN * 2 + 128))

/* Native methods are bound with RegisterNatives in JNI_OnLoad rather than exported as Java_* symbols, so the
 * entry points do not appear in the dynamic symbol table. */

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len != out_len * 2) {
        return -1;
    }
    for (size_t i = 0; i < out_len; i++) {
        char c[3] = {hex[i * 2], hex[i * 2 + 1], '\0'};
        char *end = NULL;
        long value = strtol(c, &end, 16);
        if (end != c + 2) {
            return -1;
        }
        out[i] = (uint8_t)value;
    }
    return 0;
}

static jstring native_scan(JNIEnv *env, jclass clazz) {
    (void)clazz;
    rasp_signal_list_t list = {.count = 0};
    rasp_run_all(&list);

    char *json = malloc(JSON_BUFFER_LEN);
    if (json == NULL) {
        return (*env)->NewStringUTF(env, "[]");
    }
    if (rasp_signals_to_json(&list, json, JSON_BUFFER_LEN) < 0) {
        strcpy(json, "[]");
    }
    jstring result = (*env)->NewStringUTF(env, json);
    free(json);
    return result;
}

static jstring native_seal(JNIEnv *env, jclass clazz, jstring managed, jstring nonce, jlong ts_millis) {
    (void)clazz;
    if (nonce == NULL) {
        return (*env)->NewStringUTF(env, "{}");
    }
    RASP_LIT(BUILD_KEY_HEX, key_hex);
    uint8_t build_key[32];
    if (hex_to_bytes(key_hex, build_key, sizeof(build_key)) != 0) {
        return (*env)->NewStringUTF(env, "{}");
    }

    const uint8_t *seal_key = build_key;
#ifdef RASP_INTEGRITY
    uint8_t derived_key[32];
    Dl_info info;
    uint8_t root[RASP_SHA256_DIGEST_LEN];
    if (dladdr((void *)native_seal, &info) != 0 && info.dli_fname != NULL &&
        rasp_integrity_root_from_file(info.dli_fname, RASP_INTEGRITY_REGIONS, RASP_INTEGRITY_REGION_COUNT,
                                      root) == 0) {
        rasp_hmac_sha256(build_key, sizeof(build_key), root, sizeof(root), derived_key);
        seal_key = derived_key;
    }
    /* On any failure `seal_key` stays the raw build key; the trust service expects the derived key for this
     * build, so it refuses the report — fail closed rather than sealing with a key it will accept. */
#endif

    const char *managed_utf = managed ? (*env)->GetStringUTFChars(env, managed, NULL) : NULL;
    const char *nonce_utf = (*env)->GetStringUTFChars(env, nonce, NULL);

    size_t out_len = JSON_BUFFER_LEN * 2;
    char *out = malloc(out_len);
    jstring result;
    if (out != NULL &&
        rasp_seal_report(managed_utf, nonce_utf, (int64_t)ts_millis, RASP_BUILD_ID, seal_key,
                         (size_t)32, out, out_len) > 0) {
        result = (*env)->NewStringUTF(env, out);
    } else {
        result = (*env)->NewStringUTF(env, "{}");
    }

    free(out);
    if (managed_utf) {
        (*env)->ReleaseStringUTFChars(env, managed, managed_utf);
    }
    (*env)->ReleaseStringUTFChars(env, nonce, nonce_utf);
    return result;
}

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    RASP_LIT(JNI_CLASS, cls);
    RASP_LIT(JNI_M_SCAN, m_scan);
    RASP_LIT(JNI_SIG_SCAN, sig_scan);
    RASP_LIT(JNI_M_SEAL, m_seal);
    RASP_LIT(JNI_SIG_SEAL, sig_seal);
    const char *class_name = cls;
    JNINativeMethod methods[] = {
        {m_scan, sig_scan, (void *)native_scan},
        {m_seal, sig_seal, (void *)native_seal},
    };


    jclass clazz = (*env)->FindClass(env, class_name);
    if (clazz == NULL) {
        return JNI_ERR;
    }
    if ((*env)->RegisterNatives(env, clazz, methods, sizeof(methods) / sizeof(methods[0])) != 0) {
        return JNI_ERR;
    }
    return JNI_VERSION_1_6;
}
