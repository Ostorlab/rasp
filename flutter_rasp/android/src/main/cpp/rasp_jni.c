#include <jni.h>
#include <stdlib.h>
#include <string.h>

#include "build_config.h"
#include "detectors.h"
#include "report.h"

/* When the hardener has generated build_seed.h (see hardener/emit.py), the class and method-name strings are
 * kept encrypted in the binary and decrypted at registration time (RASP_HARDENED path in JNI_OnLoad). Without
 * it, the cleartext literals below are used, so an unhardened build and the host tests still work. */
#if defined(__has_include)
#if __has_include("build_seed.h")
#include "build_seed.h"
#include "strobf.h"
#define RASP_HARDENED 1
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
    uint8_t build_key[32];
    if (hex_to_bytes(RASP_BUILD_KEY_HEX, build_key, sizeof(build_key)) != 0) {
        return (*env)->NewStringUTF(env, "{}");
    }

    const char *managed_utf = managed ? (*env)->GetStringUTFChars(env, managed, NULL) : NULL;
    const char *nonce_utf = (*env)->GetStringUTFChars(env, nonce, NULL);

    size_t out_len = JSON_BUFFER_LEN * 2;
    char *out = malloc(out_len);
    jstring result;
    if (out != NULL &&
        rasp_seal_report(managed_utf, nonce_utf, (int64_t)ts_millis, RASP_BUILD_ID, build_key,
                         sizeof(build_key), out, out_len) > 0) {
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

#ifdef RASP_HARDENED
    /* Decrypt the class and method strings into stack buffers only for the duration of registration. */
    char cls[RASP_STR_TARGET_CLASS_LEN + 1];
    char m_scan[RASP_STR_M_SCAN_LEN + 1];
    char sig_scan[RASP_STR_SIG_SCAN_LEN + 1];
    char m_seal[RASP_STR_M_SEAL_LEN + 1];
    char sig_seal[RASP_STR_SIG_SEAL_LEN + 1];
    rasp_strobf_decode(RASP_STR_TARGET_CLASS, RASP_STR_TARGET_CLASS_LEN, RASP_STR_TARGET_CLASS_IDX,
                       RASP_STRING_KEY, cls);
    rasp_strobf_decode(RASP_STR_M_SCAN, RASP_STR_M_SCAN_LEN, RASP_STR_M_SCAN_IDX, RASP_STRING_KEY, m_scan);
    rasp_strobf_decode(RASP_STR_SIG_SCAN, RASP_STR_SIG_SCAN_LEN, RASP_STR_SIG_SCAN_IDX, RASP_STRING_KEY, sig_scan);
    rasp_strobf_decode(RASP_STR_M_SEAL, RASP_STR_M_SEAL_LEN, RASP_STR_M_SEAL_IDX, RASP_STRING_KEY, m_seal);
    rasp_strobf_decode(RASP_STR_SIG_SEAL, RASP_STR_SIG_SEAL_LEN, RASP_STR_SIG_SEAL_IDX, RASP_STRING_KEY, sig_seal);
    const char *class_name = cls;
    JNINativeMethod methods[] = {
        {m_scan, sig_scan, (void *)native_scan},
        {m_seal, sig_seal, (void *)native_seal},
    };
#else
    const char *class_name = "dev/ostorlab/rasp/flutter_rasp/NativeDetectors";
    JNINativeMethod methods[] = {
        {"nativeScan", "()Ljava/lang/String;", (void *)native_scan},
        {"nativeSeal", "(Ljava/lang/String;Ljava/lang/String;J)Ljava/lang/String;", (void *)native_seal},
    };
#endif

    jclass clazz = (*env)->FindClass(env, class_name);
    if (clazz == NULL) {
        return JNI_ERR;
    }
    if ((*env)->RegisterNatives(env, clazz, methods, sizeof(methods) / sizeof(methods[0])) != 0) {
        return JNI_ERR;
    }
    return JNI_VERSION_1_6;
}
