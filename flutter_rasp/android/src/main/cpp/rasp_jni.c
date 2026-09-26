#include <jni.h>
#include <stdlib.h>
#include <string.h>

#include "build_config.h"
#include "detectors.h"
#include "report.h"

#define JSON_BUFFER_LEN (RASP_MAX_SIGNALS * (RASP_EVIDENCE_LEN * 2 + 128))

/* Native methods are bound with RegisterNatives in JNI_OnLoad rather than exported as Java_* symbols, so the
 * entry points do not appear in the dynamic symbol table. The method-name strings still live in the binary;
 * a hardener would obfuscate them and decrypt at registration time. */

static const char *TARGET_CLASS = "dev/ostorlab/rasp/flutter_rasp/NativeDetectors";

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

static const JNINativeMethod METHODS[] = {
    {"nativeScan", "()Ljava/lang/String;", (void *)native_scan},
    {"nativeSeal", "(Ljava/lang/String;Ljava/lang/String;J)Ljava/lang/String;", (void *)native_seal},
};

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    jclass clazz = (*env)->FindClass(env, TARGET_CLASS);
    if (clazz == NULL) {
        return JNI_ERR;
    }
    if ((*env)->RegisterNatives(env, clazz, METHODS, sizeof(METHODS) / sizeof(METHODS[0])) != 0) {
        return JNI_ERR;
    }
    return JNI_VERSION_1_6;
}
