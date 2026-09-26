#include <jni.h>
#include <stdlib.h>

#include "detectors.h"

#define JSON_BUFFER_LEN (RASP_MAX_SIGNALS * (RASP_EVIDENCE_LEN * 2 + 128))

JNIEXPORT jstring JNICALL
Java_dev_ostorlab_rasp_flutter_1rasp_NativeDetectors_nativeScan(JNIEnv *env, jclass clazz) {
    (void)clazz;
    rasp_signal_list_t list = {.count = 0};
    rasp_run_all(&list);

    char *json = malloc(JSON_BUFFER_LEN);
    if (json == NULL) {
        return (*env)->NewStringUTF(env, "[]");
    }
    if (rasp_signals_to_json(&list, json, JSON_BUFFER_LEN) < 0) {
        json[0] = '[';
        json[1] = ']';
        json[2] = '\0';
    }
    jstring result = (*env)->NewStringUTF(env, json);
    free(json);
    return result;
}
