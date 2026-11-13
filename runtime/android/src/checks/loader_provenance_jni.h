/// JNI opaque reference conversions at the native C ABI, without RTTI or C++ hierarchy casts.
#pragma once
#include <jni.h>
#ifdef __cplusplus
extern "C" {
#endif
/// Preserves the handle produced by a verified String-returning public signature.
__attribute__((visibility("hidden"))) jstring rasp_provenance_string(jobject value);
/// Preserves the handle produced by the public ApplicationInfo String[] field.
__attribute__((visibility("hidden"))) jobjectArray rasp_provenance_array(jobject value);
#ifdef __cplusplus
}
#endif
