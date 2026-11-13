/// JNI's C opaque reference types preserve VM handles without C++ hierarchy casts or RTTI.
#include "loader_provenance_jni.h"

#include <jni.h>

/// Called only for the declared String return/field/array-element signatures, after exception checks.
__attribute__((visibility("hidden"))) jstring rasp_provenance_string(jobject value) { return value; }
/// Called only for the declared public ApplicationInfo String[] field, after exception checks.
__attribute__((visibility("hidden"))) jobjectArray rasp_provenance_array(jobject value) { return value; }
