/// Calling Java from the runtime's own thread: attaching it to the app's Java VM, and clearing what a call threw.

#include "util/jni.h"

#include <jni.h>

namespace rasp::android::util {

JNIEnv* attached_env() {
  JavaVM* vm = nullptr;
  jsize count = 0;
  if (JNI_GetCreatedJavaVMs(&vm, 1, &count) != JNI_OK || count < 1 || vm == nullptr) {
    return nullptr;
  }
  JNIEnv* env = nullptr;
  if (vm->AttachCurrentThread(&env, nullptr) != JNI_OK) {
    return nullptr;
  }
  return env;
}

bool threw(JNIEnv* env) {
  if (env->ExceptionCheck() == JNI_FALSE) {
    return false;
  }
  env->ExceptionClear();
  return true;
}

}  // namespace rasp::android::util
