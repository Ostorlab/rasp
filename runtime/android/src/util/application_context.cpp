/// The process-lifetime Application global reference; no JNIEnv or component Context crosses a thread boundary.

#include "util/application_context.h"

#include <array>
#include <atomic>
#include <expected>
#include <jni.h>
#ifndef __ANDROID__
#include <jni_md.h>
#endif

#include "util/jni.h"

namespace rasp::android::util {
namespace {

/// Immutable after publication; process lifetime matches the detached monitor, so no teardown can race a reader.
[[nodiscard]] std::atomic<jobject>& retained_application() {
  static constinit std::atomic<jobject> application{nullptr};
  return application;
}

/// Normalizes and publishes inside the caller's local frame.
[[nodiscard]] ContextInitResult initialize_in_frame(JNIEnv* env, jobject context) {
  jclass context_class = env->FindClass("android/content/Context");
  if (threw(env) || context_class == nullptr) {
    return ContextInitResult::kJniError;
  }
  jmethodID get_application = env->GetMethodID(context_class, "getApplicationContext", "()Landroid/content/Context;");
  if (threw(env) || get_application == nullptr) {
    return ContextInitResult::kJniError;
  }
  jobject application = env->CallObjectMethodA(context, get_application, nullptr);
  if (threw(env)) {
    return ContextInitResult::kJniError;
  }
  if (application == nullptr) {
    return ContextInitResult::kInvalidContext;
  }
  jclass application_class = env->FindClass("android/app/Application");
  if (threw(env) || application_class == nullptr) {
    return ContextInitResult::kJniError;
  }
  const jboolean is_application = env->IsInstanceOf(application, application_class);
  if (threw(env)) {
    return ContextInitResult::kJniError;
  }
  if (is_application == JNI_FALSE) {
    return ContextInitResult::kInvalidContext;
  }
  jobject existing = retained_application().load(std::memory_order_acquire);
  if (existing == nullptr) {
    jobject global = env->NewGlobalRef(application);
    const bool failed = threw(env);
    if (failed || global == nullptr) {
      if (global != nullptr) {
        env->DeleteGlobalRef(global);
      }
      return ContextInitResult::kJniError;
    }
    if (retained_application().compare_exchange_strong(existing, global, std::memory_order_release,
                                                       std::memory_order_acquire)) {
      return ContextInitResult::kInitialized;
    }
    env->DeleteGlobalRef(global);
  }
  const jboolean same = env->IsSameObject(existing, application);
  if (threw(env)) {
    return ContextInitResult::kJniError;
  }
  return same == JNI_TRUE ? ContextInitResult::kAlreadyInitialized : ContextInitResult::kDifferentApplication;
}

/// The registered bridge entry; all local references and exceptions stay within this host call.
jint initialize_native(JNIEnv* env, jclass /*bridge*/, jobject context) {
  return static_cast<jint>(initialize_application_context(env, context));
}

}  // namespace

ContextInitResult initialize_application_context(JNIEnv* env, jobject context) {
  if (context == nullptr) {
    return ContextInitResult::kInvalidContext;
  }
  if (env->PushLocalFrame(4) != JNI_OK) {
    static_cast<void>(threw(env));
    return ContextInitResult::kJniError;
  }
  const ContextInitResult result = initialize_in_frame(env, context);
  env->PopLocalFrame(nullptr);
  return result;
}

std::expected<jobject, ContextInitResult> application_context(JNIEnv* env) {
  jobject global = retained_application().load(std::memory_order_acquire);
  if (global == nullptr) {
    return nullptr;
  }
  jobject local = env->NewLocalRef(global);
  const bool failed = threw(env);
  if (failed || local == nullptr) {
    if (local != nullptr) {
      env->DeleteLocalRef(local);
    }
    return std::unexpected(ContextInitResult::kJniError);
  }
  return local;
}

bool register_context_bridge(JNIEnv* env) {
  jclass bridge = env->FindClass("co/ostorlab/rasp/RuntimeBridge");
  if (threw(env) || bridge == nullptr) {
    if (bridge != nullptr) {
      env->DeleteLocalRef(bridge);
    }
    return false;
  }
  auto method_name = std::to_array("initializeNative");
  auto signature = std::to_array("(Landroid/content/Context;)I");
  const JNINativeMethod method{
      .name = method_name.data(),
      .signature = signature.data(),
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): RegisterNatives requires a void* function entry.
      .fnPtr = reinterpret_cast<void*>(&initialize_native),
  };
  const jint result = env->RegisterNatives(bridge, &method, 1);
  const bool failed = threw(env);
  env->DeleteLocalRef(bridge);
  return result == JNI_OK && !failed;
}

}  // namespace rasp::android::util
