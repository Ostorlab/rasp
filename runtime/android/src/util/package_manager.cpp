/// The existing PackageManager signer certificate reader, preferring explicit host Context integration.

#include "util/package_manager.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <jni.h>
#ifndef __ANDROID__
#include <jni_md.h>
#endif
#include <optional>
#include <thread>
#include <vector>

#include "util/application_context.h"
#include "util/jni.h"

namespace rasp::android::util {
namespace {

/// The local references a pass of package_manager_certificate makes.
constexpr jint kLocalFrameCapacity = 16;
/// PackageManager.GET_SIGNING_CERTIFICATES, which fills PackageInfo.signingInfo.
constexpr jint kGetSigningCertificates = 0x08000000;
/// How long the thread waits between two looks for the app's Application.
constexpr std::chrono::milliseconds kApplicationWaitStep{50};
/// The most looks for the app's Application, five seconds in all, so an app that never creates one can't keep the
/// thread waiting.
constexpr int kApplicationWaitAttempts = 100;

/// Waits for the app's Application, at most kApplicationWaitAttempts looks kApplicationWaitStep apart.
///
/// The runtime's thread can start before Android creates the Application. The returned local reference belongs to
/// the caller's local frame; a JNI exception or a timeout returns nullptr.
[[nodiscard]] jobject wait_for_application(JNIEnv* env, jclass activity_thread, jmethodID current_application) {
  jobject application = nullptr;
  for (int attempt = 0; attempt < kApplicationWaitAttempts && application == nullptr; ++attempt) {
    if (attempt > 0) {
      std::this_thread::sleep_for(kApplicationWaitStep);
    }
    application = env->CallStaticObjectMethodA(activity_thread, current_application, nullptr);
    if (threw(env)) {
      return nullptr;
    }
  }
  return application;
}

/// Prefers supported initialization and keeps the bounded legacy lookup only for unintegrated apps.
[[nodiscard]] std::expected<jobject, ContextInitResult> find_application(JNIEnv* env) {
  const auto explicit_context = application_context(env);
  if (!explicit_context.has_value()) {
    return std::unexpected(ContextInitResult::kJniError);
  }
  jobject application = *explicit_context;
  if (application == nullptr) {
    jclass activity_thread = env->FindClass("android/app/ActivityThread");
    if (threw(env) || activity_thread == nullptr) {
      return std::unexpected(ContextInitResult::kJniError);
    }
    jmethodID current_application =
        env->GetStaticMethodID(activity_thread, "currentApplication", "()Landroid/app/Application;");
    if (threw(env) || current_application == nullptr) {
      return std::unexpected(ContextInitResult::kJniError);
    }
    application = wait_for_application(env, activity_thread, current_application);
  }
  return application;
}

/// Reads the signer's certificate from the package manager, inside a local frame that the caller pops.
///
/// It prefers the explicit Application Context, with ActivityThread.currentApplication as a legacy fallback, to call
/// GET_SIGNING_CERTIFICATES, then SigningInfo.getApkContentsSigners and the first Signature's bytes. It calls
/// wait_for_application only on the monitor thread when explicit integration is absent.
///
/// @param env The thread's JNI environment.
/// @return The certificate's DER bytes, or nothing when a call fails or throws, there is no signer, or the Application
/// still doesn't exist after the wait.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> read_in_frame(JNIEnv* env) {
  jclass context = env->FindClass("android/content/Context");
  jclass package_manager = env->FindClass("android/content/pm/PackageManager");
  jclass package_info = env->FindClass("android/content/pm/PackageInfo");
  jclass signing_info = env->FindClass("android/content/pm/SigningInfo");
  jclass signature = env->FindClass("android/content/pm/Signature");
  if (threw(env) || context == nullptr || package_manager == nullptr || package_info == nullptr ||
      signing_info == nullptr || signature == nullptr) {
    return std::nullopt;
  }
  jmethodID get_package_manager =
      env->GetMethodID(context, "getPackageManager", "()Landroid/content/pm/PackageManager;");
  jmethodID get_package_name = env->GetMethodID(context, "getPackageName", "()Ljava/lang/String;");
  jmethodID get_package_info =
      env->GetMethodID(package_manager, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
  jfieldID signing_info_field = env->GetFieldID(package_info, "signingInfo", "Landroid/content/pm/SigningInfo;");
  jmethodID get_signers = env->GetMethodID(signing_info, "getApkContentsSigners", "()[Landroid/content/pm/Signature;");
  jmethodID to_byte_array = env->GetMethodID(signature, "toByteArray", "()[B");
  if (threw(env) || get_package_manager == nullptr || get_package_name == nullptr || get_package_info == nullptr ||
      signing_info_field == nullptr || get_signers == nullptr || to_byte_array == nullptr) {
    return std::nullopt;
  }
  const auto application_result = find_application(env);
  if (!application_result.has_value()) {
    return std::nullopt;
  }
  jobject application = *application_result;
  if (application == nullptr) {
    return std::nullopt;
  }
  jobject manager = env->CallObjectMethodA(application, get_package_manager, nullptr);
  if (threw(env) || manager == nullptr) {
    return std::nullopt;
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast): getPackageName returns a String.
  auto* name = static_cast<jstring>(env->CallObjectMethodA(application, get_package_name, nullptr));
  if (threw(env) || name == nullptr) {
    return std::nullopt;
  }
  const std::array<jvalue, 2> arguments{jvalue{.l = name}, jvalue{.i = kGetSigningCertificates}};
  jobject info = env->CallObjectMethodA(manager, get_package_info, arguments.data());
  if (threw(env) || info == nullptr) {
    return std::nullopt;
  }
  jobject signers_info = env->GetObjectField(info, signing_info_field);
  if (threw(env) || signers_info == nullptr) {
    return std::nullopt;
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast): getApkContentsSigners returns a Signature[].
  auto* signers = static_cast<jobjectArray>(env->CallObjectMethodA(signers_info, get_signers, nullptr));
  if (threw(env) || signers == nullptr || env->GetArrayLength(signers) < 1) {
    return std::nullopt;
  }
  jobject first = env->GetObjectArrayElement(signers, 0);
  if (threw(env) || first == nullptr) {
    return std::nullopt;
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast): toByteArray returns a byte[].
  auto* bytes = static_cast<jbyteArray>(env->CallObjectMethodA(first, to_byte_array, nullptr));
  if (threw(env) || bytes == nullptr) {
    return std::nullopt;
  }
  const jsize length = env->GetArrayLength(bytes);
  if (threw(env) || length < 1 || length > 65536) {
    return std::nullopt;
  }
  std::vector<jbyte> raw(static_cast<std::size_t>(length));
  env->GetByteArrayRegion(bytes, 0, length, raw.data());
  if (threw(env)) {
    return std::nullopt;
  }
  std::vector<std::uint8_t> certificate(raw.size());
  std::ranges::transform(raw, certificate.begin(), [](jbyte value) { return static_cast<std::uint8_t>(value); });
  return certificate;
}

}  // namespace

std::optional<std::vector<std::uint8_t>> read_package_manager_certificate(JNIEnv* env) {
  if (env == nullptr) {
    return std::nullopt;
  }
  if (env->PushLocalFrame(kLocalFrameCapacity) != JNI_OK) {
    static_cast<void>(threw(env));
    return std::nullopt;
  }
  const auto certificate = read_in_frame(env);
  env->PopLocalFrame(nullptr);
  return certificate;
}

}  // namespace rasp::android::util
