/// Bounded public PackageManager SigningInfo reads for the supported retained Application's own package.

#include "util/package_identity.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <jni.h>
#ifndef __ANDROID__
#include <jni_md.h>
#endif
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "util/application_context.h"
#include "util/jni.h"
#include "util/signing_certificates.h"

namespace rasp::android::util {
namespace {

/// Frame capacity covers the fixed lookup set; every signer uses a separate small frame.
constexpr jint kFrameCapacity = 24;
/// PackageManager.GET_SIGNING_CERTIFICATES, supported since API28, including API31 minimum and API34.
constexpr jint kGetSigningCertificates = 0x08000000;
/// Upper bound on the actual package name, before allocating or copying Java string contents.
constexpr jsize kMaxPackageLength = 255;

/// Copies public getPackageName text only after bounding both UTF16 and encoded lengths.
[[nodiscard]] std::optional<std::string> package_text(JNIEnv* env, jstring name) {
  if (name == nullptr) {
    return std::nullopt;
  }
  const jsize length = env->GetStringLength(name);
  if (threw(env) || length < 1 || length > kMaxPackageLength) {
    return std::nullopt;
  }
  std::vector<jchar> characters(static_cast<std::size_t>(length));
  env->GetStringRegion(name, 0, length, characters.data());
  if (threw(env)) {
    return std::nullopt;
  }
  std::string result;
  for (const jchar character : characters) {
    if ((character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
        (character < '0' || character > '9') && character != '_' && character != '.') {
      return std::nullopt;
    }
    result.push_back(static_cast<char>(character));
  }
  return result;
}

/// Copies one Signature.toByteArray after checking its size, using primitive array copying rather than pinning.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> signature_bytes(JNIEnv* env, jobject signer,
                                                                       jmethodID to_bytes) {
  if (signer == nullptr) {
    return std::nullopt;
  }
  jobject bytes = env->CallObjectMethodA(signer, to_bytes, nullptr);
  if (threw(env) || bytes == nullptr) {
    return std::nullopt;
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast): Signature.toByteArray returns a JNI byte array.
  auto* array = static_cast<jbyteArray>(bytes);
  const jsize length = env->GetArrayLength(array);
  if (threw(env) || length < 1 || std::cmp_greater(length, kMaxCertificateBytes)) {
    return std::nullopt;
  }
  std::vector<jbyte> raw(static_cast<std::size_t>(length));
  env->GetByteArrayRegion(array, 0, length, raw.data());
  if (threw(env)) {
    return std::nullopt;
  }
  std::vector<std::uint8_t> certificate;
  certificate.reserve(raw.size());
  for (const jbyte byte : raw) {
    certificate.push_back(static_cast<std::uint8_t>(byte));
  }
  return certificate_envelope(certificate) ? std::optional(std::move(certificate)) : std::nullopt;
}

/// Reads every array element with fixed reference usage, bounding count and aggregate bytes before accepting a set.
[[nodiscard]] std::optional<Certificates> read_array(JNIEnv* env, jobject object, jmethodID to_bytes) {
  if (object == nullptr) {
    return std::nullopt;
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast): SigningInfo methods return JNI Signature arrays.
  auto* array = static_cast<jobjectArray>(object);
  const jsize count = env->GetArrayLength(array);
  if (threw(env) || count < 1 || std::cmp_greater(count, kMaxCertificates)) {
    return std::nullopt;
  }
  Certificates certificates;
  std::size_t total = 0;
  for (jsize index = 0; index < count; ++index) {
    if (env->PushLocalFrame(3) != JNI_OK) {
      static_cast<void>(threw(env));
      return std::nullopt;
    }
    jobject signer = env->GetObjectArrayElement(array, index);
    const bool failed = threw(env);
    auto certificate = failed ? std::nullopt : signature_bytes(env, signer, to_bytes);
    env->PopLocalFrame(nullptr);
    if (!certificate.has_value() || certificate->size() > kMaxCertificateTotalBytes - total) {
      return std::nullopt;
    }
    total += certificate->size();
    certificates.push_back(std::move(*certificate));
  }
  return certificates;
}

/// Reads current signers and, for a single current signer, ordered history from one SigningInfo snapshot.
void signing_fields(JNIEnv* env, jobject info, PackageIdentity& result) {
  jclass type = env->FindClass("android/content/pm/SigningInfo");
  if (threw(env) || type == nullptr) {
    return;
  }
  auto* const multiple_method = env->GetMethodID(type, "hasMultipleSigners", "()Z");
  if (threw(env) || multiple_method == nullptr) {
    return;
  }
  const jboolean multiple = env->CallBooleanMethodA(info, multiple_method, nullptr);
  if (threw(env)) {
    return;
  }
  auto* const current_method = env->GetMethodID(type, "getApkContentsSigners", "()[Landroid/content/pm/Signature;");
  if (threw(env) || current_method == nullptr) {
    return;
  }
  jclass signature = env->FindClass("android/content/pm/Signature");
  if (threw(env) || signature == nullptr) {
    return;
  }
  auto* const to_bytes = env->GetMethodID(signature, "toByteArray", "()[B");
  if (threw(env) || to_bytes == nullptr) {
    return;
  }
  jobject current = env->CallObjectMethodA(info, current_method, nullptr);
  if (threw(env)) {
    return;
  }
  result.current = read_array(env, current, to_bytes);
  if (!result.current.has_value()) {
    return;
  }
  if ((multiple == JNI_TRUE) != (result.current->size() > 1)) {
    result.current.reset();
    return;
  }
  if (multiple == JNI_TRUE) {
    result.history_unsupported = true;
    return;
  }
  auto* const history_method =
      env->GetMethodID(type, "getSigningCertificateHistory", "()[Landroid/content/pm/Signature;");
  if (threw(env) || history_method == nullptr) {
    return;
  }
  jobject history = env->CallObjectMethodA(info, history_method, nullptr);
  if (threw(env)) {
    return;
  }
  result.history = read_array(env, history, to_bytes);
  if (result.history.has_value() && result.history->back() != result.current->front()) {
    result.history.reset();
  }
}

/// Collects public package metadata inside the caller's local frame, preserving independently successful fields.
[[nodiscard]] PackageIdentity read_in_frame(JNIEnv* env) {
  PackageIdentity result;
  const auto application = application_context(env);
  if (!application.has_value() || *application == nullptr) {
    return result;
  }
  jclass context = env->FindClass("android/content/Context");
  if (threw(env) || context == nullptr) {
    return result;
  }
  auto* const get_name = env->GetMethodID(context, "getPackageName", "()Ljava/lang/String;");
  if (threw(env) || get_name == nullptr) {
    return result;
  }
  jobject name_object = env->CallObjectMethodA(*application, get_name, nullptr);
  if (threw(env)) {
    return result;
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast): Context.getPackageName returns a JNI String.
  auto* name = static_cast<jstring>(name_object);
  result.package_name = package_text(env, name);
  if (!result.package_name.has_value()) {
    return result;
  }
  auto* const get_manager = env->GetMethodID(context, "getPackageManager", "()Landroid/content/pm/PackageManager;");
  if (threw(env) || get_manager == nullptr) {
    return result;
  }
  jobject manager = env->CallObjectMethodA(*application, get_manager, nullptr);
  if (threw(env) || manager == nullptr) {
    return result;
  }
  jclass manager_type = env->FindClass("android/content/pm/PackageManager");
  if (threw(env) || manager_type == nullptr) {
    return result;
  }
  auto* const get_info =
      env->GetMethodID(manager_type, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
  if (threw(env) || get_info == nullptr) {
    return result;
  }
  const std::array<jvalue, 2> arguments{jvalue{.l = name}, jvalue{.i = kGetSigningCertificates}};
  jobject package_info = env->CallObjectMethodA(manager, get_info, arguments.data());
  if (threw(env) || package_info == nullptr) {
    return result;
  }
  jclass info_type = env->FindClass("android/content/pm/PackageInfo");
  if (threw(env) || info_type == nullptr) {
    return result;
  }
  auto* const signing_field = env->GetFieldID(info_type, "signingInfo", "Landroid/content/pm/SigningInfo;");
  if (threw(env) || signing_field == nullptr) {
    return result;
  }
  jobject signing_info = env->GetObjectField(package_info, signing_field);
  if (!threw(env) && signing_info != nullptr) {
    signing_fields(env, signing_info, result);
  }
  return result;
}

}  // namespace

PackageIdentity read_package_identity(JNIEnv* env) {
  if (env == nullptr) {
    return {};
  }
  if (env->PushLocalFrame(kFrameCapacity) != JNI_OK) {
    static_cast<void>(threw(env));
    return {};
  }
  PackageIdentity result = read_in_frame(env);
  env->PopLocalFrame(nullptr);
  return result;
}

}  // namespace rasp::android::util
