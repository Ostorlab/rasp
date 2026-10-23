/// The Android app-identity self-check: the package-name probe over the process's command line, the signing-certificate
/// hash probe, and their unsupported results off Android.

#include "checks/identity.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#ifdef __ANDROID__
#include <jni.h>
#include <utility>
#endif

#include "checks/integrity.h"
#include "rasp/observation.h"
#include "util/read_file.h"

namespace rasp::android::checks {

namespace {

#ifdef __ANDROID__
/// Whether this build runs on Android, the only place the probes mean anything.
constexpr bool kOnAndroid = true;
#else
/// Whether this build runs on Android, the only place the probes mean anything.
constexpr bool kOnAndroid = false;
#endif

/// The signal of the package-name probe.
constexpr std::string_view kPackageSignal = "id.package";
/// The source of the package-name probe.
constexpr std::string_view kPackageSource = "proc_cmdline";

/// The signal of the signing-certificate probe.
constexpr std::string_view kSignerSignal = "id.signer_sha256";
/// The source of the signing-certificate probe.
constexpr std::string_view kSignerSource = "package_manager";

/// The process's command line, whose first NUL-separated argument is the package name.
constexpr std::string_view kCmdlinePath = "/proc/self/cmdline";
/// The largest command line read. A real one is well under this.
constexpr std::size_t kMaxCmdlineSize = std::size_t{64} << 10U;

/// The package name in `cmdline`, the process's command line. Android sets the command line to the process name, whose
/// first NUL-separated field is the package, optionally followed by `:<name>` for a process an app declares with
/// `android:process` (such as `com.example:remote`). The package is the part before that colon, so every process of a
/// multi-process app reports the same package. The view is empty when there is no name.
[[nodiscard]] std::string_view package_name(std::string_view cmdline) {
  const std::size_t nul = cmdline.find('\0');
  const std::string_view process = cmdline.substr(0, nul == std::string_view::npos ? cmdline.size() : nul);
  const std::size_t colon = process.find(':');
  return process.substr(0, colon == std::string_view::npos ? process.size() : colon);
}

#ifdef __ANDROID__

/// `GET_SIGNING_CERTIFICATES`, the PackageManager flag that asks for the signing certificates in a PackageInfo.
constexpr jint kGetSigningCertificates = 0x08000000;
/// `GET_SIGNATURES`, the deprecated flag used on devices before the v2 signing-info API.
constexpr jint kGetSignatures = 0x00000040;

/// Whether a pending Java exception is set; clears it so the next JNI call is clean, and returns true when there was
/// one.
[[nodiscard]] bool had_exception(JNIEnv* env) {
  if (env->ExceptionCheck() == JNI_TRUE) {
    env->ExceptionClear();
    return true;
  }
  return false;
}

/// The app's Context, from `ActivityThread.currentApplication()`, or nullptr when it can't be reached. The constructor
/// model has no Context passed to it, so the runtime asks the framework for the current application, which is a
/// Context.
[[nodiscard]] jobject current_application(JNIEnv* env) {
  jclass activity_thread = env->FindClass("android/app/ActivityThread");
  if (activity_thread == nullptr || had_exception(env)) {
    return nullptr;
  }
  jmethodID current = env->GetStaticMethodID(activity_thread, "currentApplication", "()Landroid/app/Application;");
  if (current == nullptr || had_exception(env)) {
    env->DeleteLocalRef(activity_thread);
    return nullptr;
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): the JNI call methods are variadic by design.
  jobject application = env->CallStaticObjectMethod(activity_thread, current);
  env->DeleteLocalRef(activity_thread);
  if (had_exception(env)) {
    return nullptr;
  }
  return application;
}

/// The Java string `text` as a std::string, or an empty string when it is null. The bytes are copied, so the view
/// doesn't outlive the local reference.
[[nodiscard]] std::string to_string(JNIEnv* env, jstring text) {
  if (text == nullptr) {
    return {};
  }
  const char* const chars = env->GetStringUTFChars(text, nullptr);
  if (chars == nullptr) {
    return {};
  }
  std::string value(chars);
  env->ReleaseStringUTFChars(text, chars);
  return value;
}

/// The app's package name, from `context.getPackageName()`, or an empty string when it can't be read. Unlike the
/// process name in `/proc/self/cmdline`, this is the application package even for a process with a global or a private
/// `android:process` name.
[[nodiscard]] std::string package_of(JNIEnv* env, jobject context) {
  jclass context_class = env->GetObjectClass(context);
  jmethodID get_package_name = env->GetMethodID(context_class, "getPackageName", "()Ljava/lang/String;");
  env->DeleteLocalRef(context_class);
  if (get_package_name == nullptr || had_exception(env)) {
    return {};
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): the JNI call methods are variadic by design.
  jobject name = env->CallObjectMethod(context, get_package_name);
  if (name == nullptr || had_exception(env)) {
    return {};
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast): getPackageName's declared type is String.
  const std::string package = to_string(env, static_cast<jstring>(name));
  env->DeleteLocalRef(name);
  return package;
}

/// The byte array `array` as a vector, or an empty vector when it is null or can't be read.
[[nodiscard]] std::vector<std::uint8_t> to_bytes(JNIEnv* env, jbyteArray array) {
  if (array == nullptr) {
    return {};
  }
  const jsize length = env->GetArrayLength(array);
  if (length <= 0) {
    return {};
  }
  std::vector<jbyte> signed_bytes(static_cast<std::size_t>(length));
  env->GetByteArrayRegion(array, 0, length, signed_bytes.data());
  if (had_exception(env)) {
    return {};
  }
  return {signed_bytes.begin(), signed_bytes.end()};
}

/// The DER bytes of the first signer in the `Signature[]` `signatures`, or an empty vector when there is none. Each
/// element is an `android.content.pm.Signature`, whose `toByteArray` gives the signing certificate's DER bytes.
[[nodiscard]] std::vector<std::uint8_t> first_signature_bytes(JNIEnv* env, jobjectArray signatures) {
  if (signatures == nullptr || env->GetArrayLength(signatures) <= 0) {
    return {};
  }
  jobject signature = env->GetObjectArrayElement(signatures, 0);
  if (signature == nullptr || had_exception(env)) {
    return {};
  }
  jclass signature_class = env->GetObjectClass(signature);
  jmethodID to_byte_array = env->GetMethodID(signature_class, "toByteArray", "()[B");
  env->DeleteLocalRef(signature_class);
  if (to_byte_array == nullptr || had_exception(env)) {
    env->DeleteLocalRef(signature);
    return {};
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): the JNI call methods are variadic by design.
  jobject result = env->CallObjectMethod(signature, to_byte_array);
  env->DeleteLocalRef(signature);
  if (had_exception(env)) {
    return {};
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast): the method's declared return type is the array.
  auto* array = static_cast<jbyteArray>(result);
  const std::vector<std::uint8_t> bytes = to_bytes(env, array);
  env->DeleteLocalRef(array);
  return bytes;
}

/// The `Signature[]` of the current signers in `info`, read through the v2 `signingInfo.getApkContentsSigners()` when
/// present, or the deprecated `signatures` field otherwise, or null when neither is set.
[[nodiscard]] jobjectArray signatures_of(JNIEnv* env, jobject info) {
  jclass info_class = env->GetObjectClass(info);
  jfieldID signing_info_field = env->GetFieldID(info_class, "signingInfo", "Landroid/content/pm/SigningInfo;");
  if (signing_info_field != nullptr && !had_exception(env)) {
    jobject signing_info = env->GetObjectField(info, signing_info_field);
    if (signing_info != nullptr) {
      jclass signing_info_class = env->GetObjectClass(signing_info);
      jmethodID get_signers =
          env->GetMethodID(signing_info_class, "getApkContentsSigners", "()[Landroid/content/pm/Signature;");
      env->DeleteLocalRef(signing_info_class);
      if (get_signers != nullptr && !had_exception(env)) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): the JNI call methods are variadic by design.
        jobject signers = env->CallObjectMethod(signing_info, get_signers);
        env->DeleteLocalRef(signing_info);
        env->DeleteLocalRef(info_class);
        if (had_exception(env)) {
          return nullptr;
        }
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast): the method's declared type is the array.
        return static_cast<jobjectArray>(signers);
      }
      env->DeleteLocalRef(signing_info);
    }
  }
  // Clear any pending exception from the v2 lookup before trying the deprecated field.
  static_cast<void>(had_exception(env));
  jfieldID signatures_field = env->GetFieldID(info_class, "signatures", "[Landroid/content/pm/Signature;");
  env->DeleteLocalRef(info_class);
  if (signatures_field == nullptr || had_exception(env)) {
    return nullptr;
  }
  jobject signatures = env->GetObjectField(info, signatures_field);
  if (had_exception(env)) {
    return nullptr;
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast): the field's declared type is the array.
  return static_cast<jobjectArray>(signatures);
}

/// The DER bytes of the app's signing certificate, read through the PackageManager of the `context`, or an empty vector
/// when they can't be read. It calls `context.getPackageName()` and `context.getPackageManager().getPackageInfo(name,
/// flags)`, then takes the first signer's bytes.
[[nodiscard]] std::vector<std::uint8_t> signing_certificate(JNIEnv* env, jobject context) {
  jclass context_class = env->GetObjectClass(context);
  jmethodID get_package_name = env->GetMethodID(context_class, "getPackageName", "()Ljava/lang/String;");
  jmethodID get_package_manager =
      env->GetMethodID(context_class, "getPackageManager", "()Landroid/content/pm/PackageManager;");
  env->DeleteLocalRef(context_class);
  if (get_package_name == nullptr || get_package_manager == nullptr || had_exception(env)) {
    return {};
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): the JNI call methods are variadic by design.
  jobject name = env->CallObjectMethod(context, get_package_name);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): the JNI call methods are variadic by design.
  jobject manager = env->CallObjectMethod(context, get_package_manager);
  if (name == nullptr || manager == nullptr || had_exception(env)) {
    return {};
  }
  jclass manager_class = env->GetObjectClass(manager);
  jmethodID get_package_info =
      env->GetMethodID(manager_class, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
  env->DeleteLocalRef(manager_class);
  if (get_package_info == nullptr || had_exception(env)) {
    env->DeleteLocalRef(name);
    env->DeleteLocalRef(manager);
    return {};
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): the JNI call methods are variadic by design.
  jobject info = env->CallObjectMethod(manager, get_package_info, name, kGetSigningCertificates);
  if (info == nullptr || had_exception(env)) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): the JNI call methods are variadic by design.
    info = env->CallObjectMethod(manager, get_package_info, name, kGetSignatures);
  }
  env->DeleteLocalRef(name);
  env->DeleteLocalRef(manager);
  if (info == nullptr || had_exception(env)) {
    return {};
  }
  jobjectArray signatures = signatures_of(env, info);
  env->DeleteLocalRef(info);
  const std::vector<std::uint8_t> bytes = first_signature_bytes(env, signatures);
  if (signatures != nullptr) {
    env->DeleteLocalRef(signatures);
  }
  return bytes;
}

#endif  // __ANDROID__

}  // namespace

Observation observe_package(std::string_view cmdline_path) {
  const std::optional<std::string> cmdline = util::read_file(cmdline_path, kMaxCmdlineSize);
  if (!cmdline) {
    return failed(kPackageSignal, kPackageSource);
  }
  const std::string_view package = package_name(*cmdline);
  if (package.empty()) {
    return failed(kPackageSignal, kPackageSource);
  }
  return observed(kPackageSignal, kPackageSource, std::string(package));
}

Observation observe_signer(std::span<const std::uint8_t> certificate) {
  if (certificate.empty()) {
    return failed(kSignerSignal, kSignerSource);
  }
  const std::optional<std::string> hash = sha256_hex(certificate);
  if (!hash) {
    return failed(kSignerSignal, kSignerSource);
  }
  return observed(kSignerSignal, kSignerSource, *hash);
}

#ifdef __ANDROID__

Observation observe_signer_jni(JNIEnv* env) {
  if (env == nullptr) {
    return failed(kSignerSignal, kSignerSource);
  }
  jobject context = current_application(env);
  if (context == nullptr) {
    return failed(kSignerSignal, kSignerSource);
  }
  const std::vector<std::uint8_t> certificate = signing_certificate(env, context);
  env->DeleteLocalRef(context);
  return observe_signer(certificate);
}

std::vector<Observation> identity(JNIEnv* env) {
  if (env == nullptr) {
    return {failed(kPackageSignal, kPackageSource), failed(kSignerSignal, kSignerSource)};
  }
  jobject context = current_application(env);
  if (context == nullptr) {
    return {failed(kPackageSignal, kPackageSource), failed(kSignerSignal, kSignerSource)};
  }
  // The application package from the Context is authoritative even for a process with a global or private name, where
  // the process name in /proc/self/cmdline isn't the package.
  const std::string package = package_of(env, context);
  const std::vector<std::uint8_t> certificate = signing_certificate(env, context);
  env->DeleteLocalRef(context);
  Observation package_observation =
      package.empty() ? failed(kPackageSignal, kPackageSource) : observed(kPackageSignal, kPackageSource, package);
  return {std::move(package_observation), observe_signer(certificate)};
}

#endif  // __ANDROID__

std::vector<Observation> identity() {
  if (!kOnAndroid) {
    return {unsupported(kPackageSignal, kPackageSource), unsupported(kSignerSignal, kSignerSource)};
  }
  // The signing certificate needs a JNIEnv to reach the Java PackageManager, which a load-time constructor doesn't
  // have, so the hash is reported unsupported here; identity(JNIEnv*) gathers it from a context that has one.
  return {observe_package(kCmdlinePath), unsupported(kSignerSignal, kSignerSource)};
}

}  // namespace rasp::android::checks
