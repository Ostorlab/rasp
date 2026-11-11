/// The Android app-identity self-check: the package-name probe over the process's command line, the user-id probe over
/// the process's own uid, the code-path probe over the runtime's own library load path, the signer probe over the APK
/// Signing Block, and their unsupported results off Android.

#include "checks/identity.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#ifdef __ANDROID__
#include <algorithm>
#include <android/api-level.h>
#include <array>
#include <chrono>
#include <jni.h>
#include <thread>
#include <unistd.h>

#include "apk/archive.h"
#include "apk/location.h"
#include "util/jni.h"
#endif

#include "checks/integrity.h"
#include "rasp/observation.h"
#include "rasp/util/read_file.h"
#include "util/app_storage.h"

namespace rasp::android::checks {

namespace {

/// The signal of the package-name probe.
constexpr std::string_view kPackageSignal = "id.package";
/// The source of the package-name probe read at load time, from the process's command line.
constexpr std::string_view kPackageSource = "proc_cmdline";

/// The signal of the user-id probe.
constexpr std::string_view kUidSignal = "id.uid";
/// The source of the user-id probe, the process's own uid.
constexpr std::string_view kUidSource = "getuid";

/// The signal of the code-path probe.
constexpr std::string_view kCodePathSignal = "id.code_path";
/// The source of the code-path probe, the load path of the runtime's own library.
constexpr std::string_view kCodePathSource = "dladdr";

/// The signal of the signer probes.
constexpr std::string_view kSignerSignal = "sig.cert_sha256";
/// The source that reads the signer from the APK Signing Block of the APK the app runs from.
constexpr std::string_view kApkSigningBlockSource = "apk_signing_block";
/// The source that reads the signer from the package manager, through the app's own Context.
constexpr std::string_view kPackageManagerSource = "package_manager";

#ifdef __ANDROID__
/// The process's command line, whose first NUL-separated argument is the package name. Only identity() reads it, on a
/// device, so it is guarded; observe_package takes the path from its caller.
constexpr std::string_view kCmdlinePath = "/proc/self/cmdline";

/// The local references a pass of package_manager_certificate makes.
constexpr jint kLocalFrameCapacity = 16;
/// PackageManager.GET_SIGNING_CERTIFICATES, which fills PackageInfo.signingInfo.
constexpr jint kGetSigningCertificates = 0x08000000;
/// How long the thread waits between two looks for the app's Application.
constexpr std::chrono::milliseconds kApplicationWaitStep{50};
/// The most looks for the app's Application, five seconds in all, so an app that never creates one can't keep the
/// thread waiting.
constexpr int kApplicationWaitAttempts = 100;

/// Reads the signer's certificate from the package manager, inside a local frame that the caller pops.
///
/// It walks the app's own Context (ActivityThread.currentApplication) to PackageManager.getPackageInfo with
/// GET_SIGNING_CERTIFICATES, then SigningInfo.getApkContentsSigners and the first Signature's bytes. The runtime's
/// thread starts before Android creates the Application, so the first pass can get here while there is none yet: it
/// waits for it, at most kApplicationWaitAttempts looks kApplicationWaitStep apart, so that a failure of this read
/// isn't a state every cold start can produce.
///
/// @param env The thread's JNI environment.
/// @return The certificate's DER bytes, or nothing when a call fails or throws, there is no signer, or the Application
/// still doesn't exist after the wait.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> read_package_manager_certificate(JNIEnv* env) {
  jclass activity_thread = env->FindClass("android/app/ActivityThread");
  jclass context = env->FindClass("android/content/Context");
  jclass package_manager = env->FindClass("android/content/pm/PackageManager");
  jclass package_info = env->FindClass("android/content/pm/PackageInfo");
  jclass signing_info = env->FindClass("android/content/pm/SigningInfo");
  jclass signature = env->FindClass("android/content/pm/Signature");
  if (util::threw(env) || activity_thread == nullptr || context == nullptr || package_manager == nullptr ||
      package_info == nullptr || signing_info == nullptr || signature == nullptr) {
    return std::nullopt;
  }
  jmethodID current_application =
      env->GetStaticMethodID(activity_thread, "currentApplication", "()Landroid/app/Application;");
  jmethodID get_package_manager =
      env->GetMethodID(context, "getPackageManager", "()Landroid/content/pm/PackageManager;");
  jmethodID get_package_name = env->GetMethodID(context, "getPackageName", "()Ljava/lang/String;");
  jmethodID get_package_info =
      env->GetMethodID(package_manager, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
  jfieldID signing_info_field = env->GetFieldID(package_info, "signingInfo", "Landroid/content/pm/SigningInfo;");
  jmethodID get_signers = env->GetMethodID(signing_info, "getApkContentsSigners", "()[Landroid/content/pm/Signature;");
  jmethodID to_byte_array = env->GetMethodID(signature, "toByteArray", "()[B");
  if (util::threw(env) || current_application == nullptr || get_package_manager == nullptr ||
      get_package_name == nullptr || get_package_info == nullptr || signing_info_field == nullptr ||
      get_signers == nullptr || to_byte_array == nullptr) {
    return std::nullopt;
  }
  jobject application = nullptr;
  for (int attempt = 0; attempt < kApplicationWaitAttempts && application == nullptr; ++attempt) {
    if (attempt > 0) {
      std::this_thread::sleep_for(kApplicationWaitStep);
    }
    application = env->CallStaticObjectMethodA(activity_thread, current_application, nullptr);
    if (util::threw(env)) {
      return std::nullopt;
    }
  }
  if (application == nullptr) {
    return std::nullopt;
  }
  jobject manager = env->CallObjectMethodA(application, get_package_manager, nullptr);
  if (util::threw(env) || manager == nullptr) {
    return std::nullopt;
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast): getPackageName returns a String.
  auto* name = static_cast<jstring>(env->CallObjectMethodA(application, get_package_name, nullptr));
  if (util::threw(env) || name == nullptr) {
    return std::nullopt;
  }
  const std::array<jvalue, 2> arguments{jvalue{.l = name}, jvalue{.i = kGetSigningCertificates}};
  jobject info = env->CallObjectMethodA(manager, get_package_info, arguments.data());
  if (util::threw(env) || info == nullptr) {
    return std::nullopt;
  }
  jobject signers_info = env->GetObjectField(info, signing_info_field);
  if (util::threw(env) || signers_info == nullptr) {
    return std::nullopt;
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast): getApkContentsSigners returns a Signature[].
  auto* signers = static_cast<jobjectArray>(env->CallObjectMethodA(signers_info, get_signers, nullptr));
  if (util::threw(env) || signers == nullptr || env->GetArrayLength(signers) < 1) {
    return std::nullopt;
  }
  jobject first = env->GetObjectArrayElement(signers, 0);
  if (util::threw(env) || first == nullptr) {
    return std::nullopt;
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast): toByteArray returns a byte[].
  auto* bytes = static_cast<jbyteArray>(env->CallObjectMethodA(first, to_byte_array, nullptr));
  if (util::threw(env) || bytes == nullptr) {
    return std::nullopt;
  }
  const jsize length = env->GetArrayLength(bytes);
  if (length < 1) {
    return std::nullopt;
  }
  std::vector<jbyte> raw(static_cast<std::size_t>(length));
  env->GetByteArrayRegion(bytes, 0, length, raw.data());
  if (util::threw(env)) {
    return std::nullopt;
  }
  std::vector<std::uint8_t> certificate(raw.size());
  std::ranges::transform(raw, certificate.begin(), [](jbyte value) { return static_cast<std::uint8_t>(value); });
  return certificate;
}

/// The signer's certificate from the package manager, read through JNI on the calling thread, which is attached to the
/// app's Java VM for it. Every local reference is freed.
///
/// @return The certificate's DER bytes, or nothing when the thread can't reach the VM, or a call fails or throws.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> package_manager_certificate() {
  JNIEnv* env = util::attached_env();
  if (env == nullptr) {
    return std::nullopt;
  }
  if (env->PushLocalFrame(kLocalFrameCapacity) != JNI_OK) {
    static_cast<void>(util::threw(env));
    return std::nullopt;
  }
  const std::optional<std::vector<std::uint8_t>> certificate = read_package_manager_certificate(env);
  env->PopLocalFrame(nullptr);
  return certificate;
}
#endif

/// The largest command line read. A real one is well under this.
constexpr std::size_t kMaxCmdlineSize = std::size_t{64} << 10U;

}  // namespace

Observation observe_package(std::string_view cmdline_path) {
  const std::optional<std::string> cmdline = rasp::util::read_file(cmdline_path, kMaxCmdlineSize);
  if (!cmdline) {
    return failed(kPackageSignal, kPackageSource);
  }
  const std::string_view package = util::package_name(*cmdline);
  if (package.empty()) {
    return failed(kPackageSignal, kPackageSource);
  }
  return observed(kPackageSignal, kPackageSource, std::string(package));
}

Observation observe_uid(std::int64_t uid) { return observed(kUidSignal, kUidSource, uid); }

Observation observe_code_path(std::string_view code_path) {
  if (code_path.empty()) {
    return failed(kCodePathSignal, kCodePathSource);
  }
  return observed(kCodePathSignal, kCodePathSource, std::string(code_path));
}

namespace {

/// The sig.cert_sha256 observation for `source`: the SHA-256 of `certificate`, or an error when it is nothing or can't
/// be hashed.
[[nodiscard]] Observation signer_digest(std::string_view source,
                                        const std::optional<std::vector<std::uint8_t>>& certificate) {
  if (!certificate) {
    return failed(kSignerSignal, source);
  }
  const std::optional<std::string> digest = sha256_hex(*certificate);
  if (!digest) {
    return failed(kSignerSignal, source);
  }
  return observed(kSignerSignal, source, *digest);
}

}  // namespace

Observation observe_signer(const std::optional<std::vector<std::uint8_t>>& certificate) {
  return signer_digest(kApkSigningBlockSource, certificate);
}

Observation observe_package_manager_signer(const std::optional<std::vector<std::uint8_t>>& certificate) {
  return signer_digest(kPackageManagerSource, certificate);
}

std::vector<Observation> identity() {
#ifdef __ANDROID__
  const std::optional<std::string> code_path = apk::self_library_path();
  const std::optional<std::string> apk_path = apk::self_apk_path();
  const int api_level = android_get_device_api_level();
  return {
      observe_package(kCmdlinePath),
      observe_uid(static_cast<std::int64_t>(getuid())),
      observe_code_path(code_path.value_or(std::string())),
      observe_signer(apk_path && api_level > 0
                         ? apk::read_signing_certificate(*apk_path, static_cast<std::uint32_t>(api_level))
                         : std::nullopt),
      observe_package_manager_signer(package_manager_certificate()),
  };
#else
  return {
      unsupported(kPackageSignal, kPackageSource),       unsupported(kUidSignal, kUidSource),
      unsupported(kCodePathSignal, kCodePathSource),     unsupported(kSignerSignal, kApkSigningBlockSource),
      unsupported(kSignerSignal, kPackageManagerSource),
  };
#endif
}

}  // namespace rasp::android::checks
