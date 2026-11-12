/// Public Android Context APIs with bounded JNI frames and no inventory or private fallback.
#include "checks/context_exposure.h"

#include "rasp/observation.h"
#ifdef __ANDROID__
#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <cstddef>
#include <jni.h>
#ifdef __BIONIC__
#include <linux/in6.h>
#else
#include <netinet/in.h>
#endif
#include <sys/socket.h>
#if __has_include(<jni_md.h>)
#include <jni_md.h>
#endif
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "util/application_context.h"
#include "util/jni.h"
#endif
namespace rasp::android::checks {
namespace {
#ifdef __ANDROID__
#include "root_manager_packages.h"
/// Releases all references from a pass or item, including failure paths, on their owning thread.
class LocalFrame {
 public:
  /// Reserves bounded local references, clearing allocation exceptions.
  explicit LocalFrame(JNIEnv* env, jint capacity = 24)
      : env_(env), ready_(env != nullptr && env->PushLocalFrame(capacity) == JNI_OK) {
    if (env != nullptr) {
      static_cast<void>(util::threw(env));
    }
  }
  /// Releases references only when the frame was successfully pushed.
  ~LocalFrame() {
    if (ready_) {
      env_->PopLocalFrame(nullptr);
    }
  }
  LocalFrame(const LocalFrame&) = delete;
  LocalFrame& operator=(const LocalFrame&) = delete;
  LocalFrame(LocalFrame&&) = delete;
  LocalFrame& operator=(LocalFrame&&) = delete;
  /// Whether this frame can safely receive local references.
  [[nodiscard]] bool ready() const { return ready_; }

 private:
  JNIEnv* env_;
  bool ready_;
};

/// Resolves one instance method on the actual Java object without retaining its class reference.
[[nodiscard]] jmethodID method(JNIEnv* env, jobject object, const char* name, const char* signature) {
  if (object == nullptr) {
    return nullptr;
  }
  jclass type = env->GetObjectClass(object);
  if (util::threw(env) || type == nullptr) {
    return nullptr;
  }
  jmethodID result = env->GetMethodID(type, name, signature);
  const bool failed = util::threw(env);
  env->DeleteLocalRef(type);
  return failed ? nullptr : result;
}

/// Calls one object-returning public method, treating null and exceptions as unavailable.
[[nodiscard]] jobject call_object(JNIEnv* env, jobject object, const char* name, const char* signature,
                                  const jvalue* arguments = nullptr) {
  jmethodID target = method(env, object, name, signature);
  if (target == nullptr) {
    return nullptr;
  }
  jobject result = env->CallObjectMethodA(object, target, arguments);
  return util::threw(env) ? nullptr : result;
}

/// Calls one int-returning public method with an independent error state.
[[nodiscard]] std::optional<jint> call_int(JNIEnv* env, jobject object, const char* name) {
  jmethodID target = method(env, object, name, "()I");
  if (target == nullptr) {
    return std::nullopt;
  }
  const jint result = env->CallIntMethodA(object, target, nullptr);
  return util::threw(env) ? std::nullopt : std::optional(result);
}

/// Reads the public SDK_INT before any version-specific method lookup.
[[nodiscard]] std::optional<jint> sdk_level(JNIEnv* env) {
  jclass version = env->FindClass("android/os/Build$VERSION");
  if (util::threw(env) || version == nullptr) {
    return std::nullopt;
  }
  jfieldID field = env->GetStaticFieldID(version, "SDK_INT", "I");
  if (util::threw(env) || field == nullptr) {
    return std::nullopt;
  }
  const jint result = env->GetStaticIntField(version, field);
  if (util::threw(env) || result <= 0) {
    return std::nullopt;
  }
  return result;
}

/// Copies bounded ASCII structural identifiers, rejecting non-ASCII, NUL and controls rather than truncating.
[[nodiscard]] std::optional<std::string> read_string(JNIEnv* env, jobject object, std::size_t limit) {
  if (object == nullptr) {
    return std::nullopt;
  }
  jclass string_class = env->FindClass("java/lang/String");
  if (util::threw(env) || string_class == nullptr) {
    return std::nullopt;
  }
  const jboolean is_string = env->IsInstanceOf(object, string_class);
  const bool failed = util::threw(env);
  env->DeleteLocalRef(string_class);
  if (failed || is_string == JNI_FALSE) {
    return std::nullopt;
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast): IsInstanceOf above verifies the String type.
  auto* string = static_cast<jstring>(object);
  const jsize length = env->GetStringLength(string);
  if (util::threw(env) || length < 0 || std::cmp_greater(length, limit)) {
    return std::nullopt;
  }
  std::vector<jchar> characters(static_cast<std::size_t>(length));
  if (length > 0) {
    env->GetStringRegion(string, 0, length, characters.data());
    if (util::threw(env)) {
      return std::nullopt;
    }
  }
  std::string result;
  result.reserve(characters.size());
  for (const jchar character : characters) {
    if (character < 0x21 || character > 0x7e) {
      return std::nullopt;
    }
    result.push_back(static_cast<char>(character));
  }
  return result;
}

/// Uses only the explicitly retained Application, never a private ActivityThread fallback.
[[nodiscard]] jobject service(JNIEnv* env, const char* name) {
  const auto context = util::application_context(env);
  if (!context.has_value() || *context == nullptr) {
    return nullptr;
  }
  jstring key = env->NewStringUTF(name);
  if (util::threw(env) || key == nullptr) {
    return nullptr;
  }
  const jvalue argument{.l = key};
  return call_object(env, *context, "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;", &argument);
}

/// Queries a fixed identifier; only NameNotFoundException is a visibility-limited negative result.
[[nodiscard]] std::optional<bool> visible_package(JNIEnv* env, jobject manager, jclass not_found, const char* name) {
  const LocalFrame frame(env, 8);
  if (!frame.ready()) {
    return std::nullopt;
  }
  jmethodID target = method(env, manager, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
  if (target == nullptr) {
    return std::nullopt;
  }
  jstring package = env->NewStringUTF(name);
  if (util::threw(env) || package == nullptr) {
    return std::nullopt;
  }
  const std::array arguments{jvalue{.l = package}, jvalue{.i = 0}};
  jobject info = env->CallObjectMethodA(manager, target, arguments.data());
  jthrowable exception = env->ExceptionOccurred();
  if (exception != nullptr) {
    env->ExceptionClear();
    const jboolean negative = env->IsInstanceOf(exception, not_found);
    if (util::threw(env) || negative == JNI_FALSE) {
      return std::nullopt;
    }
    return false;
  }
  return info != nullptr ? std::optional(true) : std::nullopt;
}
/// Reads exactly the public list-v1 names, preserving association and rejecting partial lists.
[[nodiscard]] std::optional<std::vector<std::string>> package_context(JNIEnv* env) {
  const auto context = util::application_context(env);
  if (!context.has_value() || *context == nullptr) {
    return std::nullopt;
  }
  jobject manager = call_object(env, *context, "getPackageManager", "()Landroid/content/pm/PackageManager;");
  if (manager == nullptr) {
    return std::nullopt;
  }
  jclass not_found = env->FindClass("android/content/pm/PackageManager$NameNotFoundException");
  if (util::threw(env) || not_found == nullptr) {
    return std::nullopt;
  }
  std::vector<std::string> result;
  for (const char* name : kRootManagerPackages) {
    const auto visible = visible_package(env, manager, not_found, name);
    if (!visible.has_value()) {
      return std::nullopt;
    }
    result.push_back(std::string(name) + (*visible ? " visible" : " not_visible"));
  }
  return result;
}
/// Validates bounded host-only DNS or IPv6 syntax; credentials and URI components are unrepresentable.
[[nodiscard]] bool valid_proxy_host(std::string_view host) {
  if (host.empty() || host.size() > 253) {
    return false;
  }
  if (host.contains(':')) {
    if (host.starts_with('[') && host.ends_with(']')) {
      host.remove_prefix(1);
      host.remove_suffix(1);
    }
    const std::string address(host);
    in6_addr parsed{};
    return inet_pton(AF_INET6, address.c_str(), &parsed) == 1;
  }
  if (host.ends_with('.')) {
    host.remove_suffix(1);
  }
  if (host.empty()) {
    return false;
  }
  for (const auto piece : std::views::split(host, '.')) {
    const std::string_view label(piece.begin(), piece.end());
    if (label.empty() || label.size() > 63 || label.starts_with('-') || label.ends_with('-') ||
        !std::ranges::all_of(label, [](unsigned char character) {
          return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
                 (character >= '0' && character <= '9') || character == '-';
        })) {
      return false;
    }
  }
  return true;
}
/// Uses public nullable PAC metadata without copying or fetching the URI; null and Uri.EMPTY both mean manual.
[[nodiscard]] std::optional<bool> pac_configured(JNIEnv* env, jobject info) {
  jmethodID target = method(env, info, "getPacFileUrl", "()Landroid/net/Uri;");
  if (target == nullptr) {
    return std::nullopt;
  }
  jobject pac = env->CallObjectMethodA(info, target, nullptr);
  if (util::threw(env)) {
    return std::nullopt;
  }
  if (pac == nullptr) {
    return false;
  }
  jclass uri = env->FindClass("android/net/Uri");
  if (util::threw(env) || uri == nullptr) {
    return std::nullopt;
  }
  jfieldID empty_field = env->GetStaticFieldID(uri, "EMPTY", "Landroid/net/Uri;");
  if (util::threw(env) || empty_field == nullptr) {
    return std::nullopt;
  }
  jobject empty = env->GetStaticObjectField(uri, empty_field);
  if (util::threw(env) || empty == nullptr) {
    return std::nullopt;
  }
  jmethodID equals = method(env, pac, "equals", "(Ljava/lang/Object;)Z");
  if (equals == nullptr) {
    return std::nullopt;
  }
  const jvalue argument{.l = empty};
  const jboolean is_empty = env->CallBooleanMethodA(pac, equals, &argument);
  if (util::threw(env)) {
    return std::nullopt;
  }
  return is_empty == JNI_FALSE;
}

/// Reads public ProxyInfo and Uri.EMPTY equality without copying, parsing or fetching any PAC URI.
[[nodiscard]] std::optional<std::vector<std::string>> proxy_context(JNIEnv* env) {
  jobject manager = service(env, "connectivity");
  jmethodID target = method(env, manager, "getDefaultProxy", "()Landroid/net/ProxyInfo;");
  if (target == nullptr) {
    return std::nullopt;
  }
  jobject info = env->CallObjectMethodA(manager, target, nullptr);
  if (util::threw(env)) {
    return std::nullopt;
  }
  if (info == nullptr) {
    return std::vector<std::string>{"mode=none"};
  }
  const auto pac = pac_configured(env, info);
  if (!pac.has_value()) {
    return std::nullopt;
  }
  if (*pac) {
    return std::vector<std::string>{"mode=pac"};
  }
  const auto host = read_string(env, call_object(env, info, "getHost", "()Ljava/lang/String;"), 253);
  const auto port = call_int(env, info, "getPort");
  if (!host.has_value() || !valid_proxy_host(*host) || !port.has_value() || *port < 1 || *port > 65535) {
    return std::nullopt;
  }
  return std::vector<std::string>{
      "mode=manual",
      "host=" + *host,
      "port=" + std::to_string(*port),
  };
}
/// Applies the public API floor before Context calls and preserves explicit unsupported/error states.
[[nodiscard]] std::vector<Observation> context_observation(
    std::string_view signal, std::string_view source, std::optional<std::vector<std::string>> (*collect)(JNIEnv*)) {
  JNIEnv* env = util::attached_env();
  const LocalFrame frame(env);
  const auto api = frame.ready() ? sdk_level(env) : std::nullopt;
  if (!api.has_value()) {
    return {failed(signal, source)};
  }
  if (*api < 31) {
    return {unsupported(signal, source)};
  }
  auto result = collect(env);
  return {result.has_value() ? observed(signal, source, std::move(*result)) : failed(signal, source)};
}
#endif
}  // namespace
std::vector<Observation> root_packages() {
#ifdef __ANDROID__
  return context_observation("root.manager_packages_v1", "package_manager", package_context);
#else
  return {unsupported("root.manager_packages_v1", "package_manager")};
#endif
}
std::vector<Observation> proxy() {
#ifdef __ANDROID__
  return context_observation("net.default_proxy_v1", "connectivity_manager", proxy_context);
#else
  return {unsupported("net.default_proxy_v1", "connectivity_manager")};
#endif
}
std::vector<Observation> developer_settings() {
  return {
      unsupported("debug.adb_enabled_v1", "settings_global"),
      unsupported("debug.developer_options_enabled_v1", "settings_global"),
  };
}
}  // namespace rasp::android::checks
