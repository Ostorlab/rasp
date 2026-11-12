/// Bounded public Android service metadata; every JNI failure discards the affected observation.

#include "checks/service_exposure.h"

#include "rasp/observation.h"

#ifdef __ANDROID__
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <jni.h>
#if __has_include(<jni_md.h>)
#include <jni_md.h>
#endif
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "util/application_context.h"
#include "util/jni.h"
#include "util/service_components.h"

#endif

namespace rasp::android::checks {
namespace {
#ifdef __ANDROID__

/// Releases all references from a pass or item, including failure paths, on their owning thread.
class LocalFrame {
 public:
  /// Reserves bounded local references, clearing allocation exceptions.
  explicit LocalFrame(JNIEnv* env) : env_(env), ready_(env != nullptr && env->PushLocalFrame(24) == JNI_OK) {
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

/// Reads a component and, for accessibility only, its complete uint32 capability/request flag masks.
[[nodiscard]] std::optional<std::string> read_component(JNIEnv* env, jobject item, bool accessibility_metadata) {
  const auto raw = read_string(env, call_object(env, item, "getId", "()Ljava/lang/String;"), util::kMaxComponentBytes);
  if (!raw.has_value()) {
    return std::nullopt;
  }
  auto component = util::normalize_component(*raw);
  if (!component.has_value() || !accessibility_metadata) {
    return component;
  }
  const auto capabilities = call_int(env, item, "getCapabilities");
  if (!capabilities.has_value()) {
    return std::nullopt;
  }
  jclass type = env->GetObjectClass(item);
  if (util::threw(env) || type == nullptr) {
    return std::nullopt;
  }
  jfieldID flags_field = env->GetFieldID(type, "flags", "I");
  const bool lookup_failed = util::threw(env);
  env->DeleteLocalRef(type);
  if (lookup_failed || flags_field == nullptr) {
    return std::nullopt;
  }
  const jint flags = env->GetIntField(item, flags_field);
  if (util::threw(env)) {
    return std::nullopt;
  }
  *component += " capabilities=" + std::to_string(static_cast<std::uint32_t>(*capabilities)) +
                " flags=" + std::to_string(static_cast<std::uint32_t>(flags));
  return component;
}

/// Sorts and removes only identical complete records, preserving services with distinct masks.
void sort_unique(std::vector<std::string>& records) {
  std::ranges::sort(records);
  const auto duplicates = std::ranges::unique(records);
  records.erase(duplicates.begin(), duplicates.end());
}

/// Traverses the bounded public list with a fresh local frame per component and no partial-success return.
[[nodiscard]] std::optional<std::vector<std::string>> read_list(JNIEnv* env, jobject list, bool metadata) {
  const auto size = call_int(env, list, "size");
  if (!size.has_value() || *size < 0 || std::cmp_greater(*size, util::kMaxComponents)) {
    return std::nullopt;
  }
  std::vector<std::string> result;
  std::size_t total_bytes = 0;
  for (jint index = 0; index < *size; ++index) {
    const LocalFrame item_frame(env);
    if (!item_frame.ready()) {
      return std::nullopt;
    }
    const jvalue argument{.i = index};
    jobject item = call_object(env, list, "get", "(I)Ljava/lang/Object;", &argument);
    auto component = read_component(env, item, metadata);
    if (!component.has_value() || component->size() > util::kMaxObservationBytes - total_bytes) {
      return std::nullopt;
    }
    total_bytes += component->size();
    result.push_back(std::move(*component));
  }
  if (call_int(env, list, "size") != size) {
    return std::nullopt;
  }
  sort_unique(result);
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

/// Reads the AndroidX-compatible key via public Settings.Secure.getString, not a hidden field or manager API.
[[nodiscard]] std::optional<std::vector<std::string>> notification_components(JNIEnv* env) {
  const auto context = util::application_context(env);
  if (!context.has_value() || *context == nullptr) {
    return std::nullopt;
  }
  jobject resolver = call_object(env, *context, "getContentResolver", "()Landroid/content/ContentResolver;");
  if (resolver == nullptr) {
    return std::nullopt;
  }
  jclass settings = env->FindClass("android/provider/Settings$Secure");
  if (util::threw(env) || settings == nullptr) {
    return std::nullopt;
  }
  jmethodID get_string = env->GetStaticMethodID(
      settings, "getString", "(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;");
  if (util::threw(env) || get_string == nullptr) {
    return std::nullopt;
  }
  jstring key = env->NewStringUTF("enabled_notification_listeners");
  if (util::threw(env) || key == nullptr) {
    return std::nullopt;
  }
  const std::array<jvalue, 2> arguments{jvalue{.l = resolver}, jvalue{.l = key}};
  jobject value = env->CallStaticObjectMethodA(settings, get_string, arguments.data());
  if (util::threw(env)) {
    return std::nullopt;
  }
  const auto raw = read_string(env, value, util::kMaxObservationBytes);
  if (!raw.has_value()) {
    return std::nullopt;
  }
  return util::parse_notification_components(*raw);
}

/// Converts a complete list result without treating failures as empty lists.
[[nodiscard]] Observation list_observation(std::string_view signal, std::string_view source,
                                           std::optional<std::vector<std::string>> result) {
  return result.has_value() ? observed(signal, source, std::move(*result)) : failed(signal, source);
}

#endif
}  // namespace

std::vector<Observation> accessibility() {
#ifdef __ANDROID__
  constexpr std::string_view kSignal = "a11y.enabled_services";
  constexpr std::string_view kSource = "accessibility_manager";
  JNIEnv* env = util::attached_env();
  const LocalFrame frame(env);
  const auto api = frame.ready() ? sdk_level(env) : std::nullopt;
  if (!api.has_value()) {
    return {failed(kSignal, kSource)};
  }
  if (*api < 31) {
    return {unsupported(kSignal, kSource)};
  }
  jobject manager = service(env, "accessibility");
  const jvalue argument{.i = -1};
  jobject list = call_object(env, manager, "getEnabledAccessibilityServiceList", "(I)Ljava/util/List;", &argument);
  return {list_observation(kSignal, kSource, read_list(env, list, true))};
#else
  return {unsupported("a11y.enabled_services", "accessibility_manager")};
#endif
}

std::vector<Observation> input_method() {
#ifdef __ANDROID__
  constexpr std::string_view kEnabled = "ime.enabled_components";
  constexpr std::string_view kCurrent = "ime.current_component";
  constexpr std::string_view kSource = "input_method_manager";
  JNIEnv* env = util::attached_env();
  const LocalFrame frame(env);
  const auto api = frame.ready() ? sdk_level(env) : std::nullopt;
  if (!api.has_value()) {
    return {failed(kEnabled, kSource), failed(kCurrent, kSource)};
  }
  if (*api < 31) {
    return {unsupported(kEnabled, kSource), unsupported(kCurrent, kSource)};
  }
  jobject manager = service(env, "input_method");
  jobject list = call_object(env, manager, "getEnabledInputMethodList", "()Ljava/util/List;");
  Observation enabled = list_observation(kEnabled, kSource, read_list(env, list, false));
  if (*api < 34) {
    return {std::move(enabled), unsupported(kCurrent, kSource)};
  }
  jobject current =
      call_object(env, manager, "getCurrentInputMethodInfo", "()Landroid/view/inputmethod/InputMethodInfo;");
  auto component = read_component(env, current, false);
  return {
      std::move(enabled),
      component.has_value() ? observed(kCurrent, kSource, std::move(*component)) : failed(kCurrent, kSource),
  };
#else
  return {
      unsupported("ime.enabled_components", "input_method_manager"),
      unsupported("ime.current_component", "input_method_manager"),
  };
#endif
}

std::vector<Observation> notification_access() {
#ifdef __ANDROID__
  constexpr std::string_view kSignal = "notification.enabled_listeners";
  constexpr std::string_view kSource = "settings_secure";
  JNIEnv* env = util::attached_env();
  const LocalFrame frame(env);
  const auto api = frame.ready() ? sdk_level(env) : std::nullopt;
  if (!api.has_value()) {
    return {failed(kSignal, kSource)};
  }
  if (*api < 31) {
    return {unsupported(kSignal, kSource)};
  }
  return {list_observation(kSignal, kSource, notification_components(env))};
#else
  return {unsupported("notification.enabled_listeners", "settings_secure")};
#endif
}

}  // namespace rasp::android::checks
