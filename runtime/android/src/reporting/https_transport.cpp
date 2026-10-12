/// HttpsTransport: one HttpsURLConnection per request, driven through JNI.

#include "reporting/https_transport.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <jni.h>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include "rasp/util/logging.h"

namespace rasp::android {

namespace {

/// The most local references one post creates, which the local frame around it makes room for.
constexpr jint kLocalReferences = 16;

/// How far a post got.
enum class Stage : std::uint8_t {
  /// The request wasn't written.
  kNotSent,
  /// The request was written, but no answer started.
  kSent,
  /// The start of the answer arrived.
  kAnswered,
};

/// Whether `text` is made only of visible ASCII characters.
[[nodiscard]] bool is_visible_ascii(std::string_view text) {
  return std::ranges::all_of(text, [](char c) { return c > ' ' && c < '\x7f'; });
}

/// Gives the endpoint's URL, or nothing when the host is empty or not visible ASCII, or the path isn't a visible
/// ASCII path that starts with a slash.
[[nodiscard]] std::optional<std::string> endpoint_url(std::string_view host, std::string_view path) {
  if (host.empty() || !is_visible_ascii(host) || !path.starts_with('/') || !is_visible_ascii(path)) {
    return std::nullopt;
  }
  std::string url = "https://";
  url += host;
  url += path;
  return url;
}

/// Converts `timeout` to Java milliseconds, from 1, since Java reads 0 as no timeout, up to the largest jint.
[[nodiscard]] jint to_java_timeout(std::chrono::milliseconds timeout) {
  return static_cast<jint>(
      std::clamp<std::chrono::milliseconds::rep>(timeout.count(), 1, std::numeric_limits<jint>::max()));
}

/// Clears the pending Java exception, if there is one, and says whether there was.
[[nodiscard]] bool threw(JNIEnv& env) {
  if (env.ExceptionCheck() == JNI_FALSE) {
    return false;
  }
  env.ExceptionClear();
  return true;
}

/// Finds the class named `name`, such as java/net/URL, or gives null when Java throws.
[[nodiscard]] jclass find_class(JNIEnv& env, const char* name) {
  jclass type = env.FindClass(name);
  return threw(env) ? nullptr : type;
}

/// Finds the instance method `name` of `type` with the JNI signature `signature`, or gives null when Java throws.
[[nodiscard]] jmethodID find_method(JNIEnv& env, jclass type, const char* name, const char* signature) {
  jmethodID method = env.GetMethodID(type, name, signature);
  return threw(env) ? nullptr : method;
}

/// Makes a Java string of `text`, which must be ASCII, or gives null when Java throws.
[[nodiscard]] jstring to_java_string(JNIEnv& env, const char* text) {
  jstring string = env.NewStringUTF(text);
  return threw(env) ? nullptr : string;
}

/// Makes a Java byte array that holds the bytes of `body`, or gives null when Java throws or `body` is too long.
[[nodiscard]] jbyteArray to_java_bytes(JNIEnv& env, std::string_view body) {
  if (body.size() > static_cast<std::size_t>(std::numeric_limits<jsize>::max())) {
    return nullptr;
  }
  jbyteArray array = env.NewByteArray(static_cast<jsize>(body.size()));
  if (threw(env) || array == nullptr) {
    return nullptr;
  }
  void* const elements = env.GetPrimitiveArrayCritical(array, nullptr);
  if (elements == nullptr) {
    static_cast<void>(threw(env));
    return nullptr;
  }
  std::ranges::copy(body, static_cast<char*>(elements));
  env.ReleasePrimitiveArrayCritical(array, elements, 0);
  return threw(env) ? nullptr : array;
}

/// Calls the method `name` of `type`, which returns nothing, on `object`, and says whether it returned without
/// throwing.
[[nodiscard]] bool call_void(JNIEnv& env, jobject object, jclass type, const char* name, const char* signature,
                             std::span<const jvalue> arguments = {}) {
  jmethodID method = find_method(env, type, name, signature);
  if (method == nullptr) {
    return false;
  }
  env.CallVoidMethodA(object, method, arguments.data());
  return !threw(env);
}

/// Calls the method `name` of `type`, which takes no argument and returns an object, on `object`, and gives what it
/// returns, or null when it throws.
[[nodiscard]] jobject call_object(JNIEnv& env, jobject object, jclass type, const char* name, const char* signature) {
  jmethodID method = find_method(env, type, name, signature);
  if (method == nullptr) {
    return nullptr;
  }
  jobject result = env.CallObjectMethodA(object, method, nullptr);
  return threw(env) ? nullptr : result;
}

/// Calls the method `name` of `type`, which takes no argument and returns an int, on `object`, and gives what it
/// returns, or nothing when it throws.
[[nodiscard]] std::optional<jint> call_int(JNIEnv& env, jobject object, jclass type, const char* name,
                                           const char* signature) {
  jmethodID method = find_method(env, type, name, signature);
  if (method == nullptr) {
    return std::nullopt;
  }
  const jint result = env.CallIntMethodA(object, method, nullptr);
  if (threw(env)) {
    return std::nullopt;
  }
  return result;
}

/// Opens a connection to `url` with java.net.URL, or gives null when Java throws or the connection isn't an
/// `https_class`.
[[nodiscard]] jobject open_connection(JNIEnv& env, const std::string& url, jclass https_class) {
  jclass url_class = find_class(env, "java/net/URL");
  if (url_class == nullptr) {
    return nullptr;
  }
  jmethodID constructor = find_method(env, url_class, "<init>", "(Ljava/lang/String;)V");
  if (constructor == nullptr) {
    return nullptr;
  }
  jstring text = to_java_string(env, url.c_str());
  if (text == nullptr) {
    return nullptr;
  }
  const std::array arguments{jvalue{.l = text}};
  jobject address = env.NewObjectA(url_class, constructor, arguments.data());
  if (threw(env) || address == nullptr) {
    return nullptr;
  }
  jobject connection = call_object(env, address, url_class, "openConnection", "()Ljava/net/URLConnection;");
  if (connection == nullptr) {
    return nullptr;
  }
  const jboolean is_https = env.IsInstanceOf(connection, https_class);
  if (threw(env) || is_https == JNI_FALSE) {
    return nullptr;
  }
  return connection;
}

/// Sets `connection` up for one POST of a JSON body `length` bytes long, and says whether Java accepted every setting.
[[nodiscard]] bool configure(JNIEnv& env, jobject connection, jclass https_class, jint timeout, jlong length) {
  jstring method = to_java_string(env, "POST");
  jstring header = to_java_string(env, "Content-Type");
  jstring type = to_java_string(env, "application/json");
  if (method == nullptr || header == nullptr || type == nullptr) {
    return false;
  }
  return call_void(env, connection, https_class, "setRequestMethod", "(Ljava/lang/String;)V",
                   std::array{jvalue{.l = method}}) &&
         call_void(env, connection, https_class, "setDoOutput", "(Z)V", std::array{jvalue{.z = JNI_TRUE}}) &&
         call_void(env, connection, https_class, "setConnectTimeout", "(I)V", std::array{jvalue{.i = timeout}}) &&
         call_void(env, connection, https_class, "setReadTimeout", "(I)V", std::array{jvalue{.i = timeout}}) &&
         call_void(env, connection, https_class, "setRequestProperty", "(Ljava/lang/String;Ljava/lang/String;)V",
                   std::array{jvalue{.l = header}, jvalue{.l = type}}) &&
         call_void(env, connection, https_class, "setFixedLengthStreamingMode", "(J)V",
                   std::array{jvalue{.j = length}});
}

/// Writes `body` to the output stream of `connection`, which connects it, then closes the stream, and says whether
/// both worked.
[[nodiscard]] bool write_body(JNIEnv& env, jobject connection, jclass https_class, std::string_view body) {
  jobject stream = call_object(env, connection, https_class, "getOutputStream", "()Ljava/io/OutputStream;");
  if (stream == nullptr) {
    return false;
  }
  jclass stream_class = find_class(env, "java/io/OutputStream");
  if (stream_class == nullptr) {
    return false;
  }
  jbyteArray bytes = to_java_bytes(env, body);
  if (bytes == nullptr) {
    return false;
  }
  return call_void(env, stream, stream_class, "write", "([B)V", std::array{jvalue{.l = bytes}}) &&
         call_void(env, stream, stream_class, "close", "()V");
}

/// Opens a connection to `url`, posts `body` on it, waits for the start of the answer, and disconnects, and says how
/// far the post got.
[[nodiscard]] Stage send(JNIEnv& env, const std::string& url, std::string_view body, jint timeout) {
  jclass https_class = find_class(env, "javax/net/ssl/HttpsURLConnection");
  if (https_class == nullptr) {
    return Stage::kNotSent;
  }
  jobject connection = open_connection(env, url, https_class);
  if (connection == nullptr) {
    return Stage::kNotSent;
  }
  Stage stage = Stage::kNotSent;
  if (configure(env, connection, https_class, timeout, static_cast<jlong>(body.size())) &&
      write_body(env, connection, https_class, body)) {
    stage =
        call_int(env, connection, https_class, "getResponseCode", "()I").has_value() ? Stage::kAnswered : Stage::kSent;
  }
  static_cast<void>(call_void(env, connection, https_class, "disconnect", "()V"));
  return stage;
}

/// Writes how far a post got to the system log, in a development build.
void log_stage(Stage stage) {
  if constexpr (kLoggingEnabled) {
    if (stage == Stage::kAnswered) {
      rasp::log("transport: answered");
    } else if (stage == Stage::kSent) {
      rasp::log("transport: sent, no answer");
    } else {
      rasp::log("transport: not sent");
    }
  }
}

}  // namespace

HttpsTransport::HttpsTransport(JNIEnv* env, std::string host, std::string path, std::chrono::milliseconds timeout)
    : env_(env), host_(std::move(host)), path_(std::move(path)), timeout_(timeout) {}

void HttpsTransport::post(std::string_view body) noexcept {
  const std::optional<std::string> url = endpoint_url(host_, path_);
  if (env_ == nullptr || !url.has_value()) {
    return;
  }
  if (env_->PushLocalFrame(kLocalReferences) != JNI_OK) {
    static_cast<void>(threw(*env_));
    return;
  }
  log_stage(send(*env_, *url, body, to_java_timeout(timeout_)));
  static_cast<void>(env_->PopLocalFrame(nullptr));
}

}  // namespace rasp::android
