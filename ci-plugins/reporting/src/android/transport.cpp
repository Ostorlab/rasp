/// The Android transport: posts a request with libcurl, over TLS from Mbed TLS, both compiled into the runtime. It
/// trusts only the system's CA certificates, and checks the endpoint's certificate and host name.

#include "transport.h"

#include <chrono>
#include <cstddef>
#include <curl/curl.h>
#include <curl/easy.h>
#include <string>
#include <string_view>

#include "config.h"
#include "rasp/util/logging.h"

namespace rasp::plugins::reporting {

namespace {

/// The folder of the system's CA certificates, the only ones a post trusts. The CA certificates the user added are not
/// trusted.
constexpr const char* kSystemCaPath = "/system/etc/security/cacerts";

/// The schemes an endpoint may have.
constexpr const char* kProtocols = "http,https";

/// The connect timeout, in milliseconds, as libcurl takes it. It covers the host name lookup and the TLS handshake.
constexpr long kConnectTimeoutMs = static_cast<long>(std::chrono::milliseconds(kConnectTimeout).count());

/// How long, in seconds, a connected post may go on while less than a byte a second moves, before it ends.
constexpr long kResponseTimeoutSeconds = static_cast<long>(kResponseTimeout.count());

/// The timeout of a whole post, in milliseconds, as libcurl takes it.
constexpr long kPostTimeoutMs = static_cast<long>(std::chrono::milliseconds(kPostTimeout).count());

/// Drops the body of the answer, which the plugin doesn't read. It is libcurl's write callback, and it ignores the
/// bytes and the callback's context.
///
/// @param size Always 1.
/// @param count The number of bytes.
/// @return The number of bytes, so the post goes on.
std::size_t discard(char* /*data*/, std::size_t size, std::size_t count, void* /*context*/) { return size * count; }

/// Sets one option of a post.
///
/// @param handle The post's easy handle.
/// @param option The option.
/// @param value Its value, of the type libcurl takes for it.
/// @return `true` when libcurl accepted it.
template <typename Value>
[[nodiscard]] bool set(CURL* handle, CURLoption option, Value value) {
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): libcurl takes every option through this variadic function.
  return curl_easy_setopt(handle, option, value) == CURLE_OK;
}

/// Adds one line to a list of request headers.
///
/// @param headers The list, null when it is empty. It is updated only when the line was added.
/// @param line The header line, which the list copies.
/// @return `true` when it was added.
[[nodiscard]] bool append(curl_slist*& headers, const char* line) {
  curl_slist* const appended = curl_slist_append(headers, line);
  if (appended == nullptr) {
    return false;
  }
  headers = appended;
  return true;
}

/// Makes the request headers of a post: the JSON content type, and an empty Expect header, so the body is sent at once
/// instead of after a `100 Continue`.
///
/// @param headers The empty list to fill. It holds what was added even when a line could not be.
/// @return `true` when every line was added.
[[nodiscard]] bool make_headers(curl_slist*& headers) {
  return append(headers, "Content-Type: application/json") && append(headers, "Expect:");
}

/// Sends one post and reads the status of the answer. It sends no signal, follows no redirect, and allows TLS 1.2 or
/// newer only.
///
/// @param handle A new easy handle.
/// @param headers The request headers.
/// @param config The plugin's config. Only its endpoint is read.
/// @param body The request.
/// @return `true` when the endpoint answered with a 2xx status.
[[nodiscard]] bool send(CURL* handle, curl_slist* headers, const Config& config, std::string_view body) {
  const bool ready =
      set(handle, CURLOPT_NOSIGNAL, 1L) && set(handle, CURLOPT_URL, config.endpoint.c_str()) &&
      set(handle, CURLOPT_PROTOCOLS_STR, kProtocols) && set(handle, CURLOPT_FOLLOWLOCATION, 0L) &&
      set(handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1) &&
      set(handle, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2) && set(handle, CURLOPT_SSL_VERIFYPEER, 1L) &&
      set(handle, CURLOPT_SSL_VERIFYHOST, 2L) && set(handle, CURLOPT_CAPATH, kSystemCaPath) &&
      set(handle, CURLOPT_CONNECTTIMEOUT_MS, kConnectTimeoutMs) && set(handle, CURLOPT_LOW_SPEED_LIMIT, 1L) &&
      set(handle, CURLOPT_LOW_SPEED_TIME, kResponseTimeoutSeconds) && set(handle, CURLOPT_TIMEOUT_MS, kPostTimeoutMs) &&
      set(handle, CURLOPT_HTTPHEADER, headers) && set(handle, CURLOPT_WRITEFUNCTION, discard) &&
      set(handle, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size())) &&
      // NOLINTNEXTLINE(bugprone-suspicious-stringview-data-usage): CURLOPT_POSTFIELDSIZE gives libcurl the size.
      set(handle, CURLOPT_POSTFIELDS, body.data());
  if (!ready) {
    if constexpr (kLoggingEnabled) {
      rasp::log("reporting: the post failed: libcurl refused an option");
    }
    return false;
  }
  const CURLcode result = curl_easy_perform(handle);
  if (result != CURLE_OK) {
    if constexpr (kLoggingEnabled) {
      rasp::log("reporting: the post failed: libcurl error " + std::to_string(static_cast<int>(result)));
    }
    return false;
  }
  long status = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): libcurl gives every value through this variadic function.
  if (curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &status) != CURLE_OK) {
    if constexpr (kLoggingEnabled) {
      rasp::log("reporting: the post failed: libcurl gave no status");
    }
    return false;
  }
  if (status < 200 || status >= 300) {
    if constexpr (kLoggingEnabled) {
      rasp::log("reporting: the post failed: the endpoint answered " + std::to_string(status));
    }
    return false;
  }
  return true;
}

}  // namespace

bool post(const Config& config, std::string_view body) noexcept {
  static const bool kInitialised = curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK;
  if (!kInitialised) {
    if constexpr (kLoggingEnabled) {
      rasp::log("reporting: the post failed: libcurl did not initialise");
    }
    return false;
  }
  CURL* const handle = curl_easy_init();
  if (handle == nullptr) {
    if constexpr (kLoggingEnabled) {
      rasp::log("reporting: the post failed: libcurl gave no handle");
    }
    return false;
  }
  curl_slist* headers = nullptr;
  const bool posted = make_headers(headers) && send(handle, headers, config, body);
  curl_easy_cleanup(handle);
  curl_slist_free_all(headers);
  return posted;
}

}  // namespace rasp::plugins::reporting
