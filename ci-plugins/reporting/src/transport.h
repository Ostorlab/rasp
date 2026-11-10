/// The platform's HTTP(S) transport: posts one JSON request to the endpoint, with bounded timeouts.
///
/// On Android it uses libcurl, with Mbed TLS for TLS, both compiled into the runtime, and trusts only the system's CA
/// certificates. On iOS it uses a Network.framework connection, with the system's TLS and trust, and writes the
/// HTTP/1.1 request itself (`http.h`). Each platform has its own source file in a folder named after it. A development
/// machine, which builds the plugin only for the tests, uses the one in `dev/`, which sends nothing.

#pragma once

#include <chrono>
#include <string_view>

#include "config.h"

namespace rasp::plugins::reporting {

/// How long a post waits to connect to the endpoint.
inline constexpr std::chrono::seconds kConnectTimeout{10};

/// How long a post waits for the endpoint to answer, once connected.
inline constexpr std::chrono::seconds kResponseTimeout{10};

/// How long a whole post may take, from the request to the end of the answer.
inline constexpr std::chrono::seconds kPostTimeout = kConnectTimeout + kResponseTimeout;

/// Posts one JSON request to the endpoint, once, with the `Content-Type: application/json` header and no
/// authorization. Redirects are not followed and nothing is cached.
///
/// It blocks the calling thread until the endpoint answers, a timeout passes or the post fails. In a development build
/// it logs why a post failed.
///
/// @param config The plugin's config. Only its endpoint is read.
/// @param body The request.
/// @return `true` when the endpoint answered with a 2xx status.
[[nodiscard]] bool post(const Config& config, std::string_view body) noexcept;

}  // namespace rasp::plugins::reporting
