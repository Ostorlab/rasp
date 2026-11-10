/// HTTP/1.1 for the transports that speak it themselves, such as the iOS one: the parts of the endpoint a connection
/// needs, the request of a post, and the status of the answer.

#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace rasp::plugins::reporting {

/// The longest status line an answer may start with, `\r\n` included. An answer whose first line is longer fails.
inline constexpr std::size_t kMaxStatusLineSize = 1024;

/// The parts of an `http://` or `https://` URL a post needs.
struct Endpoint {
  /// Whether the connection uses TLS: `true` for `https://`.
  bool tls = false;
  /// The host to connect to.
  std::string host;
  /// The port to connect to, in decimal: the URL's, or 443 for `https://` and 80 for `http://`.
  std::string port;
  /// The value of the request's `Host` header: the URL's host and port as they are written.
  std::string authority;
  /// The request target: the URL's path and query, `/` when it has no path. The fragment is not part of it.
  std::string target;
};

/// Splits an endpoint URL into the parts a post needs.
///
/// @param url An `http://` or `https://` URL with a host and an optional port.
/// @return The parts, or nothing when the URL is not such a URL or its port is not between 1 and 65535.
[[nodiscard]] std::optional<Endpoint> parse_endpoint(std::string_view url);

/// Makes the request of a post: a `POST` of the JSON body to the endpoint, with `Connection: close`, so the endpoint
/// ends the connection after its answer.
///
/// @param endpoint Where the body is posted.
/// @param body The JSON body.
/// @return The request, headers and body.
[[nodiscard]] std::string make_request(const Endpoint& endpoint, std::string_view body);

/// Reads the status code of an answer from its status line.
///
/// @param status_line The first line of the answer, without its `\r\n`, such as `HTTP/1.1 200 OK`.
/// @return The status code, or nothing when the line is not an HTTP/1.x status line.
[[nodiscard]] std::optional<int> parse_status(std::string_view status_line);

}  // namespace rasp::plugins::reporting
