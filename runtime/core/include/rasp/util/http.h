/// The text of an HTTP/1.1 POST request with a JSON body.

#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace rasp::http {

/// Builds the text of an HTTP/1.1 POST request with a JSON body, ready to write on a connection to the server.
///
/// The request is the request line (`POST`, the path and `HTTP/1.1`), then the headers `Host`, `Content-Type` set to
/// `application/json`, `Content-Length` set to the size of the body in bytes, and `Connection` set to `close`. Each
/// line ends with CR LF, an empty line ends the headers, and the body follows as it is.
///
/// The host and the path must be made only of visible ASCII characters (0x21 to 0x7E), and the path must start with
/// a slash. Anything else, such as a space, CR or LF, could change the request line or add a header, so the request
/// is refused.
///
/// @param host The server's host name, such as adr.example.com. It must not be empty.
/// @param path The path of the endpoint on the server, such as /apis/graphql.
/// @param body The request body, sent unchanged.
/// @return The request text, or nothing when the host or the path breaks the rules above.
[[nodiscard]] std::optional<std::string> post_request(std::string_view host, std::string_view path,
                                                      std::string_view body);

}  // namespace rasp::http
