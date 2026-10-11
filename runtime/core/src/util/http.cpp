/// post_request: writes the text of an HTTP/1.1 POST request with a JSON body.

#include "rasp/util/http.h"

#include <algorithm>
#include <optional>
#include <string>
#include <string_view>

namespace rasp::http {

namespace {

/// Whether `text` is made only of visible ASCII characters, so it can't change the request line or add a header.
[[nodiscard]] bool is_visible_ascii(std::string_view text) {
  return std::ranges::all_of(text, [](char c) { return c > ' ' && c < '\x7f'; });
}

}  // namespace

std::optional<std::string> post_request(std::string_view host, std::string_view path, std::string_view body) {
  if (host.empty() || !is_visible_ascii(host) || !path.starts_with('/') || !is_visible_ascii(path)) {
    return std::nullopt;
  }
  std::string request = "POST ";
  request += path;
  request += " HTTP/1.1\r\nHost: ";
  request += host;
  request += "\r\nContent-Type: application/json\r\nContent-Length: ";
  request += std::to_string(body.size());
  request += "\r\nConnection: close\r\n\r\n";
  request += body;
  return request;
}

}  // namespace rasp::http
