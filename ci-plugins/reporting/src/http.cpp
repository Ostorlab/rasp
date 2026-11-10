/// HTTP/1.1 for the transports that speak it themselves: splits the endpoint URL, writes the request of a post, and
/// reads the status line of the answer.

#include "http.h"

#include <algorithm>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace rasp::plugins::reporting {

namespace {

/// The scheme of a TLS endpoint, and the port it defaults to.
constexpr std::string_view kHttpsScheme = "https://";
/// The default port of a TLS endpoint.
constexpr std::string_view kHttpsPort = "443";
/// The scheme of a plain endpoint.
constexpr std::string_view kHttpScheme = "http://";
/// The default port of a plain endpoint.
constexpr std::string_view kHttpPort = "80";
/// The highest port number.
constexpr int kMaxPort = 65535;
/// The longest port, in digits.
constexpr std::size_t kMaxPortDigits = 5;

/// Whether a character is a decimal digit.
///
/// @param character The character.
/// @return `true` for `0` to `9`.
[[nodiscard]] bool is_digit(char character) { return character >= '0' && character <= '9'; }

/// Whether a port, as written in a URL, is a number between 1 and 65535.
///
/// @param port The port, without the colon.
/// @return `true` when it is.
[[nodiscard]] bool is_valid_port(std::string_view port) {
  if (port.empty() || port.size() > kMaxPortDigits || !std::ranges::all_of(port, is_digit)) {
    return false;
  }
  int value = 0;
  for (const char digit : port) {
    value = (value * 10) + (digit - '0');
  }
  return value >= 1 && value <= kMaxPort;
}

}  // namespace

std::optional<Endpoint> parse_endpoint(std::string_view url) {
  Endpoint endpoint;
  std::string_view after_scheme;
  std::string_view default_port;
  if (url.starts_with(kHttpsScheme)) {
    endpoint.tls = true;
    after_scheme = url.substr(kHttpsScheme.size());
    default_port = kHttpsPort;
  } else if (url.starts_with(kHttpScheme)) {
    after_scheme = url.substr(kHttpScheme.size());
    default_port = kHttpPort;
  } else {
    return std::nullopt;
  }
  const std::size_t authority_end = std::min(after_scheme.find_first_of("/?#"), after_scheme.size());
  const std::string_view authority = after_scheme.substr(0, authority_end);
  const std::size_t colon = authority.find(':');
  const std::string_view host = authority.substr(0, colon);
  const std::optional<std::string_view> port =
      colon == std::string_view::npos ? std::nullopt : std::optional(authority.substr(colon + 1));
  if (host.empty() || (port.has_value() && !is_valid_port(*port))) {
    return std::nullopt;
  }
  endpoint.host = host;
  endpoint.port = port.value_or(default_port);
  endpoint.authority = authority;
  const std::string_view after_authority = after_scheme.substr(authority_end);
  const std::string_view target = after_authority.substr(0, after_authority.find('#'));
  endpoint.target = target.starts_with('/') ? std::string(target) : "/" + std::string(target);
  return endpoint;
}

std::string make_request(const Endpoint& endpoint, std::string_view body) {
  std::string request = "POST ";
  request.append(endpoint.target);
  request.append(" HTTP/1.1\r\nHost: ");
  request.append(endpoint.authority);
  request.append("\r\nContent-Type: application/json\r\nContent-Length: ");
  request.append(std::to_string(body.size()));
  request.append("\r\nConnection: close\r\n\r\n");
  request.append(body);
  return request;
}

std::optional<int> parse_status(std::string_view status_line) {
  constexpr std::string_view kVersion = "HTTP/1.";
  constexpr std::size_t kCodeStart = kVersion.size() + 2;
  constexpr std::size_t kCodeDigits = 3;
  if (!status_line.starts_with(kVersion) || status_line.size() < kCodeStart + kCodeDigits ||
      !is_digit(status_line[kVersion.size()]) || status_line[kVersion.size() + 1] != ' ') {
    return std::nullopt;
  }
  const std::string_view code = status_line.substr(kCodeStart, kCodeDigits);
  if (!std::ranges::all_of(code, is_digit) ||
      (status_line.size() > kCodeStart + kCodeDigits && status_line[kCodeStart + kCodeDigits] != ' ')) {
    return std::nullopt;
  }
  return ((code[0] - '0') * 100) + ((code[1] - '0') * 10) + (code[2] - '0');
}

}  // namespace rasp::plugins::reporting
