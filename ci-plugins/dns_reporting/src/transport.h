/// The platform's DNS transport: resolves one DNS A-record query name.
///
/// Each platform has its own source file in a folder named after it. Android and iOS both resolve with getaddrinfo, so
/// their transports call the shared resolver of resolver.h and hold no resolving code of their own. On a development
/// machine, where the plugin builds only for the tests, nothing is sent.

#pragma once

#include <string>

namespace rasp::plugins::dns_reporting {

/// Resolves one DNS A-record query name.
///
/// The resolution itself is the point: the DNS server sees the query name and extracts
/// the encoded data from it. The resolved address is ignored.
///
/// @param name The fully qualified DNS name.
/// @return `true` when the name resolved (the server received the query).
[[nodiscard]] bool resolve(const std::string& name) noexcept;

}  // namespace rasp::plugins::dns_reporting
