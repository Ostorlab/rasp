/// Resolves a DNS A-record query name with getaddrinfo, which Android and iOS both have.

#pragma once

#include <string>

namespace rasp::plugins::dns_reporting {

/// Resolves one DNS A-record query name.
///
/// The resolution itself is the point: the DNS server sees the query name and extracts the encoded data from it. The
/// resolved address is ignored.
///
/// @param name The fully qualified DNS name.
/// @return `true` when the name resolved (the server received the query).
[[nodiscard]] bool resolve_name(const std::string& name) noexcept;

}  // namespace rasp::plugins::dns_reporting
