/// DNS resolver: sends a DNS A-record query by resolving a name with getaddrinfo.

#pragma once

#include <string>

namespace rasp::reporting {

/// Resolves a DNS name as an A-record query.
///
/// The resolution itself is the point: the DNS server sees the query name and extracts
/// the encoded data from it. The resolved address (always a TEST-NET address) is ignored.
///
/// @param name The DNS query name to resolve.
/// @return `true` when the resolution succeeded (the server received the query), `false` on failure.
[[nodiscard]] bool resolve_name(const std::string& name);

}  // namespace rasp::reporting
