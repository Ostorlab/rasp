/// The ADR server the runtime reports to.

#pragma once

#include <string_view>

namespace rasp {

/// The host name of the ADR server.
inline constexpr std::string_view kServerHost = "adr.ostorlab.co";

/// The path of the ADR server's GraphQL endpoint.
inline constexpr std::string_view kServerPath = "/apis/graphql";

}  // namespace rasp
