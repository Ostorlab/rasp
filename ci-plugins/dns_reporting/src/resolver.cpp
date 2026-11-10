/// Resolves a DNS A-record query name with getaddrinfo, which Android and iOS both have.

#include "resolver.h"

#include <netdb.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>

#include "rasp/util/logging.h"

namespace rasp::plugins::dns_reporting {

bool resolve_name(const std::string& name) noexcept {
  struct addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_NUMERICSERV;

  struct addrinfo* result = nullptr;
  const int status = getaddrinfo(name.c_str(), "0", &hints, &result);
  if (result != nullptr) {
    freeaddrinfo(result);
  }
  if (status != 0) {
    if constexpr (kLoggingEnabled) {
      rasp::log("dns_reporting: resolve failed for " + name);
    }
    return false;
  }
  return true;
}

}  // namespace rasp::plugins::dns_reporting
