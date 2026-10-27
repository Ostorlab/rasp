/// DNS resolver: resolves a DNS name with getaddrinfo to send an A-record query.

#include "rasp/reporting/dns_resolve.h"

#include <netdb.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>

namespace rasp::reporting {

bool resolve_name(const std::string& name) {
  struct addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_NUMERICSERV;

  struct addrinfo* result = nullptr;
  const int status = getaddrinfo(name.c_str(), "0", &hints, &result);
  if (result != nullptr) {
    freeaddrinfo(result);
  }
  return status == 0;
}

}  // namespace rasp::reporting
