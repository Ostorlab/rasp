/// The transport on a development machine: it sends nothing, so every resolve fails and every batch is dropped.

#include "transport.h"

#include <string>

namespace rasp::plugins::dns_reporting {

bool resolve(const std::string& /*name*/) noexcept { return false; }

}  // namespace rasp::plugins::dns_reporting
