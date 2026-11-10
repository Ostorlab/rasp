/// The iOS transport: resolves the query name with the shared resolver.

#include "transport.h"

#include <string>

#include "resolver.h"

namespace rasp::plugins::dns_reporting {

bool resolve(const std::string& name) noexcept { return resolve_name(name); }

}  // namespace rasp::plugins::dns_reporting
