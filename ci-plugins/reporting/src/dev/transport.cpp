/// The development transport, which a development machine builds the plugin with, only for the tests: it sends nothing,
/// so every post fails.

#include "transport.h"

#include <string_view>

#include "config.h"

namespace rasp::plugins::reporting {

bool post(const Config& /*config*/, std::string_view /*body*/) noexcept { return false; }

}  // namespace rasp::plugins::reporting
