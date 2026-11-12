/// Explicitly selected compiled-in consumer proves the additive header and native platform symbols link for plugins.
#include "rasp/private_storage.h"

#include <span>
#include <string>

#include "rasp/context.h"
#include "rasp/observation.h"
#include "rasp/plugin.h"

namespace rasp::plugins::private_storage {
namespace {
constexpr Key<std::string> kIdentity{"test.private_storage.identity"};
/// Queries on the existing callback thread without repeating plugin init or creating sender threads.
void consume(std::span<const Observation> /*observations*/, Context& context) {
  const auto storage = acquire_private_storage();
  if (storage.has_value()) {
    context.put(kIdentity, std::string(storage->install_id()));
  }
}
}  // namespace
/// Build-only compiled-in plugin using the unchanged Plugin ABI.
extern constexpr Plugin kPlugin{.init = nullptr, .checks = {}, .on_observations = consume};
}  // namespace rasp::plugins::private_storage
