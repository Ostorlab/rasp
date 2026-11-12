/// Source-compatible legacy identity entry, sharing the verified writer and private lock with durable storage.
#include "rasp/install_id.h"

#include <optional>
#include <string>
#include <string_view>
#include <unistd.h>
#include <utility>

#include "rasp/posix/private_storage.h"

namespace rasp {
std::optional<std::string> load_or_create_install_id(std::string_view directory) {
  const auto parent = posix::open_private_directory(directory);
  if (!parent.has_value()) {
    return std::nullopt;
  }
  auto identity = posix::load_private_install_id(*parent);
  const bool closed = close(*parent) == 0;
  if (!identity.has_value() || !closed) {
    return std::nullopt;
  }
  return std::move(*identity);
}
}  // namespace rasp
