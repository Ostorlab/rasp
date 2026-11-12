/// Source-compatible legacy identity entry, sharing the verified writer and private lock with durable storage.
#include "rasp/install_id.h"

#include <chrono>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <unistd.h>
#include <utility>

#include "rasp/posix/private_storage.h"
#include "rasp/private_storage.h"

namespace rasp {
std::optional<std::string> load_or_create_install_id(std::string_view directory) {
  const auto parent = posix::open_private_directory(directory);
  if (!parent.has_value()) {
    return std::nullopt;
  }
  auto identity = posix::load_private_install_id(*parent);
  for (int attempt = 1; !identity.has_value() && identity.error() == StorageError::kBusy && attempt < 11; ++attempt) {
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    identity = posix::load_private_install_id(*parent);
  }
  const bool closed = close(*parent) == 0;
  if (!identity.has_value() || !closed) {
    return std::nullopt;
  }
  return std::move(*identity);
}
}  // namespace rasp
