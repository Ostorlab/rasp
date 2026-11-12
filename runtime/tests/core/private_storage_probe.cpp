/// Separate exec process proves durable identity across native creators and process restart, without unsafe fork work.
#include <chrono>
#include <cstddef>
#include <fcntl.h>
#include <span>
#include <string>
#include <string_view>
#include <sys/types.h>
#include <thread>
#include <unistd.h>

#include "rasp/posix/private_storage.h"
#include "rasp/private_storage.h"

/// Runs a bounded real storage consumer and optionally verifies a previous process's identity.
int main(int argument_count, char* const* arguments) {
  if (argument_count != 4) {
    return 2;
  }
  const std::span values(arguments, static_cast<std::size_t>(argument_count));
  for (int attempt = 0; attempt < 100; ++attempt) {
    auto storage = rasp::posix::acquire_private_storage_at(values[1]);
    if (!storage.has_value()) {
      if (storage.error() != rasp::StorageError::kBusy) {
        return 3;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
      continue;
    }
    const std::string identity(storage->install_id());
    if (!std::string_view(values[3]).empty() && identity != values[3]) {
      return 4;
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): required POSIX API with explicit bounded arguments.
    const int descriptor = openat(storage->native_handle(), values[2],
                                  O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600);
    if (descriptor < 0) {
      return 5;
    }
    const bool written = write(descriptor, identity.data(), identity.size()) == static_cast<ssize_t>(identity.size());
    const bool synced = fsync(descriptor) == 0;
    const bool closed = close(descriptor) == 0;
    const bool directory_synced = fsync(storage->native_handle()) == 0;
    return written && synced && closed && directory_synced && storage->close().has_value() ? 0 : 6;
  }
  return 7;
}
