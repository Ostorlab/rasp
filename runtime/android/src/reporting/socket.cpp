/// Socket: a non-blocking TCP socket driven with poll, and connect_socket, which tries each address of a host until
/// one connects or the deadline passes.

#include "reporting/socket.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <netdb.h>
#include <optional>
#include <poll.h>
#include <span>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>

namespace rasp::android {

namespace {

/// The type of each socket: TCP, non-blocking, and closed in any program the app's process executes.
constexpr int kSocketType =
    static_cast<int>(static_cast<unsigned int>(SOCK_STREAM) | static_cast<unsigned int>(SOCK_NONBLOCK) |
                     static_cast<unsigned int>(SOCK_CLOEXEC));

/// Frees an address list from getaddrinfo when the Addresses that owns it goes away.
struct AddressesRelease {
  /// Frees `addresses`.
  void operator()(addrinfo* addresses) const noexcept { freeaddrinfo(addresses); }
};

/// An address list from getaddrinfo, freed with its owner.
using Addresses = std::unique_ptr<addrinfo, AddressesRelease>;

/// Gives the whole milliseconds left until `deadline`, rounded up so that 0 means it has passed.
[[nodiscard]] int milliseconds_until(Deadline deadline) {
  const std::chrono::milliseconds::rep left =
      std::chrono::ceil<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
  return static_cast<int>(std::clamp<std::chrono::milliseconds::rep>(left, 0, std::numeric_limits<int>::max()));
}

/// Waits until `descriptor` is ready for `events` or has an error, but not past `deadline`, and says whether it is.
[[nodiscard]] bool wait_until_ready(int descriptor, short events, Deadline deadline) {
  pollfd entry{.fd = descriptor, .events = events, .revents = 0};
  for (int timeout = milliseconds_until(deadline); timeout > 0; timeout = milliseconds_until(deadline)) {
    const int ready = poll(&entry, 1, timeout);
    if (ready > 0) {
      return true;
    }
    if (ready < 0 && errno != EINTR) {
      return false;
    }
  }
  return false;
}

/// Connects a new socket to `address`, and gives it once it is connected, or nothing when the connect fails or
/// `deadline` passes.
[[nodiscard]] std::optional<Socket> connect_to(const addrinfo& address, Deadline deadline) {
  const int descriptor = socket(address.ai_family, kSocketType, address.ai_protocol);
  if (descriptor < 0) {
    return std::nullopt;
  }
  Socket connection{descriptor};
  if (connect(descriptor, address.ai_addr, address.ai_addrlen) == 0) {
    return connection;
  }
  if (errno != EINPROGRESS || !wait_until_ready(descriptor, POLLOUT, deadline)) {
    return std::nullopt;
  }
  int error = 0;
  socklen_t size = sizeof(error);
  if (getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &error, &size) != 0 || error != 0) {
    return std::nullopt;
  }
  return connection;
}

}  // namespace

Socket::Socket(int descriptor) noexcept : descriptor_(descriptor) {}

Socket::Socket(Socket&& other) noexcept : descriptor_(std::exchange(other.descriptor_, -1)) {}

Socket::~Socket() {
  if (descriptor_ >= 0) {
    static_cast<void>(close(descriptor_));
  }
}

std::optional<std::size_t> Socket::send_some(std::span<const std::uint8_t> data, Deadline deadline) const noexcept {
  while (wait_until_ready(descriptor_, POLLOUT, deadline)) {
    const ssize_t sent = send(descriptor_, data.data(), data.size(), MSG_NOSIGNAL);
    if (sent > 0) {
      return static_cast<std::size_t>(sent);
    }
    if (sent < 0 && errno != EAGAIN && errno != EINTR) {
      return std::nullopt;
    }
  }
  return std::nullopt;
}

std::optional<std::size_t> Socket::receive_some(std::span<std::uint8_t> buffer, Deadline deadline) const noexcept {
  while (wait_until_ready(descriptor_, POLLIN, deadline)) {
    const ssize_t received = recv(descriptor_, buffer.data(), buffer.size(), 0);
    if (received >= 0) {
      return static_cast<std::size_t>(received);
    }
    if (errno != EAGAIN && errno != EINTR) {
      return std::nullopt;
    }
  }
  return std::nullopt;
}

std::optional<Socket> connect_socket(const std::string& host, std::uint16_t port, Deadline deadline) noexcept {
  const addrinfo hints{
      .ai_flags = AI_ADDRCONFIG,
      .ai_family = AF_UNSPEC,
      .ai_socktype = SOCK_STREAM,
      .ai_protocol = 0,
      .ai_addrlen = 0,
      .ai_canonname = nullptr,
      .ai_addr = nullptr,
      .ai_next = nullptr,
  };
  addrinfo* found = nullptr;
  if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &found) != 0) {
    return std::nullopt;
  }
  const Addresses addresses{found};
  for (const addrinfo* address = addresses.get(); address != nullptr && milliseconds_until(deadline) > 0;
       address = address->ai_next) {
    std::optional<Socket> connection = connect_to(*address, deadline);
    if (connection.has_value()) {
      return connection;
    }
  }
  return std::nullopt;
}

}  // namespace rasp::android
