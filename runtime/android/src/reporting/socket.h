/// Socket and connect_socket: a TCP connection whose every step stops at a deadline, for the Android transport.

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace rasp::android {

/// The moment a whole post must be over by.
using Deadline = std::chrono::steady_clock::time_point;

/// A connected, non-blocking TCP socket, closed with its owner.
///
/// Each send and receive waits for the socket with poll, and gives up at the deadline it is given. Not thread-safe.
class Socket {
 public:
  /// Takes ownership of `descriptor`, a connected non-blocking TCP socket.
  ///
  /// @param descriptor The socket's file descriptor.
  explicit Socket(int descriptor) noexcept;
  /// Deleted: the socket owns its descriptor, which a copy would close twice.
  Socket(const Socket&) = delete;
  /// Deleted: the socket owns its descriptor, which a copy would close twice.
  Socket& operator=(const Socket&) = delete;
  /// Takes the descriptor of `other`, which then owns nothing.
  ///
  /// @param other The socket to move from.
  Socket(Socket&& other) noexcept;
  /// Deleted: no caller replaces a socket, and the transport never needs to.
  Socket& operator=(Socket&&) = delete;
  /// Closes the socket's descriptor.
  ~Socket();

  /// Sends the start of `data`, waiting until the socket can take it, but not past `deadline`.
  ///
  /// It never raises SIGPIPE, even when the server has closed the connection.
  ///
  /// @param data The bytes to send. It must not be empty.
  /// @param deadline The moment to give up at.
  /// @return How many bytes were sent, at least 1. Nothing when the deadline passed or the send failed.
  [[nodiscard]] std::optional<std::size_t> send_some(std::span<const std::uint8_t> data,
                                                     Deadline deadline) const noexcept;

  /// Receives the next bytes the server sent into `buffer`, waiting for them, but not past `deadline`.
  ///
  /// @param buffer Where to write the bytes. It must not be empty.
  /// @param deadline The moment to give up at.
  /// @return How many bytes were received, or 0 when the server closed the connection. Nothing when the deadline
  /// passed or the receive failed.
  [[nodiscard]] std::optional<std::size_t> receive_some(std::span<std::uint8_t> buffer,
                                                        Deadline deadline) const noexcept;

 private:
  /// The socket's file descriptor, or -1 once it was moved from.
  int descriptor_;
};

/// Opens a TCP connection to `host` on `port`, trying each address the host name resolves to, in the resolver's
/// order, until one connects.
///
/// Each connect is non-blocking and waits with poll, so connecting gives up at `deadline`. The name lookup comes first
/// and isn't bounded: getaddrinfo takes as long as the system's resolver takes, which can be past the deadline. Without
/// the INTERNET permission, the lookup or socket() fails, and no connection is made.
///
/// @param host The server's host name or IP address, such as adr.example.com.
/// @param port The server's TCP port, such as 443.
/// @param deadline The moment to give up at.
/// @return The connected socket, or nothing when the name doesn't resolve, no address connects, or the deadline passes.
[[nodiscard]] std::optional<Socket> connect_socket(const std::string& host, std::uint16_t port,
                                                   Deadline deadline) noexcept;

}  // namespace rasp::android
