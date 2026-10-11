/// NetworkTransport, the iOS transport: sends each request to the ADR server over HTTPS, with Network.framework.

#pragma once

#include <chrono>
#include <dispatch/dispatch.h>
#include <string>
#include <string_view>

#include "rasp/reporting/transport.h"

namespace rasp::ios {

/// Sends each request to the ADR server over HTTPS, with Network.framework's C API.
///
/// Each post opens a new TLS connection to the server on port 443, writes one HTTP/1.1 POST, waits for the start of
/// the server's answer, and closes the connection. The system checks the server's certificate. Not thread-safe: one
/// thread posts at a time.
class NetworkTransport final : public Transport {
 public:
  /// Creates a transport for one endpoint of the ADR server. It connects to nothing until the first post.
  ///
  /// @param host The server's host name, such as adr.example.com. When it isn't made only of visible ASCII
  /// characters, every post returns without sending anything.
  /// @param path The path of the GraphQL endpoint on the server, such as /apis/graphql. When it doesn't start with a
  /// slash or isn't made only of visible ASCII characters, every post returns without sending anything.
  /// @param timeout The longest one post may take, from opening the connection to the start of the answer.
  NetworkTransport(std::string host, std::string path, std::chrono::milliseconds timeout);
  /// Deleted: the transport owns its dispatch queue, which a copy would release twice.
  NetworkTransport(const NetworkTransport&) = delete;
  /// Deleted: the transport owns its dispatch queue, which a copy would release twice.
  NetworkTransport& operator=(const NetworkTransport&) = delete;
  /// Deleted: a moved-from transport would still release its dispatch queue.
  NetworkTransport(NetworkTransport&&) = delete;
  /// Deleted: a moved-from transport would still release its dispatch queue.
  NetworkTransport& operator=(NetworkTransport&&) = delete;
  /// Releases the transport's dispatch queue.
  ~NetworkTransport() override;

  /// Sends one request body to the server and waits for the start of its answer, then closes the connection.
  ///
  /// It blocks the calling thread until one of these happens, whichever comes first: the start of the answer arrives,
  /// the server closes the connection, the connection fails, or the timeout given to the constructor passes. It reads
  /// at most a few kilobytes of the answer and discards them, without parsing. A post that fails, for example with no
  /// network or a certificate the system refuses, returns quietly: nothing is reported and nothing is retried. A
  /// callback that arrives after the post has returned is harmless.
  ///
  /// @param body The JSON request body, as submit_event_request writes it.
  void post(std::string_view body) noexcept override;

 private:
  /// The server's host name.
  std::string host_;
  /// The path of the GraphQL endpoint.
  std::string path_;
  /// The longest one post may take.
  std::chrono::milliseconds timeout_;
  /// The serial queue the connections deliver their callbacks on, or nullptr when it couldn't be created.
  dispatch_queue_t queue_;
};

}  // namespace rasp::ios
