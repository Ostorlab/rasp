/// TlsTransport, the Android transport: sends each request to the ADR server over TLS done inside librasp.so, with
/// Mbed TLS and the trust anchors built into the library.

#pragma once

#include <chrono>
#include <string>
#include <string_view>

#include "rasp/reporting/transport.h"

namespace rasp::android {

/// Sends each request to the ADR server over HTTPS, with its own TCP socket and Mbed TLS, linked statically.
///
/// Each post opens a new TLS connection to the server on port 443, writes one HTTP/1.1 POST, waits for the start of
/// the server's answer, and closes the connection. TLS never goes through Java or the system's TLS library, so hooks
/// on those see nothing. The server's certificate must chain up to one of the trust anchors the build was configured
/// with (kTrustAnchors), and must be issued for the host name. The system's trust store and the user's certificates
/// are never used. Not thread-safe: one thread posts at a time.
class TlsTransport final : public Transport {
 public:
  /// Creates a transport for one endpoint of the ADR server. It connects to nothing until the first post.
  ///
  /// @param host The server's host name, such as adr.example.com. When it isn't made only of visible ASCII
  /// characters, every post returns without sending anything.
  /// @param path The path of the GraphQL endpoint on the server, such as /apis/graphql. When it doesn't start with a
  /// slash or isn't made only of visible ASCII characters, every post returns without sending anything.
  /// @param timeout The longest one post may take, from its start to the start of the answer. The name lookup counts
  /// against it, but can't be cut short, so it can run past it.
  TlsTransport(std::string host, std::string path, std::chrono::milliseconds timeout);

  /// Sends one request body to the server and waits for the start of its answer, then closes the connection.
  ///
  /// It blocks the calling thread until the start of the answer arrives, the server closes the connection, a step
  /// fails, or the timeout given to the constructor passes, whichever comes first. One deadline, set when the post
  /// starts, covers the connect, the TLS handshake, the write and the read. The name lookup with getaddrinfo comes
  /// first and can't be interrupted: it takes as long as the system's resolver takes, so one post can take longer than
  /// the timeout. It reads at most a few kilobytes of the answer and discards them, without parsing.
  ///
  /// A post that fails returns quietly: nothing is reported and nothing is retried. That includes no network, a
  /// server certificate that doesn't chain up to a trust anchor or isn't for the host name, and an app without the
  /// INTERNET permission, where the name lookup or socket() fails. When the build has no trust anchors, no handshake
  /// could succeed, so every post returns at once without connecting.
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
};

}  // namespace rasp::android
