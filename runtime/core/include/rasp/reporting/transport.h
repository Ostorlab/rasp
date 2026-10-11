/// Transport, the interface each platform implements to send a request to the ADR server.

#pragma once

#include <string_view>

namespace rasp {

/// Sends a request body to the ADR server's GraphQL endpoint. Each platform implements it with its
/// own network stack.
class Transport {
 public:
  /// Creates the base part of a platform transport.
  Transport() = default;
  /// Deleted: copying a transport through this base class would copy only the base part.
  Transport(const Transport&) = delete;
  /// Deleted: assigning a transport through this base class would assign only the base part.
  Transport& operator=(const Transport&) = delete;
  /// Deleted: moving a transport through this base class would move only the base part.
  Transport(Transport&&) = delete;
  /// Deleted: move-assigning a transport through this base class would move only the base part.
  Transport& operator=(Transport&&) = delete;
  /// Destroys a platform transport through a pointer or a reference to this base class.
  virtual ~Transport() = default;

  /// Sends one request body to the ADR server's GraphQL endpoint with an HTTP POST.
  ///
  /// The implementation chooses the URL, the headers and the timeout. The runtime doesn't read the server's answer,
  /// and it never sends a request again, so this function reports nothing back, not even a failure.
  ///
  /// @param body The JSON request body, as submit_event_request writes it.
  virtual void post(std::string_view body) noexcept = 0;
};

}  // namespace rasp
