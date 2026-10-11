/// NetworkTransport: one HTTPS connection per request, opened with Network.framework's C API.

#include "reporting/network_transport.h"

#include <Network/Network.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <dispatch/dispatch.h>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

#include "rasp/util/http.h"
#include "rasp/util/logging.h"

namespace rasp::ios {

namespace {

/// The most bytes of the server's answer that a post reads before it closes the connection.
constexpr std::uint32_t kMaxAnswerBytes = 4096;

/// Releases a dispatch semaphore when the Semaphore that owns it goes away.
struct SemaphoreRelease {
  /// Releases `semaphore`.
  void operator()(dispatch_semaphore_t semaphore) const noexcept { dispatch_release(semaphore); }
};

/// A dispatch semaphore, released with its owner.
using Semaphore = std::unique_ptr<std::remove_pointer_t<dispatch_semaphore_t>, SemaphoreRelease>;

/// What a post shares with its connection's callbacks, each of which keeps it alive with its own reference.
struct Exchange {
  /// Signalled each time a callback records that a step ended, or nullptr when it couldn't be created.
  Semaphore signal{dispatch_semaphore_create(0)};
  /// Whether the connection became ready.
  std::atomic<bool> connected{false};
  /// Whether the request was written.
  std::atomic<bool> sent{false};
  /// Whether the read of the answer ended: the answer started, the server closed the connection or the read failed.
  std::atomic<bool> received{false};
  /// Whether the start of the answer arrived.
  std::atomic<bool> answered{false};
  /// Whether the connection failed or was cancelled.
  std::atomic<bool> failed{false};
};

/// Waits until `done` is set or the connection fails, but not past `deadline`, and says whether `done` was set.
[[nodiscard]] bool wait_for(const Exchange& exchange, const std::atomic<bool>& done, dispatch_time_t deadline) {
  while (!done.load() && !exchange.failed.load()) {
    if (dispatch_semaphore_wait(exchange.signal.get(), deadline) != 0) {
      return false;
    }
  }
  return done.load();
}

/// Creates a TLS connection to `host` on port 443 with the system's default settings, or nullptr when that fails.
[[nodiscard]] nw_connection_t create_connection(const std::string& host) {
  nw_endpoint_t endpoint = nw_endpoint_create_host(host.c_str(), "443");
  if (endpoint == nullptr) {
    return nullptr;
  }
  nw_parameters_t parameters =
      nw_parameters_create_secure_tcp(NW_PARAMETERS_DEFAULT_CONFIGURATION, NW_PARAMETERS_DEFAULT_CONFIGURATION);
  if (parameters == nullptr) {
    nw_release(endpoint);
    return nullptr;
  }
  nw_connection_t connection = nw_connection_create(endpoint, parameters);
  nw_release(parameters);
  nw_release(endpoint);
  return connection;
}

/// Records in `exchange` when `connection` becomes ready, fails or is cancelled.
void watch_state(nw_connection_t connection, std::shared_ptr<Exchange> exchange) {
  nw_connection_set_state_changed_handler(connection, ^(nw_connection_state_t state, nw_error_t) {
    if (state == nw_connection_state_ready) {
      exchange->connected.store(true);
    } else if (state == nw_connection_state_failed || state == nw_connection_state_cancelled) {
      exchange->failed.store(true);
    } else {
      return;
    }
    dispatch_semaphore_signal(exchange->signal.get());
  });
}

/// Writes `request` on `connection`, and records in `exchange` when it was written or the write failed.
void send_request(nw_connection_t connection, const std::string& request, dispatch_queue_t queue,
                  std::shared_ptr<Exchange> exchange) {
  dispatch_data_t content =
      dispatch_data_create(request.data(), request.size(), queue, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
  if (content == nullptr) {
    exchange->failed.store(true);
    return;
  }
  nw_connection_send(connection, content, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true, ^(nw_error_t error) {
    if (error == nullptr) {
      exchange->sent.store(true);
    } else {
      exchange->failed.store(true);
    }
    dispatch_semaphore_signal(exchange->signal.get());
  });
  dispatch_release(content);
}

/// Asks `connection` for the start of the answer, and records in `exchange` whether it arrived and when the read ends.
void receive_answer(nw_connection_t connection, std::shared_ptr<Exchange> exchange) {
  nw_connection_receive(connection, 1, kMaxAnswerBytes,
                        ^(dispatch_data_t content, nw_content_context_t, bool, nw_error_t) {
                          exchange->answered.store(content != nullptr);
                          exchange->received.store(true);
                          dispatch_semaphore_signal(exchange->signal.get());
                        });
}

}  // namespace

NetworkTransport::NetworkTransport(std::string host, std::string path, std::chrono::milliseconds timeout)
    : host_(std::move(host)),
      path_(std::move(path)),
      timeout_(timeout),
      queue_(dispatch_queue_create(nullptr, DISPATCH_QUEUE_SERIAL)) {}

NetworkTransport::~NetworkTransport() {
  if (queue_ != nullptr) {
    dispatch_release(queue_);
  }
}

void NetworkTransport::post(std::string_view body) noexcept {
  const std::optional<std::string> request = http::post_request(host_, path_, body);
  if (queue_ == nullptr || !request.has_value()) {
    return;
  }
  const auto exchange = std::make_shared<Exchange>();
  if (exchange->signal == nullptr) {
    return;
  }
  nw_connection_t connection = create_connection(host_);
  if (connection == nullptr) {
    return;
  }
  const dispatch_time_t deadline =
      dispatch_time(DISPATCH_TIME_NOW, std::chrono::duration_cast<std::chrono::nanoseconds>(timeout_).count());
  nw_connection_set_queue(connection, queue_);
  watch_state(connection, exchange);
  nw_connection_start(connection);
  if (wait_for(*exchange, exchange->connected, deadline)) {
    send_request(connection, *request, queue_, exchange);
    if (wait_for(*exchange, exchange->sent, deadline)) {
      receive_answer(connection, exchange);
      static_cast<void>(wait_for(*exchange, exchange->received, deadline));
    }
  }
  if constexpr (kLoggingEnabled) {
    if (exchange->answered.load()) {
      rasp::log("transport: answered");
    } else if (exchange->sent.load()) {
      rasp::log("transport: sent, no answer");
    } else {
      rasp::log("transport: not sent");
    }
  }
  nw_connection_cancel(connection);
  nw_connection_set_state_changed_handler(connection, nullptr);
  nw_release(connection);
}

}  // namespace rasp::ios
