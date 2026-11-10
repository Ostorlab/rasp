/// The iOS transport: posts a request over a Network.framework connection, with TLS for `https://` endpoints, and
/// speaks HTTP/1.1 itself. TLS checks the endpoint's certificate and host name against the system's trust, and allows
/// TLS 1.2 or newer only.

#include "transport.h"

#include <Network/Network.h>
#include <Security/SecProtocolOptions.h>
#include <Security/SecProtocolTypes.h>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <dispatch/dispatch.h>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>

#include "config.h"
#include "http.h"
#include "rasp/util/logging.h"

namespace rasp::plugins::reporting {

namespace {

/// The most bytes one receive reads.
constexpr std::uint32_t kMaxReceiveSize = 1024;

/// Releases a dispatch object when the pointer that owns it goes away.
struct DispatchRelease {
  /// Releases `object`.
  void operator()(dispatch_object_t object) const noexcept { dispatch_release(object); }
};

/// A dispatch semaphore, released with its owner.
using Semaphore = std::unique_ptr<std::remove_pointer_t<dispatch_semaphore_t>, DispatchRelease>;
/// A dispatch queue, released with its owner.
using Queue = std::unique_ptr<std::remove_pointer_t<dispatch_queue_t>, DispatchRelease>;

/// What the connection's blocks share with the thread that waits for them. The blocks keep it alive after a timeout.
struct Exchange {
  /// Signalled whenever one of the flags below is set, or a receive ends.
  Semaphore signal{dispatch_semaphore_create(0)};
  /// Set once the connection is ready to send.
  std::atomic<bool> ready{false};
  /// Set once the connection failed, or the endpoint ended it.
  std::atomic<bool> failed{false};
  /// Set once the request was sent.
  std::atomic<bool> sent{false};
  /// Set while a receive is pending.
  std::atomic<bool> receiving{false};
  /// Guards `answer`.
  std::mutex mutex;
  /// The first bytes of the answer, at most kMaxStatusLineSize.
  std::string answer;
};

/// Waits until a condition holds or the connection fails.
///
/// @param exchange What the connection's blocks share with this thread.
/// @param holds The condition, which the blocks make true.
/// @param deadline When to stop waiting.
/// @return `true` when the condition holds, `false` when the connection failed or the deadline passed.
template <typename Condition>
[[nodiscard]] bool wait_for(Exchange& exchange, Condition holds, dispatch_time_t deadline) {
  while (!holds()) {
    if (exchange.failed.load() || dispatch_semaphore_wait(exchange.signal.get(), deadline) != 0) {
      return holds();
    }
  }
  return true;
}

/// Creates the connection to the endpoint, with TLS 1.2 or newer for an `https://` one.
///
/// @param endpoint The endpoint.
/// @return The connection, or null when it can't be created.
[[nodiscard]] nw_connection_t create_connection(const Endpoint& endpoint) {
  auto* const host = nw_endpoint_create_host(endpoint.host.c_str(), endpoint.port.c_str());
  if (host == nullptr) {
    return nullptr;
  }
  auto* const parameters = endpoint.tls ? nw_parameters_create_secure_tcp(
                                              ^(nw_protocol_options_t tls_options) {
                                                auto* const options = nw_tls_copy_sec_protocol_options(tls_options);
                                                sec_protocol_options_set_tls_min_version(options, kTLSProtocol12);
                                                sec_release(options);
                                              },
                                              NW_PARAMETERS_DEFAULT_CONFIGURATION)
                                        : nw_parameters_create_secure_tcp(NW_PARAMETERS_DISABLE_PROTOCOL,
                                                                          NW_PARAMETERS_DEFAULT_CONFIGURATION);
  if (parameters == nullptr) {
    nw_release(host);
    return nullptr;
  }
  auto* const connection = nw_connection_create(host, parameters);
  nw_release(parameters);
  nw_release(host);
  return connection;
}

/// Starts one receive, which appends what it reads to the answer, up to kMaxStatusLineSize bytes.
///
/// @param connection The connection.
/// @param exchange What the connection's blocks share with the waiting thread.
void receive(nw_connection_t connection, const std::shared_ptr<Exchange>& exchange) {
  exchange->receiving.store(true);
  nw_connection_receive(connection, 1, kMaxReceiveSize,
                        ^(dispatch_data_t content, nw_content_context_t, bool is_complete, nw_error_t error) {
                          if (content != nullptr) {
                            dispatch_data_apply(
                                content, ^bool(dispatch_data_t, std::size_t, const void* buffer, std::size_t size) {
                                  const std::scoped_lock lock(exchange->mutex);
                                  const std::size_t room = kMaxStatusLineSize - exchange->answer.size();
                                  const std::span bytes(static_cast<const char*>(buffer), size < room ? size : room);
                                  exchange->answer.append(bytes.begin(), bytes.end());
                                  return exchange->answer.size() < kMaxStatusLineSize;
                                });
                          }
                          if (error != nullptr || is_complete) {
                            exchange->failed.store(true);
                          }
                          exchange->receiving.store(false);
                          dispatch_semaphore_signal(exchange->signal.get());
                        });
}

/// What the answer holds so far.
struct Answer {
  /// The status line without its `\r\n`, once the answer holds it.
  std::optional<std::string> status_line;
  /// Whether the answer reached kMaxStatusLineSize bytes, so no more of it is read.
  bool full = false;
};

/// Reads what the answer holds so far.
///
/// @param exchange What the connection's blocks share with the waiting thread.
/// @return The status line once the answer holds it, and whether the answer is full.
[[nodiscard]] Answer read_answer(Exchange& exchange) {
  const std::scoped_lock lock(exchange.mutex);
  const std::size_t end = exchange.answer.find("\r\n");
  return Answer{
      .status_line = end == std::string::npos ? std::nullopt : std::optional(exchange.answer.substr(0, end)),
      .full = exchange.answer.size() >= kMaxStatusLineSize,
  };
}

/// Sends the request on a started connection and reads the status of the answer.
///
/// @param connection The connection, started on its queue.
/// @param exchange What the connection's blocks share with this thread.
/// @param request The request.
/// @param endpoint The endpoint, for the logs.
/// @return The status of the answer, or nothing when the post failed or timed out.
[[nodiscard]] std::optional<int> exchange_request(nw_connection_t connection, const std::shared_ptr<Exchange>& exchange,
                                                  const std::string& request, const Endpoint& endpoint) {
  const dispatch_time_t connected_by =
      dispatch_time(DISPATCH_TIME_NOW, std::chrono::duration_cast<std::chrono::nanoseconds>(kConnectTimeout).count());
  if (!wait_for(*exchange, [&exchange] { return exchange->ready.load(); }, connected_by)) {
    if constexpr (kLoggingEnabled) {
      rasp::log("reporting: the post failed: no connection to " + endpoint.host + ":" + endpoint.port);
    }
    return std::nullopt;
  }
  const dispatch_time_t answered_by =
      dispatch_time(DISPATCH_TIME_NOW, std::chrono::duration_cast<std::chrono::nanoseconds>(kResponseTimeout).count());
  auto* const content = dispatch_data_create(request.data(), request.size(), nullptr, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
  if (content == nullptr) {
    return std::nullopt;
  }
  nw_connection_send(connection, content, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true, ^(nw_error_t error) {
    if (error != nullptr) {
      exchange->failed.store(true);
    } else {
      exchange->sent.store(true);
    }
    dispatch_semaphore_signal(exchange->signal.get());
  });
  dispatch_release(content);
  if (!wait_for(*exchange, [&exchange] { return exchange->sent.load(); }, answered_by)) {
    if constexpr (kLoggingEnabled) {
      rasp::log("reporting: the post failed: the request was not sent");
    }
    return std::nullopt;
  }
  Answer answer;
  while (!answer.status_line.has_value()) {
    receive(connection, exchange);
    if (!wait_for(*exchange, [&exchange] { return !exchange->receiving.load(); }, answered_by)) {
      if constexpr (kLoggingEnabled) {
        rasp::log("reporting: the post failed: the endpoint did not answer in time");
      }
      return std::nullopt;
    }
    answer = read_answer(*exchange);
    if (!answer.status_line.has_value() && (exchange->failed.load() || answer.full)) {
      if constexpr (kLoggingEnabled) {
        rasp::log("reporting: the post failed: the endpoint gave no status line");
      }
      return std::nullopt;
    }
  }
  return parse_status(*answer.status_line);
}

}  // namespace

bool post(const Config& config, std::string_view body) noexcept {
  const std::optional<Endpoint> endpoint = parse_endpoint(config.endpoint);
  if (!endpoint.has_value()) {
    if constexpr (kLoggingEnabled) {
      rasp::log("reporting: the post failed: the endpoint is not an http:// or https:// URL");
    }
    return false;
  }
  const auto exchange = std::make_shared<Exchange>();
  const Queue queue(dispatch_queue_create(nullptr, DISPATCH_QUEUE_SERIAL));
  if (exchange->signal == nullptr || queue == nullptr) {
    return false;
  }
  auto* const connection = create_connection(*endpoint);
  if (connection == nullptr) {
    if constexpr (kLoggingEnabled) {
      rasp::log("reporting: the post failed: Network.framework gave no connection");
    }
    return false;
  }
  nw_connection_set_queue(connection, queue.get());
  nw_connection_set_state_changed_handler(connection, ^(nw_connection_state_t state, nw_error_t) {
    // Waiting is not an end: it means no path to the host for now, such as no network, and the connection retries when
    // the path changes. The connect timeout bounds how long the post waits for it.
    if (state == nw_connection_state_ready) {
      exchange->ready.store(true);
    } else if (state == nw_connection_state_failed || state == nw_connection_state_cancelled) {
      exchange->failed.store(true);
    }
    dispatch_semaphore_signal(exchange->signal.get());
  });
  nw_connection_start(connection);
  const std::optional<int> status = exchange_request(connection, exchange, make_request(*endpoint, body), *endpoint);
  nw_connection_cancel(connection);
  nw_release(connection);
  if (!status.has_value()) {
    return false;
  }
  if (*status < 200 || *status >= 300) {
    if constexpr (kLoggingEnabled) {
      rasp::log("reporting: the post failed: the endpoint answered " + std::to_string(*status));
    }
    return false;
  }
  return true;
}

}  // namespace rasp::plugins::reporting
