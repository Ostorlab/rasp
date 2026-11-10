/// handshake on iOS: a Network.framework TLS connection whose verify block copies the chain the host presented and
/// the system's trust in it, then refuses the chain, so the handshake stops before any request.

#include "handshake.h"

#include <CoreFoundation/CFBase.h>
#include <CoreFoundation/CFData.h>
#include <MacTypes.h>
#include <Network/Network.h>
#include <Security/SecBase.h>
#include <Security/SecCertificate.h>
#include <Security/SecProtocolMetadata.h>
#include <Security/SecProtocolObject.h>
#include <Security/SecProtocolOptions.h>
#include <Security/SecProtocolTypes.h>
#include <Security/SecTrust.h>
#include <TargetConditionals.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <dispatch/dispatch.h>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace rasp::plugins::adr_pin {

namespace {

#if TARGET_OS_IOS && !TARGET_OS_SIMULATOR
/// Whether this build runs on a physical iOS device, the only place the probe means anything.
constexpr bool kPhysicalDevice = true;
#else
/// Whether this build runs on a physical iOS device, the only place the probe means anything.
constexpr bool kPhysicalDevice = false;
#endif

/// The port of the connection.
constexpr const char* kPort = "443";

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
  /// Signalled whenever `read` or `failed` is set.
  Semaphore signal{dispatch_semaphore_create(0)};
  /// Guards `chain` and `trusted`.
  std::mutex mutex;
  /// The chain the host presented, leaf first.
  std::vector<std::vector<std::uint8_t>> chain;
  /// Whether the system trusted the chain.
  bool trusted = false;
  /// Set once `chain` and `trusted` hold the host's chain.
  std::atomic<bool> read{false};
  /// Set once the connection failed or can't go further.
  std::atomic<bool> failed{false};
};

/// The DER of a certificate, or nothing (an empty vector) when it can't be copied or is larger than
/// kMaxCertificateBytes.
///
/// @param certificate The certificate.
/// @return The DER.
[[nodiscard]] std::vector<std::uint8_t> copy_der(SecCertificateRef certificate) {
  const auto* const data = SecCertificateCopyData(certificate);
  if (data == nullptr) {
    return {};
  }
  std::vector<std::uint8_t> der;
  const CFIndex length = CFDataGetLength(data);
  if (length > 0 && std::cmp_less_equal(length, kMaxCertificateBytes)) {
    const std::span bytes(CFDataGetBytePtr(data), static_cast<std::size_t>(length));
    der.assign(bytes.begin(), bytes.end());
  }
  CFRelease(data);
  return der;
}

/// Copies the chain the host presented, before the system builds its own, and evaluates the system's trust in it.
///
/// @param trust The handshake's trust object.
/// @param exchange Where to leave the chain and the trust.
void read_trust(sec_trust_t trust, Exchange& exchange) {
  auto* const reference = sec_trust_copy_ref(trust);
  if (reference == nullptr) {
    exchange.failed.store(true);
    return;
  }
  // The evaluation must not wait on revocation servers: the trust is a fact to report, not a decision to take here.
  static_cast<void>(SecTrustSetNetworkFetchAllowed(reference, static_cast<Boolean>(false)));
  const auto count = static_cast<std::size_t>(std::max<CFIndex>(SecTrustGetCertificateCount(reference), 0));
  std::vector<std::vector<std::uint8_t>> chain;
  chain.reserve(std::min(count, kMaxCertificates));
  for (std::size_t index = 0; index < std::min(count, kMaxCertificates); ++index) {
    auto* const certificate = SecTrustGetCertificateAtIndex(reference, static_cast<CFIndex>(index));
    chain.push_back(certificate == nullptr ? std::vector<std::uint8_t>{} : copy_der(certificate));
  }
  const bool trusted = SecTrustEvaluateWithError(reference, nullptr);
  CFRelease(reference);
  {
    const std::scoped_lock lock(exchange.mutex);
    exchange.chain = std::move(chain);
    exchange.trusted = trusted;
  }
  exchange.read.store(true);
}

/// Creates the connection, whose TLS verify block reads the chain and then refuses it.
///
/// @param host The host name.
/// @param queue The queue of the connection's blocks.
/// @param exchange What the blocks share with the waiting thread.
/// @return The connection, or null when it can't be created.
[[nodiscard]] nw_connection_t create_connection(const std::string& host, dispatch_queue_t queue,
                                                const std::shared_ptr<Exchange>& exchange) {
  auto* const endpoint = nw_endpoint_create_host(host.c_str(), kPort);
  if (endpoint == nullptr) {
    return nullptr;
  }
  const sec_protocol_verify_t verify =
      ^(sec_protocol_metadata_t, sec_trust_t trust, sec_protocol_verify_complete_t complete) {
        read_trust(trust, *exchange);
        dispatch_semaphore_signal(exchange->signal.get());
        complete(false);
      };
  auto* const parameters = nw_parameters_create_secure_tcp(
      ^(nw_protocol_options_t tls_options) {
        auto* const options = nw_tls_copy_sec_protocol_options(tls_options);
        sec_protocol_options_set_verify_block(options, verify, queue);
        sec_release(options);
      },
      NW_PARAMETERS_DEFAULT_CONFIGURATION);
  if (parameters == nullptr) {
    nw_release(endpoint);
    return nullptr;
  }
  auto* const connection = nw_connection_create(endpoint, parameters);
  nw_release(parameters);
  nw_release(endpoint);
  return connection;
}

}  // namespace

Handshake handshake(const std::string& host, std::chrono::milliseconds timeout) {
  if constexpr (!kPhysicalDevice) {
    return Handshake{.outcome = Outcome::kUnsupported, .chain = {}, .trusted = false};
  }
  const auto exchange = std::make_shared<Exchange>();
  const Queue queue(dispatch_queue_create(nullptr, DISPATCH_QUEUE_SERIAL));
  if (exchange->signal == nullptr || queue == nullptr) {
    return Handshake{.outcome = Outcome::kFailed, .chain = {}, .trusted = false};
  }
  auto* const connection = create_connection(host, queue.get(), exchange);
  if (connection == nullptr) {
    return Handshake{.outcome = Outcome::kFailed, .chain = {}, .trusted = false};
  }
  nw_connection_set_queue(connection, queue.get());
  nw_connection_set_state_changed_handler(connection, ^(nw_connection_state_t state, nw_error_t) {
    // Waiting is not an end: it means no path to the host for now, such as no network, and the connection retries when
    // the path changes. The wait below keeps waiting for it until the timeout.
    if (state == nw_connection_state_failed || state == nw_connection_state_cancelled) {
      exchange->failed.store(true);
      dispatch_semaphore_signal(exchange->signal.get());
    }
  });
  nw_connection_start(connection);
  const dispatch_time_t deadline =
      dispatch_time(DISPATCH_TIME_NOW, std::chrono::duration_cast<std::chrono::nanoseconds>(timeout).count());
  // Why the wait ended is decided here, before the cancel below: the cancel makes the state handler set `failed`, so
  // reading `failed` after it could turn a timeout into a failure.
  bool timed_out = false;
  while (!exchange->read.load() && !exchange->failed.load()) {
    if (dispatch_semaphore_wait(exchange->signal.get(), deadline) != 0) {
      timed_out = true;
      break;
    }
  }
  nw_connection_cancel(connection);
  nw_release(connection);
  if (exchange->read.load()) {
    const std::scoped_lock lock(exchange->mutex);
    return Handshake{.outcome = Outcome::kRead, .chain = std::move(exchange->chain), .trusted = exchange->trusted};
  }
  const Outcome outcome = timed_out ? Outcome::kTimeout : Outcome::kFailed;
  return Handshake{.outcome = outcome, .chain = {}, .trusted = false};
}

}  // namespace rasp::plugins::adr_pin
