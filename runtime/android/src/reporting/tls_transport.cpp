/// TlsTransport: one TLS connection per request, with Mbed TLS over a socket of our own.

#include "reporting/tls_transport.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <memory>
#include <optional>
#include <psa/crypto.h>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "rasp/util/http.h"
#include "rasp/util/logging.h"
#include "reporting/socket.h"
#include "reporting/trust_anchors.h"

namespace rasp::android {

namespace {

/// The server's TCP port.
constexpr std::uint16_t kPort = 443;

/// The most bytes of the server's answer that a post reads before it closes the connection.
constexpr std::size_t kMaxAnswerBytes = 4096;

/// How far a post got.
enum class Stage : std::uint8_t {
  /// The request wasn't written.
  kNotSent,
  /// The request was written, but no answer started.
  kSent,
  /// The start of the answer arrived.
  kAnswered,
};

/// PSA crypto, which TLS 1.3 needs, started for one post and freed with its owner.
class Crypto {
 public:
  /// Starts PSA crypto, which seeds its random generator from the system.
  Crypto() noexcept : ready_(psa_crypto_init() == PSA_SUCCESS) {}
  /// Deleted: a copy would free PSA crypto a second time.
  Crypto(const Crypto&) = delete;
  /// Deleted: a copy would free PSA crypto a second time.
  Crypto& operator=(const Crypto&) = delete;
  /// Deleted: a moved-from Crypto would still free PSA crypto.
  Crypto(Crypto&&) = delete;
  /// Deleted: a moved-from Crypto would still free PSA crypto.
  Crypto& operator=(Crypto&&) = delete;
  /// Frees what PSA crypto holds, its keys and its random generator.
  ~Crypto() { mbedtls_psa_crypto_free(); }

  /// Whether PSA crypto started.
  [[nodiscard]] bool ready() const noexcept { return ready_; }

 private:
  /// Whether PSA crypto started.
  bool ready_;
};

/// Fills `output` from PSA crypto's random generator, and gives 0, or an Mbed TLS error code when that fails.
[[nodiscard]] int random_bytes(std::span<std::uint8_t> output) {
  return psa_generate_random(output.data(), output.size()) == PSA_SUCCESS ? 0 : MBEDTLS_ERR_ERROR_GENERIC_ERROR;
}

/// The Mbed TLS contexts of one connection: the trust anchors, the TLS settings and the TLS context, freed with their
/// owner.
class Session {
 public:
  /// Initializes every context, so that each one can be freed whatever happens next.
  Session() noexcept {
    mbedtls_x509_crt_init(&anchors_);
    mbedtls_ssl_config_init(&config_);
    mbedtls_ssl_init(&context_);
  }
  /// Deleted: the TLS context points to the settings, which point to the anchors, so a copy would point into the
  /// original.
  Session(const Session&) = delete;
  /// Deleted: the TLS context points to the settings, which point to the anchors, so a copy would point into the
  /// original.
  Session& operator=(const Session&) = delete;
  /// Deleted: the contexts point to each other, so a moved session would point into the moved-from one.
  Session(Session&&) = delete;
  /// Deleted: the contexts point to each other, so a moved session would point into the moved-from one.
  Session& operator=(Session&&) = delete;
  /// Frees every context, the TLS context first because it points to the others.
  ~Session() {
    mbedtls_ssl_free(&context_);
    mbedtls_ssl_config_free(&config_);
    mbedtls_x509_crt_free(&anchors_);
  }

  /// Parses the trust anchors and sets up a TLS client that requires a server certificate that chains up to one of
  /// them and is issued for `host`, and says whether all of it worked.
  [[nodiscard]] bool prepare(const std::string& host) {
    for (const std::span<const std::uint8_t> anchor : kTrustAnchors) {
      if (mbedtls_x509_crt_parse_der_nocopy(&anchors_, anchor.data(), anchor.size()) != 0) {
        return false;
      }
    }
    if (mbedtls_ssl_config_defaults(&config_, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
      return false;
    }
    mbedtls_ssl_conf_authmode(&config_, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&config_, &anchors_, nullptr);
    mbedtls_ssl_conf_rng(
        &config_,
        []([[maybe_unused]] void* state, unsigned char* output, std::size_t size) {
          return random_bytes(std::span(output, size));
        },
        nullptr);
    return mbedtls_ssl_setup(&context_, &config_) == 0 && mbedtls_ssl_set_hostname(&context_, host.c_str()) == 0;
  }

  /// The TLS context, ready for a handshake once prepare succeeded.
  [[nodiscard]] mbedtls_ssl_context& context() noexcept { return context_; }

 private:
  /// The certificates a server certificate must chain up to.
  mbedtls_x509_crt anchors_{};
  /// The TLS client settings.
  mbedtls_ssl_config config_{};
  /// The TLS connection.
  mbedtls_ssl_context context_{};
};

/// What the I/O callbacks of a TLS connection need: its socket and the deadline of the post.
struct Link {
  /// The connected socket.
  const Socket* socket = nullptr;
  /// The moment the post must be over by.
  Deadline deadline;
};

/// Sends the start of `data` on the socket of `link`, and gives how many bytes were sent, or an Mbed TLS error code.
[[nodiscard]] int send_bytes(const Link& link, std::span<const std::uint8_t> data) {
  const std::size_t size = std::min<std::size_t>(data.size(), std::numeric_limits<int>::max());
  const std::optional<std::size_t> sent = link.socket->send_some(data.first(size), link.deadline);
  return sent.has_value() ? static_cast<int>(*sent) : MBEDTLS_ERR_NET_SEND_FAILED;
}

/// Receives into the start of `buffer` from the socket of `link`, and gives how many bytes were received, 0 when the
/// server closed the connection, or an Mbed TLS error code.
[[nodiscard]] int receive_bytes(const Link& link, std::span<std::uint8_t> buffer) {
  const std::size_t size = std::min<std::size_t>(buffer.size(), std::numeric_limits<int>::max());
  const std::optional<std::size_t> received = link.socket->receive_some(buffer.first(size), link.deadline);
  return received.has_value() ? static_cast<int>(*received) : MBEDTLS_ERR_NET_RECV_FAILED;
}

/// Calls `step` again while Mbed TLS asks for it, but not past `deadline`, and gives its last result.
template <typename Step>
[[nodiscard]] int retry(Step step, Deadline deadline) {
  int result = step();
  while ((result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE) &&
         std::chrono::steady_clock::now() < deadline) {
    result = step();
  }
  return result;
}

/// Writes all of `request` on the connection of `context`, and says whether it was all written.
[[nodiscard]] bool write_all(mbedtls_ssl_context& context, std::string_view request) {
  const std::vector<std::uint8_t> bytes(request.begin(), request.end());
  std::size_t written = 0;
  while (written < bytes.size()) {
    const std::span<const std::uint8_t> left = std::span(bytes).subspan(written);
    const int result = mbedtls_ssl_write(&context, left.data(), left.size());
    if (result <= 0) {
      return false;
    }
    written += static_cast<std::size_t>(result);
  }
  return true;
}

/// Reads the start of the server's answer on the connection of `context`, at most kMaxAnswerBytes, discards it, and
/// says whether any of it arrived before `deadline`.
[[nodiscard]] bool read_answer(mbedtls_ssl_context& context, Deadline deadline) {
  std::vector<std::uint8_t> answer(kMaxAnswerBytes);
  return retry([&] { return mbedtls_ssl_read(&context, answer.data(), answer.size()); }, deadline) > 0;
}

/// Connects to `host`, does the TLS handshake, writes `request` and reads the start of the answer, all before
/// `deadline`, then closes the connection, and says how far the post got.
[[nodiscard]] Stage send(const std::string& host, std::string_view request, Deadline deadline) {
  const Crypto crypto;
  if (!crypto.ready()) {
    return Stage::kNotSent;
  }
  const auto session = std::make_unique<Session>();
  if (!session->prepare(host)) {
    return Stage::kNotSent;
  }
  const std::optional<Socket> socket = connect_socket(host, kPort, deadline);
  if (!socket.has_value()) {
    return Stage::kNotSent;
  }
  Link link{.socket = &*socket, .deadline = deadline};
  mbedtls_ssl_context& context = session->context();
  mbedtls_ssl_set_bio(
      &context, &link,
      [](void* state, const unsigned char* data, std::size_t size) {
        return send_bytes(*static_cast<const Link*>(state), std::span(data, size));
      },
      [](void* state, unsigned char* buffer, std::size_t size) {
        return receive_bytes(*static_cast<const Link*>(state), std::span(buffer, size));
      },
      nullptr);
  if (retry([&] { return mbedtls_ssl_handshake(&context); }, deadline) != 0 || !write_all(context, request)) {
    return Stage::kNotSent;
  }
  const Stage stage = read_answer(context, deadline) ? Stage::kAnswered : Stage::kSent;
  static_cast<void>(mbedtls_ssl_close_notify(&context));
  return stage;
}

/// Writes how far a post got to the system log, in a development build.
void log_stage(Stage stage) {
  if constexpr (kLoggingEnabled) {
    if (stage == Stage::kAnswered) {
      rasp::log("transport: answered");
    } else if (stage == Stage::kSent) {
      rasp::log("transport: sent, no answer");
    } else {
      rasp::log("transport: not sent");
    }
  }
}

}  // namespace

TlsTransport::TlsTransport(std::string host, std::string path, std::chrono::milliseconds timeout)
    : host_(std::move(host)), path_(std::move(path)), timeout_(timeout) {}

void TlsTransport::post(std::string_view body) noexcept {
  const std::optional<std::string> request = http::post_request(host_, path_, body);
  if (!request.has_value()) {
    return;
  }
  if (kTrustAnchors.empty()) {
    if constexpr (kLoggingEnabled) {
      rasp::log("transport: the build has no trust anchors, so nothing is sent");
    }
    return;
  }
  log_stage(send(host_, *request, std::chrono::steady_clock::now() + timeout_));
}

}  // namespace rasp::android
