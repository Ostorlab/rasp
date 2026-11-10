/// kPlugin, the DNS reporting plugin, the fallback of the reporting plugin: init receives the build id and the install
/// id from the runtime, and on_observations takes the run the reporting plugin did not deliver, if any, encodes it as
/// DNS query names and leaves them in the sender's mailbox. A run the reporting plugin delivers is never sent over DNS.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <optional>
#include <pthread.h>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "dns_frame.h"
#include "dns_report.h"
#include "random.h"
#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/observation.h"
#include "rasp/plugin.h"
#include "rasp/util/logging.h"
#include "reporting/undelivered_run.h"
#include "sender.h"
#include "transport.h"

namespace rasp::plugins::dns_reporting {

namespace {

/// The DNS zone the collector listens on.
constexpr const char* kZone = RASP_DNS_REPORTING_ZONE;

/// Context key for the build ref.
constexpr Key<std::array<std::uint8_t, kBuildRefBytes>> kBuildRefKey{"dns_reporting.build_ref"};

/// Context key for the install id: the one the runtime gives, or a random one for this launch when it gives none.
constexpr Key<std::array<std::uint8_t, kInstallIdBytes>> kInstallIdKey{"dns_reporting.install_id"};

/// Context key for the sender pointer.
constexpr Key<Sender*> kSenderKey{"dns_reporting.sender"};

/// Returns the value of a hex digit, or -1 for non-hex characters.
[[nodiscard]] constexpr int nibble(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

/// Parses the first 32 hex characters of a build id into 16 bytes. Returns a zeroed ref and logs on invalid input.
[[nodiscard]] std::array<std::uint8_t, kBuildRefBytes> parse_build_ref(const std::string& build_id) {
  std::array<std::uint8_t, kBuildRefBytes> ref{};
  if (build_id.size() < static_cast<std::size_t>(kBuildRefBytes) * 2) {
    if constexpr (kLoggingEnabled) {
      rasp::log("dns_reporting: build_id shorter than 32 chars, build ref zeroed");
    }
    return ref;
  }
  for (std::size_t i = 0; i < kBuildRefBytes; ++i) {
    const int hi = nibble(build_id[i * 2]);        // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    const int lo = nibble(build_id[(i * 2) + 1]);  // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    if (hi < 0 || lo < 0) {
      if constexpr (kLoggingEnabled) {
        rasp::log("dns_reporting: build_id contains non-hex character, build ref zeroed");
      }
      return {};
    }
    ref[i] = static_cast<std::uint8_t>(  // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        static_cast<unsigned>(hi) << 4U | static_cast<unsigned>(lo));
  }
  return ref;
}

/// The length of a UUID's text: 32 hex digits and 4 hyphens.
constexpr std::size_t kUuidLength = 36;

/// Where a UUID's text has its hyphens.
constexpr std::array<std::size_t, 4> kUuidHyphens{8, 13, 18, 23};

/// Parses an install id, a UUID such as `0f8e5b8e-6c1a-4b7e-9d3a-2a4c5e6f7a8b`, into its 16 bytes.
///
/// @param install_id The UUID's text: 36 characters, hex digits with hyphens at kUuidHyphens.
/// @return The 16 bytes, or nothing when the text is not such a UUID.
[[nodiscard]] std::optional<std::array<std::uint8_t, kInstallIdBytes>> parse_install_id(std::string_view install_id) {
  if (install_id.size() != kUuidLength) {
    return std::nullopt;
  }
  std::array<std::uint8_t, kInstallIdBytes> bytes{};
  const std::span<std::uint8_t, kInstallIdBytes> output{bytes};
  std::size_t byte_count = 0;
  std::optional<unsigned> high_nibble;
  for (std::size_t index = 0; index < install_id.size(); ++index) {
    const bool hyphen = std::ranges::find(kUuidHyphens, index) != kUuidHyphens.end();
    if (hyphen) {
      if (install_id[index] != '-') {
        return std::nullopt;
      }
      continue;
    }
    const int value = nibble(install_id[index]);
    if (value < 0) {
      return std::nullopt;
    }
    if (!high_nibble.has_value()) {
      high_nibble = static_cast<unsigned>(value);
      continue;
    }
    output[byte_count] = static_cast<std::uint8_t>((*high_nibble << 4U) | static_cast<unsigned>(value));
    ++byte_count;
    high_nibble.reset();
  }
  return bytes;
}

/// The install id the reports carry: the one the runtime gives, or a random one for this launch when it gives none or
/// gives one that is not a UUID.
///
/// @param install_id The install id the runtime gives.
/// @return The install id's 16 bytes.
[[nodiscard]] std::array<std::uint8_t, kInstallIdBytes> report_install_id(
    const std::optional<std::string>& install_id) {
  if (install_id.has_value()) {
    const std::optional<std::array<std::uint8_t, kInstallIdBytes>> parsed = parse_install_id(*install_id);
    if (parsed.has_value()) {
      return *parsed;
    }
  }
  std::array<std::uint8_t, kInstallIdBytes> launch_id{};
  if (!fill_random(launch_id.data(), launch_id.size())) {
    if constexpr (kLoggingEnabled) {
      rasp::log("dns_reporting: entropy source failed, install id is zeroed");
    }
  }
  return launch_id;
}

/// Builds the sender and starts its thread.
[[nodiscard]] Sender* start() {
  // NOLINTNEXTLINE(cppcoreguidelines-owning-memory): the sender's thread uses it until the process exits.
  auto* const sender = new (std::nothrow) Sender{
      .resolve = resolve,
      .mailbox = {},
  };
  if (sender == nullptr) {
    return nullptr;
  }
  if (!start_sender(*sender)) {
    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory): the thread did not start, so nothing else uses the sender.
    delete sender;
    return nullptr;
  }
  return sender;
}

/// Guards the load→start→store sequence so two concurrent report() calls cannot each start a sender.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
pthread_mutex_t sender_mutex = PTHREAD_MUTEX_INITIALIZER;  // NOLINT(misc-include-cleaner)

/// Returns the sender, starting it on the first successful call. Retries on each call so a transient failure
/// self-heals.
[[nodiscard]] Sender* sender(Context& context) {
  auto existing = context.get(kSenderKey);
  if (existing.has_value()) {
    return *existing;
  }
  pthread_mutex_lock(&sender_mutex);
  existing = context.get(kSenderKey);
  if (existing.has_value()) {
    pthread_mutex_unlock(&sender_mutex);
    return *existing;
  }
  Sender* s = start();
  if (s != nullptr) {
    context.put(kSenderKey, s);
  }
  pthread_mutex_unlock(&sender_mutex);
  return s;
}

/// Receives the runtime's config. The runtime calls it once before any observations.
void init(const rasp::Config& config, Context& context) {
  context.put(kBuildRefKey, parse_build_ref(config.build_id));
  context.put(kInstallIdKey, report_install_id(config.install_id));
}

/// The plugin's on_observations: takes the run the reporting plugin did not deliver from the context, encodes it as DNS
/// query names and leaves them in the sender's mailbox. When there is no such run, it sends nothing. The observations
/// of this pass are not sent: the reporting plugin posts them, and leaves them for this plugin's next pass if it can't.
/// The run is taken only once the sender has started, so a sender that fails to start leaves it for the next pass.
void report([[maybe_unused]] std::span<const rasp::Observation> unused_observations, Context& context) {
  if (!context.get(reporting::kUndeliveredRun).has_value()) {
    return;
  }
  Sender* const destination = sender(context);
  if (destination == nullptr) {
    if constexpr (kLoggingEnabled) {
      rasp::log("dns_reporting: the sender did not start, the undelivered run is left for the next pass");
    }
    return;
  }
  std::optional<std::vector<rasp::Observation>> undelivered = context.take(reporting::kUndeliveredRun);
  if (!undelivered.has_value()) {
    return;
  }
  const ReportContext report_ctx{
      .build_ref = context.get(kBuildRefKey).value_or(std::array<std::uint8_t, kBuildRefBytes>{}),
      .install_id = context.get(kInstallIdKey).value_or(std::array<std::uint8_t, kInstallIdBytes>{}),
      .zone = kZone,
  };
  std::vector<std::string> names = build_report(*undelivered, report_ctx);
  if (names.empty()) {
    if constexpr (kLoggingEnabled) {
      rasp::log("dns_reporting: encoding produced no DNS names, the undelivered run is dropped");
    }
    return;
  }
  destination->mailbox.put(std::move(names));
}

}  // namespace

/// The DNS reporting plugin.
extern constexpr Plugin kPlugin{.init = init, .checks = {}, .on_observations = report};

}  // namespace rasp::plugins::dns_reporting
