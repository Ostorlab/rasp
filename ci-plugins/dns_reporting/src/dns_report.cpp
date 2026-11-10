/// DNS report builder: encodes observations as DNS query names for the collector.

#include "dns_report.h"

#include <array>
#include <cstdint>
#include <ctime>
#include <string>
#include <vector>

#include "cbor.h"
#include "dns_frame.h"
#include "random.h"
#include "rasp/observation.h"

namespace rasp::plugins::dns_reporting {

std::vector<std::string> build_report(const std::vector<rasp::Observation>& observations,
                                      const ReportContext& context) {
  std::array<std::uint8_t, kMsgIdBytes> msg_id{};
  if (!fill_random(msg_id.data(), msg_id.size())) {
    return {};
  }

  const auto now = static_cast<std::int64_t>(std::time(nullptr));
  const std::uint16_t hour = hour_of(now);

  const std::vector<std::uint8_t> cbor = encode_observations(observations);
  const std::vector<std::uint8_t> payload = write_payload(context.build_ref, hour, context.install_id, cbor, msg_id);
  if (payload.empty()) {
    return {};
  }

  return write_names(payload, msg_id, context.zone);
}

}  // namespace rasp::plugins::dns_reporting
