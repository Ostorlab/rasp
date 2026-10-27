/// DNS report builder: encodes observations as DNS query names for the collector.

#include "rasp/reporting/dns_report.h"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <string>
#include <vector>

#include "rasp/observation.h"
#include "rasp/reporting/cbor.h"
#include "rasp/reporting/dns_frame.h"

namespace rasp::reporting {

std::vector<std::string> build_report(const std::vector<Observation>& observations, const ReportContext& context) {
  std::array<std::uint8_t, kMsgIdBytes> msg_id{};
  arc4random_buf(msg_id.data(), msg_id.size());

  const auto now = static_cast<std::int64_t>(std::time(nullptr));
  const std::uint16_t hour = hour_of(now);

  const std::vector<std::uint8_t> cbor = encode_observations(observations);
  const std::vector<std::uint8_t> payload = write_payload(context.build_ref, hour, context.install_id, cbor, msg_id);
  if (payload.empty()) {
    return {};
  }

  return write_names(payload, msg_id, context.zone);
}

}  // namespace rasp::reporting
