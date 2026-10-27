/// DNS transport: builds a DNS report and resolves each query name.

#include "rasp/reporting/dns_transport.h"

#include <string>
#include <vector>

#include "rasp/observation.h"
#include "rasp/reporting/dns_report.h"
#include "rasp/reporting/dns_resolve.h"

namespace rasp::reporting {

void send_observations(const std::vector<Observation>& observations, const ReportContext& context, Resolver resolver) {
  if (resolver == nullptr) {
    resolver = &resolve_name;
  }
  const std::vector<std::string> names = build_report(observations, context);
  for (const std::string& name : names) {
    if (!resolver(name)) {
      return;
    }
  }
}

}  // namespace rasp::reporting
