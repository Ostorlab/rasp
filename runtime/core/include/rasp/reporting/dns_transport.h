/// DNS transport: encodes observations and sends them as DNS queries.

#pragma once

#include <string>
#include <vector>

#include "rasp/observation.h"
#include "rasp/reporting/dns_report.h"

namespace rasp::reporting {

/// Signature of a function that resolves one DNS query name.
using Resolver = bool (*)(const std::string&);

/// Encodes observations as DNS query names and resolves each one.
///
/// Builds the report (CBOR, payload, chunking) and resolves each chunk as a DNS
/// A-record query using the given resolver. Stops on the first resolution failure.
///
/// @param observations The security observations to send.
/// @param context The build, install and zone information.
/// @param resolver The function that sends one DNS query. Defaults to resolve_name.
void send_observations(const std::vector<Observation>& observations, const ReportContext& context,
                       Resolver resolver = nullptr);

}  // namespace rasp::reporting
