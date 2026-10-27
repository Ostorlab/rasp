/// CBOR encoder for the subset of RFC 8949 that a DNS report uses.

#pragma once

#include <cstdint>
#include <vector>

#include "rasp/observation.h"

namespace rasp::reporting {

/// Encodes observations as a CBOR array of arrays, matching the server's expected format.
///
/// Each observation becomes [signal: text, source: text, status: uint, value], where value
/// is null, a bool, an integer, a text string, or an array of text strings.
///
/// @param observations The observations to encode.
/// @return The CBOR bytes of the array.
[[nodiscard]] std::vector<std::uint8_t> encode_observations(const std::vector<Observation>& observations);

}  // namespace rasp::reporting
