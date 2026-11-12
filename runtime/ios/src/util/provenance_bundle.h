/// Public Foundation main-bundle root for inactive lexical provenance only.
#pragma once
#include "rasp/posix/provenance.h"
namespace rasp::ios::util {
/// Reads a bounded public main-bundle path; failure leaves location scope unavailable.
[[nodiscard]] provenance::Locations provenance_bundle();
}  // namespace rasp::ios::util
