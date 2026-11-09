#pragma once

#include <array>
#include <cstdint>
#include <span>

/** Message digests used by the DEX and APK formats.  Self-contained: the
 *  library has no crypto dependency.  These identify data (the DEX header
 *  signature, certificate fingerprints); they are not used to verify
 *  signatures. */
namespace dexsplit::raw {

std::array<uint8_t, 20> sha1(std::span<const uint8_t> data);
std::array<uint8_t, 32> sha256(std::span<const uint8_t> data);

} // namespace dexsplit::raw
