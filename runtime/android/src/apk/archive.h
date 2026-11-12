/// Reading an APK straight from its bytes, without inflating anything: an uncompressed entry, and the certificate of
/// the key that signed it.

#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "util/signing_certificates.h"

namespace rasp::android::apk {

/// Reads one stored (uncompressed) entry from an APK by name.
///
/// The packer writes the runtime's assets stored, not compressed, so the runtime reads them without an inflate step
/// and without a zip library. The APK is read through bounded descriptor regions. Only a unique stored entry with
/// consistent local/central metadata is accepted; ZIP64, encryption and ambiguous names are refused.
///
/// @param apk_path The APK file to read.
/// @param name The entry's full name in the APK, such as `assets/rasp/payload.bin`.
/// @param max_bytes Explicit caller allocation limit, at most 64 MiB + 28 bytes.
/// @return The entry's bytes, or nothing on malformed/over-limit input, I/O or detected mutation. Regular ZIP32
/// files up to 2 GiB minus one byte, a 16 MiB directory and 65,534 entries are supported. Symlinks to regular files
/// are followed. Metadata equality does not prove authenticity or an immutable snapshot.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> read_stored_entry(const std::string& apk_path,
                                                                         std::string_view name, std::size_t max_bytes);

/// Finds the certificate of the key that Android uses as the signer of the APK whose bytes are `apk`, on a device at
/// `api_level`.
///
/// An APK signed with the v2 or v3 scheme carries an APK Signing Block right before its central directory. Its entries
/// are read as Android verifies them, newest first: the v3.1 entry, which holds the signers of a rotated key and is
/// read only on Android 13 and up, where the platform honors it, then the v3 entry, then the v2 entry. A v3 or v3.1
/// signer applies to a range of API levels, and the first one whose range holds `api_level` is used; v2's first signer
/// applies to every level. This returns that signer's first certificate, the X.509 certificate in DER whose digest
/// `apksigner verify --print-certs` prints. It does not verify signatures or current file integrity: installation-time
/// platform verification does not establish trust in bytes read now from an attacker-controlled device.
///
/// @param apk The bytes of the APK.
/// @param api_level The API level of the device.
/// @return The certificate's DER bytes. Nothing when the APK has no end-of-central-directory record or no APK Signing
/// Block, as an APK signed only with the JAR scheme, no entry has a signer for `api_level`, a length runs past what
/// holds it, or the certificate is empty or larger than 64 KiB.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> find_signing_certificate(std::span<const std::uint8_t> apk,
                                                                                std::uint32_t api_level);

/// Reads the certificate of the key that Android uses as the signer of the APK at `apk_path`, as
/// find_signing_certificate finds it.
///
/// @param apk_path The APK file to read.
/// @param api_level The API level of the device.
/// @return The certificate's DER bytes. Nothing on I/O, malformed/over-limit input or detected changes. Reads a bounded
/// ZIP tail and at most 1 MiB of signing block, retaining legacy selection and first-certificate semantics.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> read_signing_certificate(const std::string& apk_path,
                                                                                std::uint32_t api_level);

/// Why a complete signer set could not be collected; absence is never an empty successful set.
enum class SignerReadError : std::uint8_t {
  /// Missing, malformed, inconsistent or over-limit input.
  kError,
  /// Scheme selection requires unsupported developer-release metadata or a device below API31.
  kUnsupported,
};

/// Complete current signer leaves for the selected platform scheme, without cryptographic verification.
using SignerCertificates = std::expected<util::Certificates, SignerReadError>;

/// Parses one complete current set, keeping certificate-chain entries distinct from concurrent signers.
/// @param apk Untrusted bounded APK bytes; ZIP64, multi-disk and blocks over 1MiB are refused.
/// @param api_level Device API, minimum 31. v3.1 is considered only from API33.
/// @return v2 leaves (at most ten), or exactly one applicable v3/v3.1 leaf. Never combines schemes or emits history.
[[nodiscard]] SignerCertificates find_signing_certificates(std::span<const std::uint8_t> apk, std::uint32_t api_level);

/// Reads only the bounded ZIP tail and signing block, avoiding a mapping of the untrusted archive.
/// @param apk_path APK path, up to 2GiB minus one byte; regular files only.
/// @param api_level Device API, minimum 31.
/// @return Complete observed current certificates, or explicit error/unsupported; no signature or lineage proof.
[[nodiscard]] SignerCertificates read_signing_certificates(const std::string& apk_path, std::uint32_t api_level);

}  // namespace rasp::android::apk
