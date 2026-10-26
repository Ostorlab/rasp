/// The iOS app-identity self-check: whether the app still has the identity it shipped with, which a repackaged or
/// re-signed build changes. It reports the app's bundle identifier, read through two independent sources, and the Team
/// ID and the cdhash of the code signature of the app's main executable; the server checks that they agree with each
/// other and with the values the customer registered, and decides.

#pragma once

#include <string_view>
#include <vector>

#include "rasp/observation.h"

namespace rasp::ios::checks {

/// Runs the app-identity check and returns what it observed.
///
/// On a physical iOS device it reports the bundle identifier of the app's main bundle twice: once as CFBundle reports
/// it, as observe_bundle_identifier does, and once as the main bundle's Info.plist file on disk holds it, as
/// observe_main_info_plist does. It then reports the Team ID and the cdhash of the code signature of the app's main
/// executable, as observe_main_executable_signature does. Anywhere else, on a simulator, a Mac or a Linux host, every
/// observation is unsupported instead, so the result still shows that the check ran.
///
/// @return Four observations, in this order: id.bundle_id through CFBundle, id.bundle_id through Info.plist, then
/// id.team_id and id.cdhash through code_signature.
[[nodiscard]] std::vector<Observation> identity();

/// Reports the bundle identifier of the app's main bundle, as CFBundle reports it.
///
/// The probe asks CoreFoundation for the main bundle with CFBundleGetMainBundle and for its identifier with
/// CFBundleGetIdentifier, the value an app reads when it asks who it is. A repackaged app published under another
/// identifier reports that identifier. A hook on CFBundleGetIdentifier can make it report the original one instead,
/// so the same value is also read from the Info.plist file, as observe_main_info_plist does, and a hook shows as two
/// values that disagree. CoreFoundation exists only on Apple systems, so anywhere else the observation is unsupported.
///
/// @return One id.bundle_id observation through CFBundle: the identifier as a string. It has an error status when
/// there is no main bundle or no identifier, when the identifier is not a string, is empty, is longer than 1024 bytes
/// of UTF-8 or holds a character UTF-8 can't encode, and the unsupported status on a system without CoreFoundation.
[[nodiscard]] Observation observe_bundle_identifier();

/// Reports the bundle identifier that the property list file at `plist_path` holds, the value of its
/// `CFBundleIdentifier` key.
///
/// The probe reads the file itself, without CFBundle, so a hook on CFBundle's functions doesn't change what it reads.
/// The file must be a regular file of at most 1 MiB; it is opened with close-on-exec and without blocking, so a file
/// that isn't a regular one, such as a FIFO, can't stall the probe. Its content is parsed with
/// CFPropertyListCreateWithData, which reads both the binary and the XML property list formats. CoreFoundation exists
/// only on Apple systems, so anywhere else the observation is unsupported.
///
/// @param plist_path The property list file to read, the main bundle's Info.plist on a device.
/// @return One id.bundle_id observation through Info.plist: the identifier as a string. It has an error status when
/// the file can't be opened, read or closed, isn't a regular file, is larger than 1 MiB or isn't a property list, when
/// the property list isn't a dictionary or has no `CFBundleIdentifier` key, and when the identifier is not a string,
/// is empty, is longer than 1024 bytes of UTF-8 or holds a character UTF-8 can't encode. It has the unsupported
/// status on a system without CoreFoundation.
[[nodiscard]] Observation observe_info_plist(std::string_view plist_path);

/// Reports the bundle identifier that the main bundle's Info.plist file on disk holds.
///
/// The probe asks CoreFoundation for the main bundle's directory with CFBundleCopyBundleURL, turns it into a file
/// system path that fits in PATH_MAX, 1024 bytes, with its terminating NUL, and reads the `Info.plist` file at the top
/// of that directory, where an iOS app bundle keeps it, as observe_info_plist does. CoreFoundation exists only on Apple
/// systems, so anywhere else the observation is unsupported.
///
/// @return One id.bundle_id observation through Info.plist, as observe_info_plist reports it. It also has an error
/// status when there is no main bundle, or when its directory has no file system path that fits in PATH_MAX bytes.
[[nodiscard]] Observation observe_main_info_plist();

/// Reports the Team ID and the cdhash of the code signature of the Mach-O executable file at `executable_path`.
///
/// The probe reads the file itself, so a hook on the functions that report a signature doesn't change what it reads.
/// The file must be a regular file; it is opened with close-on-exec and without blocking, so a file that isn't a
/// regular one, such as a FIFO, can't stall the probe. It must be a thin 64-bit little-endian Mach-O file, as an arm64
/// executable is. The probe reads its header and its load commands, at most 1 MiB of them, then the bytes that its
/// LC_CODE_SIGNATURE load command points to, at most 16 MiB, which hold the embedded signature, a big-endian
/// `CS_SuperBlob`. Every offset and length in them is checked against what holds it before it is used.
///
/// The signature can hold several CodeDirectories: one in the CodeDirectory slot, such as a SHA-1 one kept for older
/// systems, and others in the alternate slots, `CSSLOT_ALTERNATE_CODEDIRECTORIES` and the four slots after it. The
/// probe uses the one the kernel uses when it loads the signature, the one with the strongest hash type: SHA-384, then
/// SHA-256, then SHA-256 truncated to 20 bytes, then SHA-1. Like the kernel, it takes a signature with two
/// CodeDirectories of the same hash type, or with one of a hash type it doesn't know, as malformed.
///
/// The Team ID is the text at that CodeDirectory's `teamOffset`, a field that exists from CodeDirectory version
/// 0x20200. It is an empty string when the version predates the field or when the offset is 0, as in an ad-hoc
/// signature. The cdhash is the SHA-256 of that CodeDirectory's bytes, computed with TF-PSA-Crypto and cut to its first
/// 20 bytes, in lowercase hex: the `CDHash=` value that `codesign -dvvv` prints. Only a SHA-256 CodeDirectory has
/// that cdhash, so it is the only kind the probe hashes.
///
/// On a device these are the values of whoever signed the app last. The customer signs the protected app after the
/// packer packs it, so a genuine copy reports the customer's Team ID and cdhash, which the server compares with the
/// values the customer registered. A copy that anyone else re-signed reports their Team ID and another cdhash, because
/// the Team ID is part of the CodeDirectory the cdhash covers.
///
/// @param executable_path The Mach-O file to read, the app's main executable on a device.
/// @return Two observations through code_signature, in this order: id.team_id, the Team ID as a string, then
/// id.cdhash, the cdhash as 40 lowercase hex digits. Both have an error status when the file can't be opened, read or
/// closed, isn't a regular file, isn't a thin 64-bit little-endian Mach-O file, which a universal file isn't, or has
/// load commands larger than 1 MiB; when it has no LC_CODE_SIGNATURE load command or more than one, or a signature
/// larger than 16 MiB or past the end of the file; and when the signature is malformed: a wrong magic number, an
/// offset, a length or a count that reaches past the end of what holds it, no CodeDirectory, two of the same hash type
/// or one of an unknown hash type, or a Team ID with no terminating NUL or longer than 64 bytes. id.cdhash alone has
/// an error status when the CodeDirectory the probe uses isn't a SHA-256 one, or when TF-PSA-Crypto can't hash it.
[[nodiscard]] std::vector<Observation> observe_executable_signature(std::string_view executable_path);

/// Reports the Team ID and the cdhash of the code signature of the app's main executable.
///
/// The probe asks dyld for the path of the main executable with _NSGetExecutablePath, into a buffer of PATH_MAX, 1024
/// bytes, and reads that file as observe_executable_signature does. dyld exists only on Apple systems, so anywhere
/// else both observations are unsupported.
///
/// @return Two observations through code_signature, id.team_id then id.cdhash, as observe_executable_signature reports
/// them. Both also have an error status when the path doesn't fit in PATH_MAX bytes, and the unsupported status on a
/// system without dyld.
[[nodiscard]] std::vector<Observation> observe_main_executable_signature();

}  // namespace rasp::ios::checks
