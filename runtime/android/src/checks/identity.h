/// The Android app-identity self-check: whether the app still has the identity it shipped with, which a repackaged or
/// cloned build changes. It reports the running package name and the SHA-256 of the app's signing certificate; the
/// server compares them against the values the packer recorded and decides.

#pragma once

#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#ifdef __ANDROID__
#include <jni.h>
#endif

#include "rasp/observation.h"

namespace rasp::android::checks {

/// Runs the app-identity checks and returns what they observed.
///
/// On Android it reports the running package name, read from the process's own command line. Anywhere else the
/// observation is unsupported instead, so the server still sees that the check ran. The signing-certificate hash is not
/// gathered here: it needs the Java PackageManager, which a load-time constructor has no JNIEnv or Context for, so the
/// dispatcher reports id.signer_sha256 as unsupported; observe_signer stays available for the caller that does have the
/// certificate bytes, and for tests.
///
/// @return One observation per signal and source, in this order: id.package through proc_cmdline, then id.signer_sha256
/// through package_manager.
[[nodiscard]] std::vector<Observation> identity();

/// Reports the running package name, read from the command line at `cmdline_path`.
///
/// Android sets a process's command line to its process name, so `/proc/self/cmdline` names the app the runtime is
/// running inside. The package is the first NUL-separated field, up to an optional `:<name>` suffix that marks a
/// process an app declares with `android:process` (such as `com.example:remote`); taking the part before the colon
/// gives the same package for every process of a multi-process app. A clone or a repackaged app published under a
/// different package name reports a package that doesn't match the one the packer recorded.
///
/// @param cmdline_path The command line to read, `/proc/self/cmdline` on a device.
/// @return One id.package observation read through proc_cmdline: the package name. It has an error status when the file
/// can't be read or holds no name.
[[nodiscard]] Observation observe_package(std::string_view cmdline_path);

/// Reports the SHA-256 of the app's signing certificate, over its DER-encoded bytes `certificate`.
///
/// Android requires every APK to be signed, and refuses to install one whose contents changed without a matching
/// signature, so a repackaged app must be re-signed with the attacker's own certificate. Its hash then differs from the
/// one the packer recorded for the genuine certificate. The runtime reports the hash; the server compares it. The
/// certificate bytes come from the Java PackageManager, which the caller passes in.
///
/// @param certificate The DER-encoded bytes of the signing certificate.
/// @return One id.signer_sha256 observation read through package_manager: the lowercase hex SHA-256 of the bytes. It
/// has an error status when the hash can't be computed or the bytes are empty.
[[nodiscard]] Observation observe_signer(std::span<const std::uint8_t> certificate);

#ifdef __ANDROID__

/// Reports the SHA-256 of the app's signing certificate, read through the Java PackageManager with `env`.
///
/// It reaches the app's Context through `ActivityThread.currentApplication()`, asks its PackageManager for the
/// package's PackageInfo with the signing certificates, takes the DER bytes of the first APK-contents signer, and
/// hashes them with observe_signer. A JNIEnv is needed because the certificate is behind a Java API; the dispatcher
/// calls this from a context that has one, such as JNI_OnLoad. On older devices without the v2 signing-info API it
/// falls back to the deprecated signatures field.
///
/// @param env The JNI environment of the calling thread.
/// @return One id.signer_sha256 observation read through package_manager: the hex SHA-256 of the certificate. It has an
/// error status when the certificate can't be read or hashed.
[[nodiscard]] Observation observe_signer_jni(JNIEnv* env);

/// Runs the app-identity checks that need a JNIEnv and returns what they observed.
///
/// Called from a JNI context such as JNI_OnLoad, it reads the app's Context and reports the authoritative package name
/// from `getPackageName()` and the signing-certificate hash from the PackageManager. The package from the Context is
/// correct even for a process whose name isn't the package, which the constructor's `/proc/self/cmdline` reading can't
/// tell. The caller appends these to the observations the constructor's `identity()` already produced.
///
/// @param env The JNI environment of the calling thread.
/// @return Two observations through package_manager: id.package, then id.signer_sha256.
[[nodiscard]] std::vector<Observation> identity(JNIEnv* env);

#endif

}  // namespace rasp::android::checks
