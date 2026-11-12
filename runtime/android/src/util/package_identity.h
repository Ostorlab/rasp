/// Public own-package identity collection using only the supported retained Application Context.

#pragma once

#include <jni.h>
#include <optional>
#include <string>

#include "util/signing_certificates.h"

namespace rasp::android::util {

/// Independent field results; missing fields mean error, while parallel signers explicitly exclude history.
struct PackageIdentity {
  /// Actual package named by the retained Application, independent of process aliases.
  std::optional<std::string> package_name;
  /// All current content signers in their original order, before digest normalization.
  std::optional<Certificates> current;
  /// Oldest-to-current history for single-signer packages, including a singleton without rotation.
  std::optional<Certificates> history;
  /// True only after a valid current collection and hasMultipleSigners; history is then unsupported.
  bool history_unsupported = false;
};

/// Queries GET_SIGNING_CERTIFICATES for Application.getPackageName, with no hidden API fallback or waiting.
/// @param env Calling thread JNI environment; null produces field errors. No environment or raw certificate is
/// retained.
/// @return Bounded per-field results; JNI failures are cleared and local references released before returning.
[[nodiscard]] PackageIdentity read_package_identity(JNIEnv* env);

}  // namespace rasp::android::util
