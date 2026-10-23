/// The APK entries the packer writes for the payload key and the on-demand loader, so every reader takes their names
/// from one place. The packer stores all of them uncompressed, under `assets/`, so the runtime reads them without an
/// inflate step.

#pragma once

namespace rasp::android::payload {

/// The APK entry that holds the payload key, which decrypts every encrypted entry the packer writes.
// TODO: the key ships in clear in the APK, so anyone who unzips the app can decrypt its code. Fold the key into the
// cipher with white-box cryptography instead, so no separable key sits in the package.
inline constexpr const char* kKeyEntry = "assets/rasp/key.bin";

/// The APK entry that holds the encrypted class map, one `binary.class.Name,<path>` line per class.
inline constexpr const char* kMapEntry = "assets/rasp/map.bin";

/// The prefix a map `<path>` sits under, prepended to it to make a dex's full APK entry name.
inline constexpr const char* kAssetPrefix = "assets/";

}  // namespace rasp::android::payload
