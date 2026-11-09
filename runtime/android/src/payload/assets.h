/// The APK entries the packer writes for the key schedule and the on-demand loader, so every reader takes their names
/// from one place. The packer stores all of them uncompressed, under `assets/`, so the runtime reads them without an
/// inflate step.

#pragma once

namespace rasp::android::payload {

/// The APK entry that holds the key schedule's asset share: 32 bytes that are one input of the fold that rebuilds the
/// payload's root key, not a key by themselves (payload/key_schedule.h).
inline constexpr const char* kShareEntry = "assets/rasp/s.bin";

/// The APK entry that holds the encrypted class map, one `binary.class.Name,<path>` line per class.
inline constexpr const char* kMapEntry = "assets/rasp/map.bin";

/// The APK entry that holds the encrypted Java program: the steps the stub executes through the real runtime to
/// produce the share that arms the dex store.
inline constexpr const char* kJProgramEntry = "assets/rasp/j.bin";

/// The prefix of the APK entries that hold the decoys the fold program names, `<prefix>r<i>.bin`, whose digests are
/// inputs of the fold (payload/key_schedule.h).
inline constexpr const char* kDecoyEntryPrefix = "assets/rasp/r";

/// The prefix a map `<path>` sits under, prepended to it to make a dex's full APK entry name.
inline constexpr const char* kAssetPrefix = "assets/";

}  // namespace rasp::android::payload
