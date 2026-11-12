/// Inactive public Application class-loader topology and location metadata; no class resolution.
#pragma once
#include <jni.h>

#include "rasp/posix/provenance.h"

namespace rasp::android::checks {
/// Reads two bounded public parent-chain passes; never loads/probes named classes.
/// @param env Calling thread JNI environment, never retained; preexisting exceptions are preserved.
/// @param application Borrowed supplied Application Context; never globally retained here.
/// @param clock Cooperative monotonic clock.
/// @return Fixed path-free data/meta pair; probe exceptions are cleared and failure has no partial chain.
[[nodiscard]] provenance::Pair read_loader_provenance(JNIEnv* env, jobject application,
                                                      provenance::Clock clock = provenance::monotonic_ns);
/// Reads bounded public ApplicationInfo paths; no filesystem inference or hidden fields.
/// @param env Calling thread environment, never retained.
/// @param application Borrowed supplied Application Context.
/// @param clock Cooperative monotonic clock.
/// @return Complete lexical roots, or explicit unavailable/error.
[[nodiscard]] provenance::Result<provenance::Locations> read_provenance_locations(
    JNIEnv* env, jobject application, provenance::Clock clock = provenance::monotonic_ns);
/// Gets roots only from the already initialized Application; no new global reference.
[[nodiscard]] provenance::Locations application_provenance_locations();
/// Reads the actual supplied Application chain for eventual explicit dispatch; currently inactive.
[[nodiscard]] provenance::Pair loader_provenance();
}  // namespace rasp::android::checks
