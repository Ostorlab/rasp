/// Building a class loader over the decrypted dex files and handing it to the stub.

#pragma once

#include <jni.h>
#include <string>
#include <vector>

#include "payload/payload.h"

namespace rasp::android::loader {

/// Builds an in-memory class loader over the app's decrypted dex files and stores it in the stub's static field.
///
/// The loader is a `dalvik.system.InMemoryDexClassLoader`, so the dex files are served from memory and never written
/// to disk. Its parent is the loader that loaded the stub, and its native-library search path is `library_dir`, so the
/// app's own classes and native libraries load the way they would in the unprotected app. The stub returns this loader
/// from `instantiateClassLoader`, so Android creates the app's Application and components from it.
///
/// @param env The JNI environment of the calling thread.
/// @param dexes The app's decrypted dex files, in load order.
/// @param library_dir The directory the app's native libraries load from.
/// @return `true` when the loader was built and stored, `false` when a JNI call failed, leaving the field unset.
[[nodiscard]] bool publish(JNIEnv* env, const std::vector<payload::Dex>& dexes, const std::string& library_dir);

}  // namespace rasp::android::loader
