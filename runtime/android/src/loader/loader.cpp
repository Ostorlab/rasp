/// Building the in-memory class loader with JNI and storing it in the stub's static field.

#include "loader/loader.h"

#include <algorithm>
#include <cstdint>
#include <jni.h>
#include <span>
#include <string>
#include <vector>

#include "payload/payload.h"

namespace rasp::android::loader {

namespace {

/// The stub class that holds the class loader, and the field the loader is stored in.
constexpr const char* kStubClass = "co/ostorlab/rasp/RaspStub";
constexpr const char* kLoaderField = "classLoader";
constexpr const char* kLoaderFieldSignature = "Ljava/lang/ClassLoader;";

/// The in-memory class loader and the constructor the runtime calls, which takes the native-library search path.
constexpr const char* kLoaderClass = "dalvik/system/InMemoryDexClassLoader";
constexpr const char* kLoaderConstructorSignature =
    "([Ljava/nio/ByteBuffer;Ljava/lang/String;Ljava/lang/ClassLoader;)V";

/// The byte-buffer class and the factory that wraps a byte array in one.
constexpr const char* kBufferClass = "java/nio/ByteBuffer";
constexpr const char* kWrapName = "wrap";
constexpr const char* kWrapSignature = "([B)Ljava/nio/ByteBuffer;";

/// The reflection used to read the loader that loaded the stub.
constexpr const char* kClassClass = "java/lang/Class";
constexpr const char* kGetClassLoaderName = "getClassLoader";
constexpr const char* kGetClassLoaderSignature = "()Ljava/lang/ClassLoader;";

/// Makes a Java byte array holding `data`, or null, with no pending exception, when the JVM can't allocate it.
[[nodiscard]] jbyteArray to_java_bytes(JNIEnv* env, std::span<const std::uint8_t> data) {
  jbyteArray array = env->NewByteArray(static_cast<jsize>(data.size()));
  if (array == nullptr) {
    env->ExceptionClear();
    return nullptr;
  }
  void* const elements = env->GetPrimitiveArrayCritical(array, nullptr);
  if (elements == nullptr) {
    env->ExceptionClear();
    env->DeleteLocalRef(array);
    return nullptr;
  }
  std::ranges::copy(data, static_cast<std::uint8_t*>(elements));
  env->ReleasePrimitiveArrayCritical(array, elements, 0);
  return array;
}

/// Makes a `ByteBuffer[]` with one buffer wrapping each dex file's bytes, or null when a JNI call fails.
[[nodiscard]] jobjectArray to_byte_buffers(JNIEnv* env, const std::vector<payload::Dex>& dexes) {
  jclass buffer_class = env->FindClass(kBufferClass);
  if (buffer_class == nullptr) {
    env->ExceptionClear();
    return nullptr;
  }
  jmethodID wrap = env->GetStaticMethodID(buffer_class, kWrapName, kWrapSignature);
  if (wrap == nullptr) {
    env->ExceptionClear();
    return nullptr;
  }
  jobjectArray buffers = env->NewObjectArray(static_cast<jsize>(dexes.size()), buffer_class, nullptr);
  if (buffers == nullptr) {
    env->ExceptionClear();
    return nullptr;
  }
  jsize index = 0;
  for (const payload::Dex& dex : dexes) {
    jbyteArray bytes = to_java_bytes(env, dex.data);
    if (bytes == nullptr) {
      return nullptr;
    }
    jobject buffer = env->CallStaticObjectMethod(buffer_class, wrap, bytes);
    env->DeleteLocalRef(bytes);
    if (buffer == nullptr || env->ExceptionCheck() == JNI_TRUE) {
      env->ExceptionClear();
      return nullptr;
    }
    env->SetObjectArrayElement(buffers, index, buffer);
    env->DeleteLocalRef(buffer);
    ++index;
  }
  return buffers;
}

/// The loader that loaded the stub, which becomes the parent of the in-memory loader, or null for the boot loader.
[[nodiscard]] jobject stub_parent_loader(JNIEnv* env, jclass stub) {
  jclass class_class = env->FindClass(kClassClass);
  if (class_class == nullptr) {
    env->ExceptionClear();
    return nullptr;
  }
  jmethodID get_loader = env->GetMethodID(class_class, kGetClassLoaderName, kGetClassLoaderSignature);
  if (get_loader == nullptr) {
    env->ExceptionClear();
    return nullptr;
  }
  return env->CallObjectMethod(stub, get_loader);
}

}  // namespace

bool publish(JNIEnv* env, const std::vector<payload::Dex>& dexes, const std::string& library_dir) {
  jclass stub = env->FindClass(kStubClass);
  if (stub == nullptr) {
    env->ExceptionClear();
    return false;
  }
  jfieldID field = env->GetStaticFieldID(stub, kLoaderField, kLoaderFieldSignature);
  if (field == nullptr) {
    env->ExceptionClear();
    return false;
  }
  jobjectArray buffers = to_byte_buffers(env, dexes);
  if (buffers == nullptr) {
    return false;
  }
  jstring path = env->NewStringUTF(library_dir.c_str());
  if (path == nullptr) {
    env->ExceptionClear();
    return false;
  }
  jobject parent = stub_parent_loader(env, stub);
  jclass loader_class = env->FindClass(kLoaderClass);
  if (loader_class == nullptr) {
    env->ExceptionClear();
    return false;
  }
  jmethodID constructor = env->GetMethodID(loader_class, "<init>", kLoaderConstructorSignature);
  if (constructor == nullptr) {
    env->ExceptionClear();
    return false;
  }
  jobject loader = env->NewObject(loader_class, constructor, buffers, path, parent);
  if (loader == nullptr || env->ExceptionCheck() == JNI_TRUE) {
    env->ExceptionClear();
    return false;
  }
  env->SetStaticObjectField(stub, field, loader);
  return true;
}

}  // namespace rasp::android::loader
