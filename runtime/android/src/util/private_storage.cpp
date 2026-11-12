/// Worker-only private storage from the retained public Application, including calls after late attachment.
#include "rasp/private_storage.h"

#include <cstddef>
#include <expected>
#include <jni.h>
#ifndef __ANDROID__
#include <jni_md.h>
#endif
#include <string>

#include "rasp/posix/private_storage.h"
#include "util/application_context.h"
#include "util/jni.h"
#include "util/posix_file.h"

namespace rasp {
namespace {
constexpr jsize kMaxPathBytes = 4095;

/// Copies a bounded public File path and releases the VM string before any filesystem operations.
[[nodiscard]] std::expected<std::string, StorageError> file_path(JNIEnv* env, jobject file, jclass file_class,
                                                                 const char* method_name) {
  jmethodID method = env->GetMethodID(file_class, method_name, "()Ljava/lang/String;");
  if (android::util::threw(env) || method == nullptr) {
    return std::unexpected(StorageError::kUnavailable);
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast): the resolved public File method has a String result.
  auto* text = static_cast<jstring>(env->CallObjectMethodA(file, method, nullptr));
  if (android::util::threw(env) || text == nullptr) {
    return std::unexpected(StorageError::kUnavailable);
  }
  const jsize length = env->GetStringUTFLength(text);
  if (android::util::threw(env) || length <= 0 || length > kMaxPathBytes) {
    return std::unexpected(StorageError::kInvalidDirectory);
  }
  const char* bytes = env->GetStringUTFChars(text, nullptr);
  const bool failed = android::util::threw(env);
  if (failed || bytes == nullptr) {
    if (bytes != nullptr) {
      env->ReleaseStringUTFChars(text, bytes);
    }
    return std::unexpected(StorageError::kUnavailable);
  }
  std::string path(bytes, static_cast<std::size_t>(length));
  env->ReleaseStringUTFChars(text, bytes);
  if (android::util::threw(env)) {
    return std::unexpected(StorageError::kUnavailable);
  }
  return path;
}

/// Uses public File APIs to resolve platform ancestor aliases, while rejecting a symlink as the returned directory.
[[nodiscard]] std::expected<PrivateStorage, StorageError> acquire_in_frame(JNIEnv* env) {
  const auto application = android::util::application_context(env);
  if (!application.has_value() || *application == nullptr) {
    return std::unexpected(StorageError::kUnavailable);
  }
  jclass application_class = env->FindClass("android/app/Application");
  if (android::util::threw(env) || application_class == nullptr) {
    return std::unexpected(StorageError::kUnavailable);
  }
  jmethodID get_directory = env->GetMethodID(application_class, "getNoBackupFilesDir", "()Ljava/io/File;");
  if (android::util::threw(env) || get_directory == nullptr) {
    return std::unexpected(StorageError::kUnavailable);
  }
  jobject file = env->CallObjectMethodA(*application, get_directory, nullptr);
  if (android::util::threw(env) || file == nullptr) {
    return std::unexpected(StorageError::kUnavailable);
  }
  jclass file_class = env->FindClass("java/io/File");
  if (android::util::threw(env) || file_class == nullptr) {
    return std::unexpected(StorageError::kUnavailable);
  }
  const jboolean is_file = env->IsInstanceOf(file, file_class);
  if (android::util::threw(env) || is_file != JNI_TRUE) {
    return std::unexpected(StorageError::kInvalidDirectory);
  }
  const auto absolute = file_path(env, file, file_class, "getAbsolutePath");
  if (!absolute.has_value()) {
    return std::unexpected(absolute.error());
  }
  const auto canonical = file_path(env, file, file_class, "getCanonicalPath");
  if (!canonical.has_value()) {
    return std::unexpected(canonical.error());
  }
  struct stat original{};
  if (lstat(absolute->c_str(), &original) != 0 || !S_ISDIR(original.st_mode)) {
    return std::unexpected(StorageError::kInvalidDirectory);
  }
  const auto parent_directory = posix::open_platform_directory({.absolute = *absolute, .canonical = *canonical});
  if (!parent_directory.has_value()) {
    return std::unexpected(parent_directory.error());
  }
  auto storage = posix::acquire_private_storage_in(*parent_directory, *canonical);
  if (!storage.has_value()) {
    return storage;
  }
  struct stat parent{};
  struct stat after{};
  if (fstatat(storage->native_handle(), "..", &parent, AT_SYMLINK_NOFOLLOW) != 0 ||
      lstat(absolute->c_str(), &after) != 0 || !S_ISDIR(after.st_mode) || original.st_dev != parent.st_dev ||
      original.st_ino != parent.st_ino || after.st_dev != parent.st_dev || after.st_ino != parent.st_ino) {
    return std::unexpected(StorageError::kInvalidDirectory);
  }
  return storage;
}

/// Contains all local references and clears VM failures before returning to the worker or host caller.
[[nodiscard]] std::expected<PrivateStorage, StorageError> acquire_with_env(JNIEnv* env) {
  if (env->PushLocalFrame(12) != JNI_OK) {
    static_cast<void>(android::util::threw(env));
    return std::unexpected(StorageError::kUnavailable);
  }
  auto storage = acquire_in_frame(env);
  env->PopLocalFrame(nullptr);
  if (android::util::threw(env)) {
    return std::unexpected(StorageError::kUnavailable);
  }
  return storage;
}
}  // namespace

std::expected<PrivateStorage, StorageError> acquire_private_storage() {
  JavaVM* vm = nullptr;
  jsize count = 0;
  if (JNI_GetCreatedJavaVMs(&vm, 1, &count) != JNI_OK || count != 1 || vm == nullptr) {
    return std::unexpected(StorageError::kUnavailable);
  }
  void* raw_env = nullptr;
  const jint initial = vm->GetEnv(&raw_env, JNI_VERSION_1_6);
  const bool attach = initial == JNI_EDETACHED;
  if (attach) {
#ifdef __ANDROID__
    JNIEnv* android_env = nullptr;
    if (vm->AttachCurrentThread(&android_env, nullptr) != JNI_OK) {
      return std::unexpected(StorageError::kUnavailable);
    }
    raw_env = android_env;
#else
    if (vm->AttachCurrentThread(&raw_env, nullptr) != JNI_OK) {
      return std::unexpected(StorageError::kUnavailable);
    }
#endif
  } else if (initial != JNI_OK) {
    return std::unexpected(StorageError::kUnavailable);
  }
  if (raw_env == nullptr) {
    if (attach) {
      static_cast<void>(vm->DetachCurrentThread());
    }
    return std::unexpected(StorageError::kUnavailable);
  }
  auto storage = acquire_with_env(static_cast<JNIEnv*>(raw_env));
  if (attach && vm->DetachCurrentThread() != JNI_OK) {
    return std::unexpected(StorageError::kUnavailable);
  }
  return storage;
}
}  // namespace rasp
