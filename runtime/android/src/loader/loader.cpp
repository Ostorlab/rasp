/// @file The JNI layer of the on-demand loader. The runtime loads the loader's dex, which is embedded in the library,
/// binds its native findClass, creates the loader, and installs it as the parent of the app's base loader. Everything
/// the loader does, from its install to the first time a class is needed, lives here, in native code.
///
/// Only `JNI_OnLoad` is an exported symbol. It binds `RaspStub.install` with RegisterNatives; `install` in turn binds
/// `GeneratingClassLoader.findClass` on the class it just loaded. So neither native method is a `Java_...` symbol, and
/// the library's symbols can be stripped or renamed.

#include <cstdint>
#include <jni.h>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "apk/archive.h"
#include "apk/location.h"
#include "events/capture_bridge.h"
#include "events/window_bridge.h"
#include "loader/loader_dex.h"
#include "payload/assets.h"
#include "payload/cipher.h"
#include "payload/dex_store.h"
#include "rasp/util/logging.h"
#include "util/application_context.h"

namespace rasp::android::loader {

namespace {

/// Everything the installed loader needs, built once in `install` and kept for the life of the process.
struct State {
  /// Where a class defined from a business dex looks for the app's native libraries, for System.loadLibrary.
  std::string library_search_path;
  /// The class map and key, read from the app's APK in install. Empty when they couldn't be read; every findClass then
  /// falls back to the base loader.
  std::optional<payload::DexStore> store;
  /// A global reference to the app's base class loader, which holds the framework classes.
  jobject base = nullptr;
  /// A global reference to `dalvik.system.InMemoryDexClassLoader`.
  jclass in_memory_loader = nullptr;
  /// A global reference to `java.nio.ByteBuffer`.
  jclass byte_buffer = nullptr;
  /// The `InMemoryDexClassLoader(ByteBuffer[], String, ClassLoader)` constructor.
  jmethodID in_memory_ctor = nullptr;
  /// `ClassLoader.findClass(String)`, called on a child loader or on the base loader.
  jmethodID base_find_class = nullptr;
  /// Guards `defined`, `owners`, `define_locks` and `dex_locks`.
  std::mutex maps_mutex;
  /// The class each name resolved to, as a global reference: the cache of findClass results.
  std::unordered_map<std::string, jobject> defined;
  /// The child loader that defines each business class, as a global reference.
  std::unordered_map<std::string, jobject> owners;
  /// One lock per class name being defined, so two threads never define the same class at the same time. The
  /// mutexes are held by value; the map is node-based, so a pointer to one stays valid as the map grows.
  std::unordered_map<std::string, std::mutex> define_locks;
  /// One lock per dex being loaded, keyed by its entry, so two threads never build two child loaders over the same
  /// dex. Held by value like `define_locks`, so a pointer to one stays valid as the map grows.
  std::unordered_map<std::string, std::mutex> dex_locks;
};

/// Reads the payload key from the app's APK, the key that decrypts the class map and every business dex.
///
/// @param apk The path of the app's APK.
/// @return The key. Nothing when the key entry is absent or is not kKeySize bytes.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> read_payload_key(const std::string& apk) {
  std::optional<std::vector<std::uint8_t>> key = rasp::android::apk::read_stored_entry(apk, payload::kKeyEntry);
  if (!key.has_value() || key->size() != payload::kKeySize) {
    return std::nullopt;
  }
  return key;
}

/// The loader state, shared by every function in this file.
///
/// The first call builds it. It is never destroyed, so there is no exit-time destructor.
///
/// @return The state. Every call returns the same one.
[[nodiscard]] State& state() {
  // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
  static auto* const kState = new State();
  return *kState;
}

/// Leaves a ClassNotFoundException pending in the calling thread, for a native method to return with.
///
/// When the exception's own class can't be found, the error from that lookup is the pending exception instead.
///
/// @param env The JNI environment of the calling thread.
/// @param name The class name, for the exception's message.
void throw_class_not_found(JNIEnv* env, const std::string& name) {
  jclass error = env->FindClass("java/lang/ClassNotFoundException");
  if (error != nullptr) {
    env->ThrowNew(error, name.c_str());
    env->DeleteLocalRef(error);
  }
}

/// Reads a Java string, in the modified UTF-8 that JNI uses.
///
/// @param env The JNI environment of the calling thread.
/// @param value The string to read. It can be null.
/// @return The string's bytes. Empty when `value` is null or can't be read.
[[nodiscard]] std::string to_string(JNIEnv* env, jstring value) {
  if (value == nullptr) {
    return {};
  }
  const char* chars = env->GetStringUTFChars(value, nullptr);
  if (chars == nullptr) {
    env->ExceptionClear();
    return {};
  }
  std::string result(chars);
  env->ReleaseStringUTFChars(value, chars);
  return result;
}

/// Creates an InMemoryDexClassLoader over a decrypted business dex.
///
/// Its parent is the generating loader, so a class it defines resolves its references back through the generating
/// loader. ART copies the buffer while it creates the loader, so `dex` need not outlive this call.
///
/// @param env The JNI environment of the calling thread.
/// @param generating The generating loader, which becomes the new loader's parent.
/// @param dex The decrypted dex.
/// @return A local reference to the new loader. Null when a JNI call fails, possibly with a Java exception pending.
[[nodiscard]] jobject make_child_loader(JNIEnv* env, jobject generating, const std::vector<std::uint8_t>& dex) {
  const State& current = state();
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
  jobject buffer = env->NewDirectByteBuffer(const_cast<std::uint8_t*>(dex.data()), static_cast<jlong>(dex.size()));
  if (buffer == nullptr) {
    return nullptr;
  }
  jobjectArray buffers = env->NewObjectArray(1, current.byte_buffer, buffer);
  env->DeleteLocalRef(buffer);
  if (buffers == nullptr) {
    return nullptr;
  }
  jstring path = env->NewStringUTF(current.library_search_path.c_str());
  if (path == nullptr) {
    env->DeleteLocalRef(buffers);
    return nullptr;
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): the JNI object constructors are variadic by design.
  jobject loader = env->NewObject(current.in_memory_loader, current.in_memory_ctor, buffers, path, generating);
  env->DeleteLocalRef(buffers);
  env->DeleteLocalRef(path);
  return loader;
}

/// The child loader that defines a business class, created the first time one of its dex's classes is needed.
///
/// The first time, it decrypts the class's dex, creates a child loader over it, and records that loader for every class
/// the dex defines, so a later call for any of them returns it without decrypting again.
///
/// @param env The JNI environment of the calling thread.
/// @param generating The generating loader, which becomes the child loader's parent.
/// @param name The binary name of the class.
/// @return A global reference to the child loader, which is kept for the life of the process. Null when `name` is not a
/// business class, or when its dex can't be read, decrypted or loaded; the caller then falls back to the base loader.
[[nodiscard]] jobject owner_of(JNIEnv* env, jobject generating, const std::string& name) {
  State& current = state();
  {
    const std::scoped_lock guard(current.maps_mutex);
    const auto found = current.owners.find(name);
    if (found != current.owners.end()) {
      return found->second;
    }
  }
  if (!current.store.has_value()) {
    return nullptr;
  }
  const payload::EncryptedDex* dex = payload::dex_of(*current.store, name);
  if (dex == nullptr) {
    return nullptr;
  }

  // Serialise the decrypt, create and fill for this dex, keyed by its entry, so two threads that first touch two
  // classes of the same dex never build two child loaders over it.
  std::mutex* load_lock = nullptr;
  {
    const std::scoped_lock guard(current.maps_mutex);
    load_lock = &current.dex_locks[dex->entry];
  }
  const std::scoped_lock load_guard(*load_lock);

  // Another thread may have loaded the dex while we waited for its lock; take its loader if so.
  {
    const std::scoped_lock guard(current.maps_mutex);
    const auto found = current.owners.find(name);
    if (found != current.owners.end()) {
      return found->second;
    }
  }

  const std::optional<std::vector<std::uint8_t>> bytes = payload::decrypt_dex(*current.store, *dex);
  if (!bytes.has_value()) {
    return nullptr;
  }
  jobject child = make_child_loader(env, generating, *bytes);
  if (child == nullptr) {
    // make_child_loader may leave a JNI exception pending; clear it so the caller's base-loader fallback is clean.
    env->ExceptionClear();
    return nullptr;
  }
  jobject child_global = env->NewGlobalRef(child);
  env->DeleteLocalRef(child);
  if (child_global == nullptr) {
    return nullptr;
  }
  const std::scoped_lock guard(current.maps_mutex);
  for (const std::string& companion : dex->classes) {
    current.owners.emplace(companion, child_global);
  }
  return child_global;
}

/// The native body of `GeneratingClassLoader.findClass`, which install binds with RegisterNatives.
///
/// Android calls it only for a class the parent loaders did not find, so for the app's own names. It serves a business
/// class from the child loader over its decrypted dex, and falls back to the base loader for a framework class that a
/// business class references. Each result is cached, so a class is defined once, and two threads that ask for the same
/// class wait for each other. A class whose definition needs itself, as its own superclass or interface, gets a
/// ClassNotFoundException instead of endless recursion. The names in progress are kept in one set per thread, created
/// on first use and never freed, so there is no thread-exit destructor.
///
/// @param env The JNI environment of the calling thread.
/// @param generating The generating loader whose findClass was called.
/// @param class_name The binary name of the class.
/// @return A local reference to the class. Null when it can't be found, with a ClassNotFoundException or the defining
/// loader's exception pending.
[[nodiscard]] jclass find_class(JNIEnv* env, jobject generating, jstring class_name) {
  const std::string name = to_string(env, class_name);
  State& current = state();

  {
    const std::scoped_lock guard(current.maps_mutex);
    const auto found = current.defined.find(name);
    if (found != current.defined.end()) {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast): JNI jobject to jclass.
      return static_cast<jclass>(env->NewLocalRef(found->second));
    }
  }

  // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
  thread_local auto* in_progress = new std::unordered_set<std::string>();
  if (!in_progress->insert(name).second) {
    throw_class_not_found(env, name);
    return nullptr;
  }
  class InProgressGuard {
   public:
    InProgressGuard(std::unordered_set<std::string>* set, std::string name) : set_(set), name_(std::move(name)) {}
    InProgressGuard(const InProgressGuard&) = delete;
    InProgressGuard(InProgressGuard&&) = delete;
    InProgressGuard& operator=(const InProgressGuard&) = delete;
    InProgressGuard& operator=(InProgressGuard&&) = delete;
    ~InProgressGuard() { set_->erase(name_); }

   private:
    std::unordered_set<std::string>* set_;
    std::string name_;
  };
  const InProgressGuard scope_exit(in_progress, name);

  std::mutex* lock = nullptr;
  {
    const std::scoped_lock guard(current.maps_mutex);
    lock = &current.define_locks[name];
  }
  const std::scoped_lock define_guard(*lock);

  {
    const std::scoped_lock guard(current.maps_mutex);
    const auto found = current.defined.find(name);
    if (found != current.defined.end()) {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast): JNI jobject to jclass.
      return static_cast<jclass>(env->NewLocalRef(found->second));
    }
  }

  jobject owner = owner_of(env, generating, name);
  jobject defining = owner != nullptr ? owner : current.base;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,cppcoreguidelines-pro-type-static-cast-downcast): JNI call, jobject to jclass.
  auto* defined = static_cast<jclass>(env->CallObjectMethod(defining, current.base_find_class, class_name));
  if (env->ExceptionCheck() == JNI_TRUE) {
    return nullptr;
  }
  if (defined == nullptr) {
    throw_class_not_found(env, name);
    return nullptr;
  }
  {
    const std::scoped_lock guard(current.maps_mutex);
    jobject global = env->NewGlobalRef(defined);
    if (global != nullptr) {
      current.defined.emplace(name, global);
    }
  }
  return defined;
}

/// Creates the on-demand loader.
///
/// It reads the class map and key from the app's own APK. Without them no business class can be served, and every
/// findClass falls back to the base loader. It then loads the loader's dex, which is embedded in the library, under the
/// boot loader, binds the loaded class's native findClass to find_class, and creates the loader.
///
/// @param env The JNI environment of the calling thread.
/// @param base The app's base class loader, which holds the framework classes.
/// @param library_search_path Where a class defined from a business dex looks for the app's native libraries.
/// @return A local reference to a new GeneratingClassLoader, whose parent is the boot loader. Null on any failure, with
/// no Java exception pending.
[[nodiscard]] jobject make_loader(JNIEnv* env, jobject base, jstring library_search_path) {
  State& current = state();
  current.library_search_path = to_string(env, library_search_path);

  const std::optional<std::string> apk = rasp::android::apk::self_apk_path();
  if (apk.has_value()) {
    const std::optional<std::vector<std::uint8_t>> key = read_payload_key(*apk);
    if (key.has_value()) {
      current.store = payload::open_dex_store(*apk, *key);
    }
  }

  jclass class_loader = env->FindClass("java/lang/ClassLoader");
  jclass in_memory = env->FindClass("dalvik/system/InMemoryDexClassLoader");
  jclass byte_buffer = env->FindClass("java/nio/ByteBuffer");
  if (class_loader == nullptr || in_memory == nullptr || byte_buffer == nullptr) {
    env->ExceptionClear();
    return nullptr;
  }
  jmethodID get_parent = env->GetMethodID(class_loader, "getParent", "()Ljava/lang/ClassLoader;");
  jmethodID load_class = env->GetMethodID(class_loader, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
  jmethodID in_memory_ctor =
      env->GetMethodID(in_memory, "<init>", "([Ljava/nio/ByteBuffer;Ljava/lang/String;Ljava/lang/ClassLoader;)V");
  jmethodID base_find_class = env->GetMethodID(class_loader, "findClass", "(Ljava/lang/String;)Ljava/lang/Class;");
  if (get_parent == nullptr || load_class == nullptr || in_memory_ctor == nullptr || base_find_class == nullptr) {
    env->ExceptionClear();
    return nullptr;
  }

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast): JNI jobject to jclass.
  current.in_memory_loader = static_cast<jclass>(env->NewGlobalRef(in_memory));
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast): JNI jobject to jclass.
  current.byte_buffer = static_cast<jclass>(env->NewGlobalRef(byte_buffer));
  current.in_memory_ctor = in_memory_ctor;
  current.base_find_class = base_find_class;
  current.base = env->NewGlobalRef(base);
  if (current.in_memory_loader == nullptr || current.byte_buffer == nullptr || current.base == nullptr) {
    env->ExceptionClear();
    return nullptr;
  }

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): the JNI call methods are variadic by design.
  jobject boot = env->CallObjectMethod(base, get_parent);
  if (env->ExceptionCheck() == JNI_TRUE) {
    env->ExceptionClear();
    return nullptr;
  }

  const std::vector<std::uint8_t> dex = loader_dex();
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
  jobject buffer = env->NewDirectByteBuffer(const_cast<std::uint8_t*>(dex.data()), static_cast<jlong>(dex.size()));
  jobjectArray buffers = env->NewObjectArray(1, byte_buffer, buffer);
  if (buffer == nullptr || buffers == nullptr) {
    env->ExceptionClear();
    return nullptr;
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): the JNI object constructors are variadic by design.
  jobject bootstrap = env->NewObject(in_memory, in_memory_ctor, buffers, library_search_path, boot);
  if (bootstrap == nullptr) {
    env->ExceptionClear();
    return nullptr;
  }
  jstring loader_name = env->NewStringUTF(kLoaderClassName);
  if (loader_name == nullptr) {
    env->ExceptionClear();
    return nullptr;
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,cppcoreguidelines-pro-type-static-cast-downcast): JNI call, jobject to jclass.
  auto* generating_class = static_cast<jclass>(env->CallObjectMethod(bootstrap, load_class, loader_name));
  if (generating_class == nullptr || env->ExceptionCheck() == JNI_TRUE) {
    env->ExceptionClear();
    return nullptr;
  }

  const JNINativeMethod method = {
      .name = "findClass",
      .signature = "(Ljava/lang/String;)Ljava/lang/Class;",
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      .fnPtr = reinterpret_cast<void*>(&find_class),
  };
  if (env->RegisterNatives(generating_class, &method, 1) != JNI_OK) {
    env->ExceptionClear();
    return nullptr;
  }

  jmethodID generating_ctor =
      env->GetMethodID(generating_class, "<init>", "(Ljava/lang/ClassLoader;Ljava/lang/ClassLoader;)V");
  if (generating_ctor == nullptr) {
    env->ExceptionClear();
    return nullptr;
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): the JNI object constructors are variadic by design.
  jobject generating = env->NewObject(generating_class, generating_ctor, boot, base);
  if (generating == nullptr) {
    env->ExceptionClear();
  }
  return generating;
}

/// The native body of `RaspStub.install`, which JNI_OnLoad binds with RegisterNatives.
///
/// It creates the on-demand loader and installs it as the parent of the app's base loader, by writing the base loader's
/// `ClassLoader.parent` field, so the chain is boot <- on-demand loader (business classes) <- base (framework classes).
/// A framework class can then reference a business class. On any failure the base loader is left unchanged, no Java
/// exception is left pending, and a development build logs that the loader was not installed. The `RaspStub` class it
/// is called on is not used.
///
/// @param env The JNI environment of the calling thread.
/// @param base The app's base class loader, which holds the framework classes.
/// @param library_search_path Where a class defined from a business dex looks for the app's native libraries.
void install(JNIEnv* env, jclass /*stub*/, jobject base, jstring library_search_path) {
  jobject generating = make_loader(env, base, library_search_path);
  jclass class_loader = env->FindClass("java/lang/ClassLoader");
  jfieldID parent =
      class_loader != nullptr ? env->GetFieldID(class_loader, "parent", "Ljava/lang/ClassLoader;") : nullptr;
  if (generating == nullptr || parent == nullptr) {
    env->ExceptionClear();
    if constexpr (kLoggingEnabled) {
      rasp::log("the on-demand loader is not installed; the app keeps its base loader");
    }
    return;
  }
  env->SetObjectField(base, parent, generating);
}

}  // namespace

}  // namespace rasp::android::loader

/// Binds RaspStub.install and optionally RuntimeBridge initialization with RegisterNatives when the library loads.
/// JNI_OnLoad is the only symbol the VM resolves by name; bridge failure leaves the existing loader available.
///
/// @param vm The Java virtual machine loading the library.
/// @return The JNI version the library needs, or JNI_ERR when the method can't be bound.
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* /*reserved*/) {
  void* raw_env = nullptr;
  if (vm->GetEnv(&raw_env, JNI_VERSION_1_6) != JNI_OK) {
    return JNI_ERR;
  }
  auto* env = static_cast<JNIEnv*>(raw_env);
  jclass stub = env->FindClass("co/ostorlab/rasp/RaspStub");
  if (stub == nullptr) {
    env->ExceptionClear();
    return JNI_ERR;
  }
  const JNINativeMethod method = {
      .name = "install",
      .signature = "(Ljava/lang/ClassLoader;Ljava/lang/String;)V",
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      .fnPtr = reinterpret_cast<void*>(&rasp::android::loader::install),
  };
  const jint registered = env->RegisterNatives(stub, &method, 1);
  env->DeleteLocalRef(stub);
  if (registered != JNI_OK) {
    env->ExceptionClear();
    return JNI_ERR;
  }
  static_cast<void>(rasp::android::util::register_context_bridge(env));
  static_cast<void>(rasp::android::events::register_window_bridge(env));
  static_cast<void>(rasp::android::events::register_capture_bridge(env));
  return JNI_VERSION_1_6;
}
