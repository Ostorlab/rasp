/// @file The JNI layer of the on-demand loader. The runtime loads the loader's dex, which is embedded in the library,
/// binds its native findClass, creates the loader, and installs it as the parent of the app's base loader. Everything
/// the loader does, from its install to the first time a class is needed, lives here, in native code. Serving a class
/// is also a checkpoint of the runtime's protection: at most once a second, one quick check runs on the thread that
/// asked for the class.
///
/// Only `JNI_OnLoad` is an exported symbol. It binds `RaspStub.install` with RegisterNatives; `install` in turn binds
/// `GeneratingClassLoader.findClass` on the class it just loaded. So neither native method is a `Java_...` symbol, and
/// the library's symbols can be stripped or renamed.

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <jni.h>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <sys/mman.h>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

#include "apk/location.h"
#include "checks/debugger.h"
#include "checks/hooks.h"
#include "checks/root.h"
#include "loader/loader_dex.h"
#include "panic/end_process.h"
#include "payload/assets.h"
#include "payload/cipher.h"
#include "payload/dex_store.h"
#include "payload/key_schedule.h"
#include "rasp/config.h"
#include "rasp/embedded_config.h"
#include "rasp/heartbeat.h"
#include "rasp/observation.h"
#include "rasp/panic.h"
#include "rasp/schedule.h"
#include "rasp/util/logging.h"

namespace rasp::android::loader {

namespace {

/// Everything the installed loader needs, built once in `install` and kept for the life of the process.
struct State {
  /// Where a class defined from a business dex looks for the app's native libraries, for System.loadLibrary.
  std::string library_search_path;
  /// The class map and the dex master, opened in `install` from the root key the schedule recovered; empty when the
  /// recovery or the map failed, and every findClass then falls back to the base loader.
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

/// The shortest time between two checkpoints, whichever call site runs them.
constexpr std::chrono::milliseconds kCheckpointInterval{1000};

/// A checkpoint: runs one quick check when the loader serves a class, and arms a panic when it detects something.
///
/// At most one checkpoint runs per kCheckpointInterval, across every call site and thread; every other call returns
/// after reading the clock and one atomic. The one that runs picks one check at random, the debugger, hooking or root
/// check, observes the monitoring thread's heartbeat, and passes both to panic_on_detection. It is always inlined, so
/// each call site holds its own copy, and patching one call site leaves the others. A development build logs the call
/// site, how many classes were served since the last checkpoint, how long the check took and what it observed.
///
/// @param site The call site, for development logs.
/// @param name The binary name of the class being served, for development logs.
[[gnu::always_inline]] inline void checkpoint(int site, const std::string& name) noexcept {
  static constinit RateLimit limit{kCheckpointInterval};
  static constinit std::atomic<std::uint32_t> served{0};
  if constexpr (kLoggingEnabled) {
    served.fetch_add(1, std::memory_order_relaxed);
  }
  const std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
  if (!limit.try_acquire(now)) {
    return;
  }
  std::vector<Observation> observations;
  switch (arc4random_uniform(3)) {
    case 0:
      observations = checks::debugger();
      break;
    case 1:
      observations = checks::hooks();
      break;
    default:
      observations = checks::root();
      break;
  }
  observations.push_back(monitor_heartbeat().observe(now));
  if constexpr (kLoggingEnabled) {
    const auto took =
        std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - now).count();
    std::string line = "checkpoint " + std::to_string(site) + " on " + name + " after " +
                       std::to_string(served.exchange(0, std::memory_order_relaxed)) + " classes, " +
                       std::to_string(took) + " us:";
    for (const Observation& observation : observations) {
      line += " " + describe(observation) + ";";
    }
    rasp::log(line);
  }
  static_cast<void>(panic_on_detection(observations, end_process));
}

/// The environment the key schedule's gates measure, as the loader sees it at install time.
///
/// Each fact holds on a clean device: a JNI environment whose GetVersion reports a JNI 1.x version, no tracer
/// attached, and the library loaded from a path under /data, as an installed app's is. On anything else — an
/// emulation without a real Android runtime, a device under a native debugger — one fact flips, the recovered root
/// key is wrong, and every frame's tag fails. Nothing reports why: the failure looks like a corrupt frame.
///
/// @param env The JNI environment of the calling thread.
/// @param library The library's own path, as the dynamic loader reports it, or nothing when it can't be read.
/// @return The environment the schedule folds into the root key.
[[nodiscard]] payload::Environment observe_environment(JNIEnv* env, const std::optional<std::string>& library) {
  const Observation tracer = checks::observe_tracer_pid("/proc/self/status");
  const std::int64_t* const tracer_pid = std::get_if<std::int64_t>(&tracer.value);

  payload::Environment environment;
  environment.java_environment = (static_cast<unsigned>(env->GetVersion()) & 0xFFFF0000U) == 0x00010000U;
  environment.no_tracer = tracer.status == Status::kOk && tracer_pid != nullptr && *tracer_pid == 0;
  environment.installed_under_data = library.has_value() && library->starts_with("/data/");
#if defined(__aarch64__)
  {
    std::uint64_t frequency = 0;
    // NOLINTNEXTLINE(portability-no-assembler): the observation is the mrs read itself.
    asm volatile("mrs %0, cntfrq_el0" : "=r"(frequency));
    environment.counter_frequency_plausible = frequency >= 1000000U && frequency <= 100000000U;
    std::uint64_t midr = 0;
    // NOLINTNEXTLINE(portability-no-assembler): the observation is the mrs read itself.
    asm volatile("mrs %0, midr_el1" : "=r"(midr));
    environment.cpu_identity_plausible = midr != 0;
  }
#elif defined(__x86_64__)
  {
    std::uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;
    // NOLINTNEXTLINE(portability-no-assembler): the observation is the cpuid read itself.
    asm volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(0));
    environment.cpu_identity_plausible = !(ebx == 0 && edx == 0 && ecx == 0);
  }
#endif
  return environment;
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

  std::optional<std::vector<std::uint8_t>> bytes = payload::decrypt_dex(*current.store, *dex);
  if (!bytes.has_value()) {
    return nullptr;
  }
  // Keep the decrypted dex off any swap device: the kernel cannot write it out while it is
  // locked. The pages are unlocked again right after the wipe.
  static_cast<void>(::mlock(bytes->data(), bytes->size()));
  checkpoint(2, name);
  jobject child = make_child_loader(env, generating, *bytes);
  // ART copies the buffer while it creates the loader, so our copy is wiped right after: no decrypted dex outlives
  // this call.
  payload::wipe(*bytes);
  static_cast<void>(::munlock(bytes->data(), bytes->size()));
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

  bool is_cached = false;
  jobject cached = nullptr;
  {
    const std::scoped_lock guard(current.maps_mutex);
    const auto found = current.defined.find(name);
    if (found != current.defined.end()) {
      is_cached = true;
      cached = env->NewLocalRef(found->second);
    }
  }
  if (is_cached) {
    checkpoint(1, name);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast): JNI jobject to jclass.
    return static_cast<jclass>(cached);
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
  if (owner != nullptr) {
    checkpoint(3, name);
  }
  return defined;
}

/// Creates the on-demand loader.
///
/// It recovers the payload's root key from the key schedule — the library's own sections, the s.bin entry and the
/// environment's gates (payload/key_schedule.h) — and opens the dex store over it. Without a recovered root no
/// business class can be served, and every findClass falls back to the base loader. It then loads the loader's dex,
/// which is embedded in the library, under the boot loader, binds the loaded class's native findClass to find_class,
/// and creates the loader.
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
  const std::optional<std::string> library = rasp::android::apk::self_library_path();
  if (apk.has_value() && library.has_value()) {
    const payload::Environment environment = observe_environment(env, library);
    const std::optional<payload::Key> root = payload::recover_root_key(environment, *library, *apk);
    if (root.has_value()) {
      current.store = payload::open_dex_store(*apk, *root);
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

/// The native body of `RaspStub.program`, which JNI_OnLoad binds with RegisterNatives.
///
/// It returns the decrypted Java program the packer shipped — the steps the stub executes through the real runtime —
/// or null when the store never opened or the app shipped no program. The program is root-sealed, so an emulator
/// that cannot recover the fold gets nothing to run at all; and the store stays unarmed, so no dex decrypts.
///
/// @param env The JNI environment of the calling thread.
/// @return A new byte array holding the program, or null.
jbyteArray program(JNIEnv* env, jclass /*stub*/) {
  State& current = state();
  if (!current.store.has_value() || current.store->j_program.empty()) {
    return nullptr;
  }
  const std::span<const std::uint8_t> bytes(current.store->j_program);
  const auto size = static_cast<jsize>(bytes.size());
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  jbyteArray result = env->NewByteArray(size);
  if (result != nullptr) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    env->SetByteArrayRegion(result, 0, size, reinterpret_cast<const jbyte*>(bytes.data()));
  }
  return result;
}

/// The native body of `RaspStub.arm`, which JNI_OnLoad binds with RegisterNatives.
///
/// It folds the share the stub's Java program produced into the dex master, and lets the dexes decrypt. The share
/// is 32 bytes or nothing; nothing leaves the store unarmed, and no business class ever decrypts. A wrong share
/// arms just as quietly, and every frame's tag fails.
///
/// @param env The JNI environment of the calling thread.
/// @param share The share the stub produced, or null.
void arm(JNIEnv* env, jclass /*stub*/, jbyteArray share) {
  State& current = state();
  if (!current.store.has_value() || share == nullptr) {
    return;
  }
  const auto size = static_cast<std::size_t>(env->GetArrayLength(share));
  if (size != sizeof(payload::Key)) {
    return;
  }
  payload::Key j_share{};
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  env->GetByteArrayRegion(share, 0, static_cast<jsize>(size), reinterpret_cast<jbyte*>(j_share.data()));
  payload::arm_j_store(*current.store, j_share);
}

}  // namespace

}  // namespace rasp::android::loader

/// Binds the stub's native entry points with RegisterNatives when the library loads, so the loader's native entry
/// point is not an exported `Java_...` symbol. JNI_OnLoad is the only symbol the VM resolves by name.
///
/// The stub class the packer points the app's manifest at is named per app, so its name arrives with the runtime's
/// config: the class is looked up under the name the config carries, and the library holds none. A config without a
/// class name, or one that fails to resolve, leaves the entry points unbound, the library reports JNI_ERR, and the
/// load fails the way a load of a runtime whose app was never packed for fails.
///
/// @param vm The Java virtual machine loading the library.
/// @return The JNI version the library needs, or JNI_ERR when the method can't be bound.
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* /*reserved*/) {
  void* raw_env = nullptr;
  if (vm->GetEnv(&raw_env, JNI_VERSION_1_6) != JNI_OK) {
    return JNI_ERR;
  }
  auto* env = static_cast<JNIEnv*>(raw_env);
  const rasp::Config config = rasp::read_embedded_config();
  if (!config.stub_class.has_value() || config.stub_class->empty()) {
    return JNI_ERR;
  }
  std::string class_name = *config.stub_class;
  std::ranges::replace(class_name, '.', '/');
  jclass stub = env->FindClass(class_name.c_str());
  if (stub == nullptr) {
    env->ExceptionClear();
    return JNI_ERR;
  }
  const std::array<JNINativeMethod, 3> methods = {
      {
          {
              .name = "install",
              .signature = "(Ljava/lang/ClassLoader;Ljava/lang/String;)V",
              // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
              .fnPtr = reinterpret_cast<void*>(&rasp::android::loader::install),
          },
          {
              .name = "program",
              .signature = "()[B",
              // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
              .fnPtr = reinterpret_cast<void*>(&rasp::android::loader::program),
          },
          {
              .name = "arm",
              .signature = "([B)V",
              // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
              .fnPtr = reinterpret_cast<void*>(&rasp::android::loader::arm),
          },
      },
  };
  const jint registered = env->RegisterNatives(stub, methods.data(), static_cast<jint>(methods.size()));
  env->DeleteLocalRef(stub);
  if (registered != JNI_OK) {
    env->ExceptionClear();
    return JNI_ERR;
  }
  return JNI_VERSION_1_6;
}
