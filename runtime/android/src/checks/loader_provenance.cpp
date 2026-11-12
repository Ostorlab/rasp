/// Inactive public topology implementation; no boot registration or named class loading.
#include "checks/loader_provenance.h"

#include <array>
#include <cstddef>
#include <expected>
#include <jni.h>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "checks/loader_provenance_jni.h"
#include "rasp/posix/provenance.h"
#include "util/application_context.h"
#include "util/jni.h"

namespace rasp::android::checks {
namespace {
using provenance::Error;
using provenance::Result;
/// Per-call state; never stores JNI handles or environments across invocations.
class Probe {
 public:
  /// At most900 checkpoints: exception queries plus public operations and at most128 cleanup calls fit2048 JNI calls.
  Probe(JNIEnv* env, provenance::Clock clock) : env_(env), budget_(clock, 900) {}
  /// Borrows this call's JNI environment only.
  [[nodiscard]] JNIEnv* env() const { return env_; }
  /// Returns the first probe-boundary failure.
  [[nodiscard]] Error error() const { return error_; }
  /// Checks exceptions and work bounds before the next JNI operation.
  [[nodiscard]] bool next() {
    if (env_->ExceptionCheck() != JNI_FALSE) {
      env_->ExceptionClear();
      error_ = Error::kJni;
      return false;
    }
    if (!budget_.step()) {
      error_ = budget_.error();
      return false;
    }
    return true;
  }
  /// Calls a public zero-argument object method and checks before subsequent JNI operations.
  [[nodiscard]] Result<jobject> call(jobject object, jmethodID method) {
    if (object == nullptr || method == nullptr) {
      return std::unexpected(Error::kJni);
    }
    if (!next()) {
      return std::unexpected(error_);
    }
    jobject result = env_->CallObjectMethodA(object, method, nullptr);
    if (!next()) {
      return std::unexpected(error_);
    }
    return result;
  }

 private:
  JNIEnv* env_;
  provenance::Budget budget_;
  Error error_ = Error::kJni;
};
/// Owns a64-slot local frame and clears only exceptions generated after entry.
template <typename T>
Result<T> framed(JNIEnv* env, jobject application, provenance::Clock clock, Result<T> (*read)(Probe&, jobject)) {
  if (env == nullptr) {
    return std::unexpected(Error::kNativeUnavailable);
  }
  if (env->ExceptionCheck() != JNI_FALSE) {
    return std::unexpected(Error::kJni);
  }
  if (application == nullptr) {
    return std::unexpected(Error::kContextAbsent);
  }
  Probe probe(env, clock);
  if (!probe.next()) {
    return std::unexpected(probe.error());
  }
  const auto pushed = env->PushLocalFrame(64);
  const bool checked = probe.next();
  if (pushed < 0) {
    return std::unexpected(Error::kJni);
  }
  auto result = checked ? read(probe, application) : Result<T>(std::unexpected(probe.error()));
  env->PopLocalFrame(nullptr);
  if (env->ExceptionCheck() != JNI_FALSE) {
    env->ExceptionClear();
    return std::unexpected(Error::kCleanup);
  }
  return result;
}
/// Public method handles remain valid while their classes are retained in this frame.
struct Methods {
  jmethodID root;
  jmethodID parent;
  jmethodID name;
};
/// Resolves only the supplied Application's getter and java.lang public metadata methods.
Result<Methods> methods(Probe& probe, jobject application) {
  if (!probe.next()) {
    return std::unexpected(probe.error());
  }
  jclass application_class = probe.env()->GetObjectClass(application);
  if (!probe.next() || application_class == nullptr) {
    return std::unexpected(probe.error());
  }
  jmethodID root = probe.env()->GetMethodID(application_class, "getClassLoader", "()Ljava/lang/ClassLoader;");
  if (!probe.next() || root == nullptr) {
    return std::unexpected(probe.error());
  }
  jclass loader_class = probe.env()->FindClass("java/lang/ClassLoader");
  if (!probe.next() || loader_class == nullptr) {
    return std::unexpected(probe.error());
  }
  jmethodID parent = probe.env()->GetMethodID(loader_class, "getParent", "()Ljava/lang/ClassLoader;");
  if (!probe.next() || parent == nullptr) {
    return std::unexpected(probe.error());
  }
  jclass class_class = probe.env()->FindClass("java/lang/Class");
  if (!probe.next() || class_class == nullptr) {
    return std::unexpected(probe.error());
  }
  jmethodID name = probe.env()->GetMethodID(class_class, "getName", "()Ljava/lang/String;");
  if (!probe.next() || name == nullptr) {
    return std::unexpected(probe.error());
  }
  return Methods{.root = root, .parent = parent, .name = name};
}
/// Validates UTF16 and reduces class metadata to fixed labels without retaining names.
Result<std::string_view> class_label(std::span<const jchar> characters) {
  std::string ascii;
  bool non_ascii = false;
  for (std::size_t index = 0; index < characters.size(); ++index) {
    const auto unit = characters[index];
    if (unit >= 0xd800 && unit <= 0xdbff) {
      if (index + 1 == characters.size() || characters[index + 1] < 0xdc00 || characters[index + 1] > 0xdfff) {
        return std::unexpected(Error::kMalformed);
      }
      ++index;
      non_ascii = true;
    } else if ((unit >= 0xdc00 && unit <= 0xdfff) || unit < 32 || unit == 127) {
      return std::unexpected(Error::kMalformed);
    } else if (unit > 127) {
      non_ascii = true;
    } else {
      ascii.push_back(static_cast<char>(unit));
    }
  }
  if (non_ascii) {
    return "custom";
  }
  constexpr std::array<std::pair<std::string_view, std::string_view>, 6> kKinds{
      {
          {"dalvik.system.PathClassLoader", "path"},
          {"dalvik.system.DexClassLoader", "dex"},
          {"dalvik.system.InMemoryDexClassLoader", "inmemory"},
          {"dalvik.system.DelegateLastClassLoader", "delegate_last"},
          {"co.ostorlab.rasp.GeneratingClassLoader", "runtime_named"},
          {"java.lang.BootClassLoader", "boot_named"},
      },
  };
  for (const auto& item : kKinds) {
    if (ascii == item.first) {
      return item.second;
    }
  }
  return "custom";
}
/// Copies a bounded concrete class name through public Object/Class methods only.
Result<std::string_view> kind(Probe& probe, jobject loader, jmethodID get_name) {
  if (!probe.next()) {
    return std::unexpected(probe.error());
  }
  jclass type = probe.env()->GetObjectClass(loader);
  if (!probe.next() || type == nullptr) {
    return std::unexpected(probe.error());
  }
  const auto object = probe.call(type, get_name);
  if (!object || *object == nullptr) {
    return std::unexpected(object ? Error::kJni : object.error());
  }
  auto* name = rasp_provenance_string(*object);
  const auto length = probe.env()->GetStringLength(name);
  if (!probe.next()) {
    return std::unexpected(probe.error());
  }
  if (length < 1 || length > 256) {
    return std::unexpected(Error::kInputLimit);
  }
  std::array<jchar, 256> characters{};
  probe.env()->GetStringRegion(name, 0, length, characters.data());
  if (!probe.next()) {
    return std::unexpected(probe.error());
  }
  const auto label = class_label(std::span(characters).first(static_cast<std::size_t>(length)));
  probe.env()->DeleteLocalRef(name);
  probe.env()->DeleteLocalRef(type);
  return label;
}
/// Rejects repeated loader identities using public VM identity comparisons, not pointer equality.
Result<void> new_node(Probe& probe, jobject current, std::span<const jobject> nodes) {
  for (auto* node : nodes) {
    if (!probe.next()) {
      return std::unexpected(probe.error());
    }
    const bool same = probe.env()->IsSameObject(node, current) != JNI_FALSE;
    if (!probe.next()) {
      return std::unexpected(probe.error());
    }
    if (same) {
      return std::unexpected(Error::kRace);
    }
  }
  return {};
}
/// Repeats every root and parent edge against owned first-pass local references.
Result<void> verify_chain(Probe& probe, jobject application, const Methods& entry, std::span<const jobject> nodes) {
  auto current = probe.call(application, entry.root);
  if (!current) {
    return std::unexpected(current.error());
  }
  for (auto* node : nodes) {
    if (!probe.next()) {
      return std::unexpected(probe.error());
    }
    const bool same = probe.env()->IsSameObject(node, *current) != JNI_FALSE;
    if (!probe.next()) {
      return std::unexpected(probe.error());
    }
    if (!same) {
      return std::unexpected(Error::kRace);
    }
    const auto parent = probe.call(*current, entry.parent);
    if (!parent) {
      return std::unexpected(parent.error());
    }
    probe.env()->DeleteLocalRef(*current);
    current = parent;
  }
  if (*current != nullptr) {
    return std::unexpected(Error::kRace);
  }
  if (!probe.next()) {
    return std::unexpected(probe.error());
  }
  return {};
}
/// Retains at most16 first-pass nodes and checks the complete chain again without resolution.
Result<std::vector<std::string>> chain(Probe& probe, jobject application) {
  const auto entry = methods(probe, application);
  if (!entry) {
    return std::unexpected(entry.error());
  }
  auto current = probe.call(application, entry->root);
  if (!current || *current == nullptr) {
    return std::unexpected(current ? Error::kNativeUnavailable : current.error());
  }
  std::vector<jobject> nodes;
  std::vector<std::string> rows;
  while (*current != nullptr) {
    if (nodes.size() == 16) {
      return std::unexpected(Error::kInputLimit);
    }
    const auto unique = new_node(probe, *current, nodes);
    if (!unique) {
      return std::unexpected(unique.error());
    }
    const auto label = kind(probe, *current, entry->name);
    if (!label) {
      return std::unexpected(label.error());
    }
    const auto parent = probe.call(*current, entry->parent);
    if (!parent) {
      return std::unexpected(parent.error());
    }
    const auto index = nodes.size();
    nodes.push_back(*current);
    rows.push_back("v=1;depth=" + std::to_string(index) + ";kind=" + std::string(*label) +
                   ";parent=" + (*parent == nullptr ? "null" : std::to_string(index + 1)));
    current = parent;
  }
  const auto stable = verify_chain(probe, application, *entry, nodes);
  if (!stable) {
    return std::unexpected(stable.error());
  }
  return rows;
}
/// Copies at most4096 modified-UTF8 bytes from a public path string without retaining Java memory.
Result<std::string> path_string(Probe& probe, jstring value) {
  if (value == nullptr) {
    return std::unexpected(Error::kJni);
  }
  if (!probe.next()) {
    return std::unexpected(probe.error());
  }
  const auto length = probe.env()->GetStringLength(value);
  if (!probe.next()) {
    return std::unexpected(probe.error());
  }
  if (length < 1 || length > 4096) {
    return std::unexpected(Error::kInputLimit);
  }
  const auto bytes = probe.env()->GetStringUTFLength(value);
  if (!probe.next()) {
    return std::unexpected(probe.error());
  }
  if (bytes < 1 || bytes > 4096) {
    return std::unexpected(Error::kInputLimit);
  }
  std::vector<char> copy(static_cast<std::size_t>(bytes) + 1);
  probe.env()->GetStringUTFRegion(value, 0, length, copy.data());
  if (!probe.next()) {
    return std::unexpected(probe.error());
  }
  std::string result(copy.data(), static_cast<std::size_t>(bytes));
  if (!provenance::location_path(result)) {
    return std::unexpected(Error::kMalformed);
  }
  return result;
}
/// Reads one public string field, checking resolution and value errors independently.
Result<std::string> path_field(Probe& probe, jobject info, jclass type, const char* name) {
  if (!probe.next()) {
    return std::unexpected(probe.error());
  }
  auto* const field = probe.env()->GetFieldID(type, name, "Ljava/lang/String;");
  if (!probe.next() || field == nullptr) {
    return std::unexpected(probe.error());
  }
  auto* value = rasp_provenance_string(probe.env()->GetObjectField(info, field));
  if (!probe.next()) {
    return std::unexpected(probe.error());
  }
  auto result = path_string(probe, value);
  probe.env()->DeleteLocalRef(value);
  return result;
}
/// Reads at most64 public split paths, retaining no partial metadata on failure.
Result<void> append_splits(Probe& probe, jobjectArray splits, provenance::Locations& result) {
  if (splits == nullptr) {
    return {};
  }
  const auto count = probe.env()->GetArrayLength(splits);
  if (!probe.next()) {
    return std::unexpected(probe.error());
  }
  if (count < 0 || count > 64) {
    return std::unexpected(Error::kInputLimit);
  }
  std::size_t total = result.apk_paths[0].size() + result.native_directory.size();
  for (jsize index = 0; index < count; ++index) {
    auto* value = rasp_provenance_string(probe.env()->GetObjectArrayElement(splits, index));
    if (!probe.next()) {
      return std::unexpected(probe.error());
    }
    auto path = path_string(probe, value);
    probe.env()->DeleteLocalRef(value);
    if (!path) {
      return std::unexpected(path.error());
    }
    if (path->size() > 262144 - total) {
      return std::unexpected(Error::kInputLimit);
    }
    total += path->size();
    result.apk_paths.push_back(std::move(*path));
  }
  return {};
}
/// Resolves the supplied Context's public ApplicationInfo getter without private runtime state.
Result<jobject> application_info(Probe& probe, jobject application) {
  if (!probe.next()) {
    return std::unexpected(probe.error());
  }
  jclass application_class = probe.env()->GetObjectClass(application);
  if (!probe.next() || application_class == nullptr) {
    return std::unexpected(probe.error());
  }
  auto* const getter =
      probe.env()->GetMethodID(application_class, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;");
  if (!probe.next() || getter == nullptr) {
    return std::unexpected(probe.error());
  }
  return probe.call(application, getter);
}
/// Reads only public ApplicationInfo fields, with complete-source lexical validation.
Result<provenance::Locations> locations(Probe& probe, jobject application) {
  const auto info = application_info(probe, application);
  if (!info || *info == nullptr) {
    return std::unexpected(info ? Error::kJni : info.error());
  }
  jclass type = probe.env()->GetObjectClass(*info);
  if (!probe.next() || type == nullptr) {
    return std::unexpected(probe.error());
  }
  auto source = path_field(probe, *info, type, "sourceDir");
  if (!source) {
    return std::unexpected(source.error());
  }
  auto native = path_field(probe, *info, type, "nativeLibraryDir");
  if (!native) {
    return std::unexpected(native.error());
  }
  auto* const field = probe.env()->GetFieldID(type, "splitSourceDirs", "[Ljava/lang/String;");
  if (!probe.next() || field == nullptr) {
    return std::unexpected(probe.error());
  }
  auto* splits = rasp_provenance_array(probe.env()->GetObjectField(*info, field));
  if (!probe.next()) {
    return std::unexpected(probe.error());
  }
  provenance::Locations result{
      .apk_paths = {std::move(*source)},
      .native_directory = std::move(*native),
      .bundle_directory = {},
      .available = true,
  };
  const auto appended = append_splits(probe, splits, result);
  if (!appended) {
    return std::unexpected(appended.error());
  }
  if (!probe.next()) {
    return std::unexpected(probe.error());
  }
  return result;
}
}  // namespace

provenance::Pair read_loader_provenance(JNIEnv* env, jobject application, provenance::Clock clock) {
  auto rows = framed(env, application, clock, chain);
  const provenance::Metadata metadata{
      .seen = rows ? rows->size() : 0,
      .eligible = rows ? rows->size() : 0,
      .stability = rows ? "bracket_equal" : "na",
  };
  return provenance::pair("hook.loader_chain", "application_classloader_v1", std::move(rows), metadata);
}
provenance::Result<provenance::Locations> read_provenance_locations(JNIEnv* env, jobject application,
                                                                    provenance::Clock clock) {
  return framed(env, application, clock, locations);
}
provenance::Locations application_provenance_locations() {
  auto* env = util::attached_env();
  if (env == nullptr) {
    return {};
  }
  if (env->ExceptionCheck() != JNI_FALSE) {
    return {};
  }
  const auto application = util::application_context(env);
  if (!application || *application == nullptr) {
    return {};
  }
  auto result = read_provenance_locations(env, *application);
  env->DeleteLocalRef(*application);
  return result ? std::move(*result) : provenance::Locations{};
}
provenance::Pair loader_provenance() {
  auto* env = util::attached_env();
  if (env == nullptr) {
    return read_loader_provenance(nullptr, nullptr);
  }
  if (env->ExceptionCheck() != JNI_FALSE) {
    return provenance::pair("hook.loader_chain", "application_classloader_v1", std::unexpected(Error::kJni));
  }
  const auto application = util::application_context(env);
  if (!application) {
    return provenance::pair("hook.loader_chain", "application_classloader_v1", std::unexpected(Error::kJni));
  }
  const auto result = read_loader_provenance(env, *application);
  env->DeleteLocalRef(*application);
  return result;
}
}  // namespace rasp::android::checks
