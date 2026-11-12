/// detect: the verdict for every signal of the built-in checks, and the comparison of the sources of one signal.

#include "rasp/panic.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "rasp/observation.h"

namespace rasp {

namespace {

/// Never a finding: the signal is informational, and the server compares its value.
[[nodiscard]] bool informational(const Value& /*value*/) { return false; }

/// A finding when the value is the boolean `true`.
[[nodiscard]] bool is_true(const Value& value) {
  const bool* const flag = std::get_if<bool>(&value);
  return flag != nullptr && *flag;
}

/// A finding when the value is the boolean `false`.
[[nodiscard]] bool is_false(const Value& value) {
  const bool* const flag = std::get_if<bool>(&value);
  return flag != nullptr && !*flag;
}

/// A finding when the value is an integer above 0.
[[nodiscard]] bool is_positive(const Value& value) {
  const std::int64_t* const number = std::get_if<std::int64_t>(&value);
  return number != nullptr && *number > 0;
}

/// A finding when the value is an integer other than 1, the process id of launchd, which starts every iOS app.
[[nodiscard]] bool is_not_launchd(const Value& value) {
  const std::int64_t* const number = std::get_if<std::int64_t>(&value);
  return number != nullptr && *number != 1;
}

/// A finding when the value is a non-empty string.
[[nodiscard]] bool is_non_empty_text(const Value& value) {
  const std::string* const text = std::get_if<std::string>(&value);
  return text != nullptr && !text->empty();
}

/// A finding when the value is a non-empty list.
[[nodiscard]] bool is_non_empty_list(const Value& value) {
  const std::vector<std::string>* const items = std::get_if<std::vector<std::string>>(&value);
  return items != nullptr && !items->empty();
}

/// Whether the mount table line `line` is the read-write rootfs at `/` that a device without system-as-root mounts.
[[nodiscard]] bool is_legacy_rootfs(std::string_view line) { return line.starts_with("rootfs / rootfs "); }

/// A finding when the list of writable system mounts holds a line other than the legacy read-write rootfs at `/`.
[[nodiscard]] bool has_writable_system_mount(const Value& value) {
  const std::vector<std::string>* const lines = std::get_if<std::vector<std::string>>(&value);
  return lines != nullptr &&
         std::ranges::any_of(*lines, [](const std::string& line) { return !is_legacy_rootfs(line); });
}

/// The build properties, as `name=value`, that tell a debuggable build, a test-signed build or an unlocked bootloader.
constexpr auto kUnsafeBuildProperties = std::to_array<std::string_view>({
    "ro.debuggable=1",
    "ro.secure=0",
    "ro.build.type=eng",
    "ro.build.type=userdebug",
    "ro.boot.verifiedbootstate=orange",
    "ro.boot.verifiedbootstate=red",
    "ro.boot.vbmeta.device_state=unlocked",
    "ro.boot.flash.locked=0",
});

/// The start of the build tags property, as `name=value`.
constexpr std::string_view kBuildTagsPrefix = "ro.build.tags=";
/// The build tag of a build signed with the platform's public test keys.
constexpr std::string_view kTestKeysTag = "test-keys";

/// Whether the build property `property`, as `name=value`, tells a debuggable build, a test-signed build or an
/// unlocked bootloader.
[[nodiscard]] bool is_unsafe_build_property(std::string_view property) {
  if (property.starts_with(kBuildTagsPrefix)) {
    return property.substr(kBuildTagsPrefix.size()).contains(kTestKeysTag);
  }
  return std::ranges::contains(kUnsafeBuildProperties, property);
}

/// A finding when a reported build property tells a debuggable build, a test-signed build or an unlocked bootloader.
[[nodiscard]] bool has_unsafe_build_property(const Value& value) {
  const std::vector<std::string>* const properties = std::get_if<std::vector<std::string>>(&value);
  return properties != nullptr && std::ranges::any_of(*properties, [](const std::string& property) {
           return is_unsafe_build_property(property);
         });
}

/// The verdict for one signal of the built-in checks.
struct Verdict {
  /// The signal, such as dbg.tracer_pid.
  std::string_view signal;
  /// Whether a `kOk` value of the signal is a positive finding.
  bool (*detected)(const Value& value);
};

/// The verdict for every signal the built-in checks of both platforms report.
constexpr auto kVerdicts = std::to_array<Verdict>({
    {.signal = "dbg.tracer_pid", .detected = is_positive},
    {.signal = "dbg.traced", .detected = is_true},
    {.signal = "dbg.parent", .detected = is_not_launchd},
    {.signal = "dbg.exception_ports", .detected = informational},
    {.signal = "dbg.java_debugger", .detected = is_true},
    {.signal = "emu.props", .detected = is_non_empty_list},
    {.signal = "emu.simulator", .detected = is_true},
    {.signal = "hook.maps_hits", .detected = is_non_empty_list},
    {.signal = "hook.rwx_regions", .detected = is_non_empty_list},
    {.signal = "hook.threads", .detected = is_non_empty_list},
    {.signal = "hook.dyld_env", .detected = is_non_empty_text},
    {.signal = "hook.frida_port", .detected = is_true},
    {.signal = "hook.inline", .detected = is_non_empty_list},
    {.signal = "id.package", .detected = informational},
    {.signal = "id.uid", .detected = informational},
    {.signal = "id.code_path", .detected = informational},
    {.signal = "id.bundle_id", .detected = informational},
    {.signal = "id.team_id", .detected = informational},
    {.signal = "id.cdhash", .detected = informational},
    {.signal = "id.debuggable", .detected = is_true},
    {.signal = "integ.text_sha256", .detected = informational},
    {.signal = "jb.fs_paths", .detected = is_non_empty_list},
    {.signal = "jb.sandbox_escape", .detected = is_true},
    {.signal = "jb.fork_ok", .detected = is_true},
    {.signal = "mitm.tunnels", .detected = is_non_empty_list},
    {.signal = "mitm.proxies", .detected = is_non_empty_list},
    {.signal = "mitm.user_cas", .detected = is_non_empty_list},
    {.signal = "root.fs_paths", .detected = is_non_empty_list},
    {.signal = "root.mounts", .detected = is_non_empty_list},
    {.signal = "root.rw_mounts", .detected = has_writable_system_mount},
    {.signal = "root.selinux_enforcing", .detected = is_false},
    {.signal = "root.build_props", .detected = has_unsafe_build_property},
    {.signal = "virt.exec_path", .detected = is_true},
    {.signal = "virt.foreign_images", .detected = is_non_empty_list},
});

/// Whether the `kOk` observation `observation` is a positive finding by its signal's verdict.
[[nodiscard]] bool detected_by_value(const Observation& observation) {
  const auto* const verdict = std::ranges::find(kVerdicts, std::string_view(observation.signal), &Verdict::signal);
  return verdict != kVerdicts.end() && verdict->detected(observation.value);
}

/// The disagreement of the signal of the observation at `index` when that observation is its signal's first `kOk`
/// one: the first later `kOk` observation of the signal whose value differs. Nothing when it isn't the first, or when
/// every later one agrees.
[[nodiscard]] std::optional<Detection> disagreement(std::span<const Observation> observations, std::size_t index) {
  const Observation& first = observations[index];
  const auto same_signal = [&first](const Observation& other) {
    return other.status == Status::kOk && other.signal == first.signal;
  };
  if (first.status != Status::kOk || std::ranges::any_of(observations.first(index), same_signal)) {
    return std::nullopt;
  }
  const std::span<const Observation> later = observations.subspan(index + 1);
  const auto other = std::ranges::find_if(
      later, [&](const Observation& candidate) { return same_signal(candidate) && candidate.value != first.value; });
  if (other == later.end()) {
    return std::nullopt;
  }
  return Detection{.signal = first.signal, .source = first.source + "!=" + other->source};
}

}  // namespace

std::vector<Detection> detect(std::span<const Observation> observations) {
  std::vector<Detection> detections;
  for (const Observation& observation : observations) {
    if (observation.status == Status::kOk && detected_by_value(observation)) {
      detections.push_back(Detection{.signal = observation.signal, .source = observation.source});
    }
  }
  for (std::size_t index = 0; index < observations.size(); ++index) {
    if (std::optional<Detection> found = disagreement(observations, index)) {
      detections.push_back(std::move(*found));
    }
  }
  return detections;
}

}  // namespace rasp
