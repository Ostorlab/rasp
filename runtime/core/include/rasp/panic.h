/// panic_on_detection: ends the app after a bounded delay when a built-in check detects something, and the verdicts
/// it decides with.

#pragma once

#include <chrono>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "rasp/config.h"
#include "rasp/observation.h"

namespace rasp {

/// The platform whose check order defines the report-only mask.
enum class CheckPlatform : std::uint8_t {
  /// The Android monitoring order.
  kAndroid,
  /// The iOS monitoring order.
  kIos,
};

/// One positive finding of the built-in checks.
struct Detection {
  /// The signal that detected something, such as dbg.tracer_pid.
  std::string signal;
  /// The source that detected it, such as proc_status. When two sources of the signal disagree, it names both, as
  /// `<first>!=<second>`, such as `access!=stat`.
  std::string source;

  /// Compares two detections field by field.
  ///
  /// @param left The first detection.
  /// @param right The second detection.
  /// @return `true` when both have the same signal and source.
  [[nodiscard]] friend bool operator==(const Detection& left, const Detection& right) = default;
};

/// The function that ends the process. In the runtime it is the platform's direct system call, which never returns.
using EndProcess = void (*)() noexcept;

/// The shortest time between arming a panic and the end of the process for a severe detection: one that shows an
/// active attack on the running process, such as a debugger or a hooking framework. The window is short because the
/// one who triggered it already knows what they did; the delay only keeps the end from saying which check fired.
inline constexpr std::chrono::milliseconds kMinSeverePanicDelay{100};
/// The longest time between arming a panic and the end of the process for a severe detection.
inline constexpr std::chrono::milliseconds kMaxSeverePanicDelay{500};
/// The shortest time between arming a panic and the end of the process for every other detection.
inline constexpr std::chrono::milliseconds kMinPanicDelay{1000};
/// The longest time between arming a panic and the end of the process for every other detection.
inline constexpr std::chrono::milliseconds kMaxPanicDelay{3000};

/// Judges the observations of the built-in checks, and returns what they detected.
///
/// Only an observation with the `kOk` status counts: an unsupported, failed or timed-out one never detects anything.
/// Each signal has its own verdict, such as dbg.tracer_pid above 0, a non-empty root.fs_paths or jb.fork_ok true. An
/// informational signal, such as id.package, and a signal the verdicts don't know never detect anything by their
/// value. Separately, every source of one signal must report the same value: two `kOk` observations of one signal that
/// disagree are a detection too, reported once per signal.
///
/// @param observations The observations of the built-in checks. A plugin's observations must not be passed.
/// @return One detection per observation whose value is a positive finding, in the order of `observations`, then one
/// per signal whose sources disagree. Empty when nothing was detected.
[[nodiscard]] std::vector<Detection> detect(std::span<const Observation> observations);

/// Picks how long an armed panic waits before it ends the process.
///
/// @return A random delay, from kMinPanicDelay to kMaxPanicDelay.
[[nodiscard]] std::chrono::milliseconds panic_delay() noexcept;

/// Picks how long an armed panic waits before it ends the process after a severe detection: one that shows an active
/// attack on the running process, such as a debugger or a hooking framework.
///
/// @return A random delay, from kMinSeverePanicDelay to kMaxSeverePanicDelay.
[[nodiscard]] std::chrono::milliseconds severe_panic_delay() noexcept;

/// Arms a panic: starts a detached thread that waits `delay`, then calls `end_process`.
///
/// It returns at once: the process ends later, on that thread, not in the caller.
///
/// @param end_process The function that ends the process.
/// @param delay How long the thread waits before it calls `end_process`.
/// @return Whether the thread started. When it can't start, nothing is armed.
[[nodiscard]] bool arm_panic(EndProcess end_process, std::chrono::milliseconds delay) noexcept;

/// The runtime response to a detection: only enabled blocking groups arm the delayed process end.
///
/// It judges `observations` as detect does. In a release build, when a blocking group detected something, it arms a
/// panic with arm_panic and returns. A dbg., hook. or virt. detection uses severe_panic_delay (100–500 ms); other
/// detections use panic_delay (1–3 s). Disabled groups arm nothing, including at startup and loader checkpoints.
/// Only blocking detections choose the delay. Unknown groups and unreadable enabled-check configs block. The process
/// ends on the panic's own thread. A development build never ends the process: it logs `would panic: <signal>/<source>`
/// for blocking detections, `report only: <signal>/<source>` for report-only ones and `check off: <signal>/<source>`
/// for disabled ones instead, and arms nothing.
///
/// @param observations The observations of the built-in checks. A plugin's observations must not be passed.
/// @param end_process The function that ends the process.
/// @param config The runtime config, whose report-only mask selects the groups that never arm a panic.
/// @param platform The platform whose check order defines that mask.
/// @return Whether a panic was armed. Always `false` in a development build.
[[nodiscard]] bool panic_on_detection(std::span<const Observation> observations, EndProcess end_process,
                                      const Config& config, CheckPlatform platform) noexcept;

}  // namespace rasp
