/// detect: judges the observations of the built-in checks, with one verdict per signal, and returns what they detected.

#pragma once

#include <span>
#include <string>
#include <vector>

#include "rasp/observation.h"

namespace rasp {

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

}  // namespace rasp
