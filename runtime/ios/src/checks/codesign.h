/// The iOS code-signing status check: it reads the kernel's live code-signing flags for the app through the csops
/// system call and reports whether the signature is still valid, whether a debugger is attached, whether the build
/// allows another process to inspect its task, and whether library validation is enforced.

#pragma once

#include <cstdint>
#include <vector>

#include "rasp/observation.h"

namespace rasp::ios::checks {

/// Runs the code-signing status check and returns what it observed.
///
/// On a physical iOS device it reads the flags once through csops and reports one observation per flag. Anywhere else,
/// on a simulator, a Mac or a Linux host, every observation is unsupported instead, so the result still shows that the
/// check ran.
///
/// @return One observation per signal, all read through csops, in this order: cs.valid, cs.debugged,
/// cs.get_task_allow, cs.library_validation.
[[nodiscard]] std::vector<Observation> codesign();

/// Turns a set of code-signing status flags into one observation per signal.
///
/// The flags are the kernel's `CS_*` status bits for the app, as csops returns them. The check reports each as a
/// boolean and does not judge it; a server decides what a combination means. `cs.valid` is the `CS_VALID` bit (the
/// signature is still valid, and the kernel clears it when the code is changed at runtime), `cs.debugged` the
/// `CS_DEBUGGED` bit (a debugger is or was attached), `cs.get_task_allow` the `CS_GET_TASK_ALLOW` bit (the build lets
/// another process inspect its task, as a development or re-signed build does), and `cs.library_validation` the
/// `CS_REQUIRE_LV` bit (the app only loads libraries signed by its own team, so a cleared bit means an unsigned or
/// foreign library can be injected). It is exposed so a test can check the mapping without a device.
///
/// @param flags The app's code-signing status flags, as csops returns them.
/// @return One observation per signal, all through csops, each with its boolean value.
[[nodiscard]] std::vector<Observation> observe_codesign(std::uint32_t flags);

}  // namespace rasp::ios::checks
