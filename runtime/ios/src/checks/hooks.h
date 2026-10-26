/// The iOS hooking checks: whether an instrumentation or hooking framework has loaded its code into the app's process.

#pragma once

#include <span>
#include <string>
#include <vector>

#include "rasp/observation.h"

namespace rasp::ios::checks {

/// Runs the hooking checks and returns what they observed.
///
/// It reads the list of images loaded in the process and reports the ones that look like a known instrumentation or
/// hooking framework (Frida, Cycript, Substrate and the tweak loaders that replace it, SSL Kill Switch and the like).
/// The check reports the raw paths; the server decides.
///
/// On a physical iOS device it runs the probe. Anywhere else, on a simulator, a Mac or a Linux host, the observation is
/// unsupported instead, so the result still shows that the check ran.
///
/// @return One observation: hook.maps_hits read through dyld.
[[nodiscard]] std::vector<Observation> hooks();

/// Reports the paths of `image_paths` that name a known instrumentation or hooking framework.
///
/// A path names a framework when its file name, the last component of the path, contains a known marker, such as
/// `frida-gadget`, `fridagadget`, `mobilesubstrate`, `libhooker` or `libellekit`. The folders above the file, such as
/// the name of the app's bundle, are not matched against the markers, so an app named after a marker, or a framework
/// such as `SubstrateSdk`, is not reported.
///
/// A path also names a framework when it is in a folder that only holds tweaks or a tweak loader, such as
/// `/Library/MobileSubstrate/DynamicLibraries/`, `/usr/lib/TweakInject/` or `/usr/lib/ellekit/`, whatever its file
/// name. The folder is matched at the start of the path, or right after the root of a rootless jailbreak: `/var/jb`,
/// `/private/var/jb`, or the real folder `/var/jb` links to, which dyld reports as a path under `/private/preboot/`
/// that goes through a `procursus` folder. Markers and folders are both matched without regard to case.
///
/// The list holds at most the first 32 matching paths, in the order of `image_paths`. An empty list is a real answer,
/// not a failure.
///
/// @param image_paths The paths of the images to look at, such as the images loaded in the process.
/// @return One hook.maps_hits observation read through dyld, with the matching paths.
[[nodiscard]] Observation observe_images(std::span<const std::string> image_paths);

/// Reports the images loaded in the process that name a known instrumentation or hooking framework.
///
/// The probe walks dyld's list of loaded images with _dyld_image_count and _dyld_get_image_name, and passes their paths
/// to observe_images. The list is read again on every call, so it also sees a framework loaded after the app started.
/// Another thread can load or unload an image during the walk: an image unloaded during the walk has no name, and is
/// skipped, and an image loaded during the walk may be missed until the next call. On a system without dyld, such as
/// Linux, there is nothing to read.
///
/// @return One hook.maps_hits observation read through dyld, as observe_images reports it. It has an error status when
/// the process has more than 4096 images, and the unsupported status on a system without dyld.
[[nodiscard]] Observation observe_loaded_images();

}  // namespace rasp::ios::checks
