/// The Android root checks: whether root files exist, whether root tools mounted anything into the app's view or
/// remounted a system folder writable, whether SELinux enforces its policy, and what the build properties say about the
/// build and the bootloader.

#pragma once

#include <span>
#include <string_view>
#include <vector>

#include "rasp/observation.h"
#include "util/property_area.h"
#include "util/raw_file.h"
#include "util/system_property.h"

namespace rasp::android::checks {

/// Runs the root checks and returns what they observed.
///
/// On Android, the emulator included, it runs every probe. Anywhere else, such as on a Linux host, it cannot: the
/// files, mounts and properties it reads are Android ones. There every observation is unsupported instead, so the
/// server still sees that the check ran.
///
/// @return One observation per signal and source, in this order: root.fs_paths read through access, stat and faccessat,
/// root.mounts and root.rw_mounts through proc_mounts, root.selinux_enforcing through selinuxfs, root.build_props
/// through system_property and through property_area, and root.props_rewritten through property_area.
[[nodiscard]] std::vector<Observation> root();

/// Reports which of `paths` exist, read through three sources: libc's access and stat, and a direct faccessat system
/// call that no libc hook sees.
///
/// A hook that hides a root file from one source but not the others makes the lists disagree, which is itself a sign of
/// tampering. Every observation is produced even when no path exists: an empty list is a real answer, not a failure.
///
/// @param paths The paths to look for, such as the known root artifact paths.
/// @return Three root.fs_paths observations: the paths found through access, through stat, then through faccessat.
[[nodiscard]] std::vector<Observation> observe_paths(std::span<const std::string_view> paths);

/// Reports the lines of the mount table at `mounts_path` that a root tool made, and those that mount a system folder
/// writable.
///
/// Magisk, KernelSU and APatch mount their files over the system to add `su` and their modules, and those mounts show
/// in the app's mount table: Magisk's carry its name or its folders, and KernelSU and APatch name their mounts' source
/// `KSU` and `APatch`. A system folder (`/`, `/system`, `/vendor`, `/sbin`, `/etc`, and the `bin` folders of
/// `/system` and `/vendor`) is read-only on a stock device, so one mounted with the `rw` option was remounted, which
/// takes root. The line holds the filesystem type too, so the server can tell the read-write rootfs that devices
/// without system-as-root mount at `/`. The table is read once, whole, up to 1 MiB, and each list holds at most its
/// first 32 lines.
///
/// @param mounts_path The mount table to read, `/proc/self/mounts` on a device.
/// @param read The function the mount table is read with; the shipped runtime uses read_proc_file, a test passes
/// read_file to feed a regular file.
/// @return Two observations read through proc_mounts: root.mounts, the lines a root tool made, then root.rw_mounts, the
/// lines that mount a system folder writable, both without their line breaks. Both have an error status when the
/// table can't be read or is larger than 1 MiB.
[[nodiscard]] std::vector<Observation> observe_mounts(std::string_view mounts_path,
                                                      rasp::util::ProcReader read = rasp::util::read_proc_file);

/// Reports whether SELinux enforces its policy, from the file at `enforce_path`.
///
/// Older ways of rooting and some custom ROMs switch SELinux to permissive, so that root can act outside the policy.
/// Magisk, KernelSU and APatch keep it enforcing and only widen the policy for themselves, so this probe doesn't catch
/// them. The file holds `1` when SELinux enforces its policy and `0` when it is permissive, optionally followed by a
/// line break.
///
/// @param enforce_path The file to read, `/sys/fs/selinux/enforce` on a device.
/// @param read The function the enforce file is read with; the shipped runtime uses read_proc_file, a test passes
/// read_file to feed a regular file.
/// @return One root.selinux_enforcing observation read through selinuxfs: true for `1`, false for `0`, and an error
/// status when the file can't be read or holds anything else.
[[nodiscard]] Observation observe_selinux(std::string_view enforce_path,
                                          rasp::util::ProcReader read = rasp::util::read_proc_file);

/// Reports the build properties that tell a debuggable build, a test-signed build or an unlocked bootloader.
///
/// They are `ro.debuggable`, `ro.secure`, `ro.build.type`, `ro.build.tags`, `ro.boot.verifiedbootstate`,
/// `ro.boot.vbmeta.device_state` and `ro.boot.flash.locked`. A property the device doesn't set is left out.
///
/// @param read_property The function that reads each property. On a device, it reads the system properties.
/// @return One root.build_props observation read through system_property: each set property as `name=value`, in the
/// order above.
[[nodiscard]] Observation observe_build_props(util::PropertyReader read_property);

/// Reports the same build properties, read from the property files directly, so a libc hook that changes one makes the
/// two sources disagree.
///
/// @return One root.build_props observation read through property_area, with an error status when the property files'
/// index can't be read.
[[nodiscard]] Observation observe_build_props(util::PropertyAreas& areas);

/// Reports the read-only properties root tools rewrite to hide root that were written again after the platform set
/// them.
///
/// @return One root.props_rewritten observation read through property_area: the names of those properties, with an
/// error status when the property files' index can't be read.
[[nodiscard]] Observation observe_rewritten_props(util::PropertyAreas& areas);

}  // namespace rasp::android::checks
