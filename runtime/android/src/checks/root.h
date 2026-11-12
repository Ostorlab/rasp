/// The Android root checks: whether root files exist, whether root tools mounted anything into the app's view or
/// remounted a system folder writable, whether SELinux enforces its policy, and what the build properties say about the
/// build and the bootloader.

#pragma once

#include <span>
#include <string_view>
#include <vector>

#include "rasp/observation.h"
#include "util/direct_syscall.h"
#include "util/system_property.h"

namespace rasp::android::checks {

/// Runs the root checks and returns what they observed.
///
/// On Android, the emulator included, it runs every probe. Anywhere else, such as on a Linux host, it cannot: the
/// files, mounts and properties it reads are Android ones. There every observation is unsupported instead, so the
/// server still sees that the check ran.
///
/// @return One observation per signal and source, in this order: root.fs_paths read through access, through stat and
/// through faccessat_syscall, root.mounts and root.rw_mounts through proc_mounts and then through proc_mounts_syscall,
/// root.selinux_enforcing through selinuxfs, and root.build_props through system_property.
[[nodiscard]] std::vector<Observation> root();

/// Reports which of `paths` exist, read through three sources: access, stat, and the faccessat system call made
/// through libc's hookable syscall entry.
///
/// Each path is looked up three times. A hook that hides a root file from one source but not another makes the lists
/// disagree. Reads are sequential, so ordinary changes can also cause disagreement. The syscall entry can itself be
/// hooked; agreement does not attest absence of root. A complete negative lookup reports an empty list; any denial
/// or error other than ENOENT/ENOTDIR invalidates that source's whole observation, even after a positive lookup.
///
/// @param paths The paths to look for, such as the known root artifact paths.
/// @param invoke The hookable libc syscall boundary for the faccessat source.
/// @return Three root.fs_paths observations: the paths found through access, then through stat, then through
/// faccessat_syscall.
[[nodiscard]] std::vector<Observation> observe_paths(std::span<const std::string_view> paths,
                                                     util::SystemCall invoke = util::libc_syscall);

/// Reports the lines of the mount table at `mounts_path` that a root tool made, and those that mount a system folder
/// writable.
///
/// Magisk, KernelSU and APatch mount their files over the system to add `su` and their modules, and those mounts show
/// in the app's mount table: Magisk's carry its name or its folders, and KernelSU and APatch name their mounts' source
/// `KSU` and `APatch`. The writable-folder probe retains its historical selected mountpoints and raw lines;
/// writable rootfs, stock namespaces, containers and overlayfs can be benign context, so a matching line does not
/// establish root. The line holds the filesystem type too, including the read-write rootfs that devices without
/// system-as-root can mount at `/`. Each read takes the table whole, up to 1 MiB, and each list holds at most its
/// first 32 lines. The table is read twice, once through the libc file functions and once through libc's hookable
/// syscall entry. Both values are retained independently; shared kernel compromise can forge agreement.
///
/// @param mounts_path The mount table to read, `/proc/self/mounts` on a device.
/// @param invoke The hookable libc syscall boundary for the independent second read.
/// @return Four observations: root.mounts, the lines a root tool made, then root.rw_mounts, the lines that mount a
/// system folder writable, both without their line breaks, read through proc_mounts; then the same two read through
/// proc_mounts_syscall. Both observations of a source have an error status when that source can't read the table or
/// it is empty, malformed, truncated, larger than 1 MiB or holds a line longer than 8192 bytes.
[[nodiscard]] std::vector<Observation> observe_mounts(std::string_view mounts_path,
                                                      util::SystemCall invoke = util::libc_syscall);

/// Reports whether SELinux enforces its policy, from the file at `enforce_path`.
///
/// Older ways of rooting and some custom ROMs switch SELinux to permissive, so that root can act outside the policy.
/// Magisk, KernelSU and APatch keep it enforcing and only widen the policy for themselves, so this probe doesn't catch
/// them. The file holds `1` when SELinux enforces its policy and `0` when it is permissive, optionally followed by a
/// line break.
///
/// @param enforce_path The file to read, `/sys/fs/selinux/enforce` on a device.
/// @return One root.selinux_enforcing observation read through selinuxfs: true for `1`, false for `0`, and an error
/// status when the file can't be read or holds anything else.
[[nodiscard]] Observation observe_selinux(std::string_view enforce_path);

/// Reports the build properties that tell a debuggable build, a test-signed build or an unlocked bootloader.
///
/// They are `ro.debuggable`, `ro.secure`, `ro.build.type`, `ro.build.tags`, `ro.boot.verifiedbootstate`,
/// `ro.boot.vbmeta.device_state` and `ro.boot.flash.locked`. A property the device doesn't set is left out.
///
/// @param read_property The function that reads each property. On a device, it reads the system properties.
/// @return One root.build_props observation read through system_property: each set property as `name=value`, in the
/// order above.
[[nodiscard]] Observation observe_build_props(util::PropertyReader read_property);

}  // namespace rasp::android::checks
