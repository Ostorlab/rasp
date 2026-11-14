# Security audit findings

Twenty findings identify exposed key material, recognizable artifacts and gaps in the runtime bindings. W1 remains
open: a static analyst can recover the material needed to decrypt the library without executing it.

Historical findings from inspecting the built artifacts of the `feature/android-fold-program` branch: the packed
Alkahf APK, its shipped `librasp.so`, the stub dex, and the packer and runtime sources. Each finding preserves the
reported evidence and remediation from that audit and its later rounds. “Fixed” and “Verified” in those accounts
refer to the audited builds; they are not verification of the source revision carrying this document.

**Status at the PR #324 baseline (`6e06a415`)**: the runtime reads the W3 check mask, but the packer still writes the
check-name list, so W3 is only partially integrated. W2 still uses `.rasp_config`; W5 still preserves the debug
attribute; the W6/W7 and W16–W20 package, naming, split, process, manifest and signer fixes described below are not
present at this revision. W11 still folds only `no_tracer` and `text_intact` and remains open. Historical completion
labels below identify fixes recorded on other branches, not protections delivered by this documentation PR.

**The fold** derives a key through chains of artifact and environment bindings; decryption succeeds when the
runtime reproduces the inputs the packer used. Findings are numbered chronologically and grouped below by surface.

| Finding | Scope | Status at the PR #324 baseline |
|---|---|---|
| W1 | Plaintext self-encryption material | Open |
| W2 | Config section marker | Open; historical fix recorded |
| W3 | Check names in config | Partial: runtime mask reader only |
| W4 | Bootstrap entry signpost | Open (accepted) |
| W5 | Debuggable manifest | Open; historical fix recorded |
| W6 | App identity and content bindings | Open; historical package-only fix recorded |
| W7 | Vendor markers | Open; historical surface-only fix recorded |
| W8 | Shared root across ABIs | Open (design) |
| W9 | Stub shape and method names | Open; historical reduction recorded |
| W10 | Small public prediction table | Open |
| W11 | Two-bit sensor guard | Open |
| W12 | No observation transport | Open |
| W13 | App-derivable key inputs | Open |
| W14 | Class-count size leak | Open (minor) |
| W15 | Raw release literals | Open (accepted) |
| W16 | Companion split APK | Open; historical APK-only fix recorded |
| W17 | Host process virtualization | Open; historical fix recorded |
| W18 | AAB APK-set bindings | Open; historical fix recorded |
| W19 | AAB manifest and wrapper | Open; historical fix recorded |
| W20 | Re-signing and shared-user companion | Open; historical fix recorded |

## Shipped library at rest

### W1 — The self-encrypt IKM sits in plaintext in `.data.rel` **open**

The packer stores 32 bytes of key material in the `.data.rel` section (renamed from `.packmeta`) in a recognizable
interleaved layout — `packed=1, ikm0, region_count, ikm1, meta_vaddr, ikm2, stubcode_vaddr, ikm3, stubcode_size…` —
and the algorithm is in this public repository. A static analyst extracts the IKM, computes the salt as the SHA-256
of `.text.hot`, derives the ChaCha20 key, and decrypts the whole library without executing it.

**Evidence**: `xxd` of `.data.rel` shows the words with their known interleaving; the derivation is in
`runtime/android/src/selfdecrypt/selfdecrypt.cpp` and `packer/src/rasp_packer/android/self_encrypt.py`.

**Fix**: derive the content key from the library's own content (fold-style) instead of storing the IKM, or scatter
it under material derived from the library's bytes. Changes the bootstrap's derivation and the packer's mirror.

### W2 — `.rasp_config` section name shipped **open here; historical fix below**

The packer renamed `.stubcode`, `.packmeta` and `.stubrodata` but not `.rasp_config`. **Fixed**: the section now
ships as `.init`, and the runtime reads either name (`runtime_library.py`'s `_space`, PR #190).

### W3 — Check names in the config JSON **partial here; historical fix below**

The shipped library's config read `{"build_id":"…","checks":["debugger","emulator",…]}` — a list of exactly which
detectors to bypass. **Fixed**: the config ships `{"build_id":"…","m":127}` — a mask, one bit per group in run order
(PR #190).

### W4 — `DT_INIT` points at the self-decrypt trampoline **open (accepted)**

The dynamic table's `INIT` entry names the bootstrap's entry. The trampoline's computed branch already breaks static
flow; the entry is a signpost an analyst follows. No fix proposed short of restructuring the loader, which would
move the problem.

## The APK surface

### W5 — The packer preserved `android:debuggable=true` **open here; historical fix below**

A debug build ships debuggable; the packed app accepted a Java debugger over JDWP, which `dbg.tracer_pid` (native
only) never sees.

**Historical fix** (PR #190):

- APK: set the attribute false with an in-place AXML edit.
- AAB: remove the attribute from the proto manifest with a span edit.

### W6 — Nothing bound the app identity into the fold **open here; historical partial fix below**

The fold's chain S gathered only the runtime's own artifacts; a repackaged APK with patched clear code or a
different package name still decrypted. **Partially fixed**: the fold now binds the package name (the `kPackage`
record, read from the APK's install path). The clear dexes and the manifest's *content* are still not folded — an
attacker can patch the app's third-party classes and resources and the runtime still decrypts, because the runtime
has no inflater to read compressed entries.

**Remaining**: fold a digest of the app's clear dexes and manifest. Needs a stored-entry (uncompressed) path or an
inflater in the runtime; larger than a quick win.

### W7 — Fixed vendor markers in the shipped APK **open here; historical partial fix below**

`appComponentFactory="co.ostorlab.rasp.RaspStub"` in the manifest, `assets/rasp/*` entry names, `assets/business/`
prefix, `co/ostorlab/rasp/*` classes in the stub dex. Any packed app was fingerprinted as Ostorlab-protected in
seconds with `aapt` and `strings` alone — and the vendor's source is public, so the fingerprint also hands over the
full design.

**Historical surface fix**:

- Manifest factory class: draw a per-app name.
- Stub dex classes: draw per-app names and retain the table's sorted order.
- `loadLibrary` argument: use the per-app library name.
- Library entry filename: draw a per-app name.
- Stub source filename: strip it at the stub build.

The runtime binds the natives on the class the config carries (`"s"` in the runtime config), so nothing in the
library names the class; the APK digest's own-library exclusion follows the library's per-app name on both sides.
A seeded generator makes a pack's names reproducible.

**Still open in the historical fix**: the `assets/rasp/` and `assets/business/` entry names stay fixed. Renaming them
means plumbing the names through the fold's entry-key derivation. The stub's `install/program/arm` method names
also remain a heuristic tell.

### W8 — The same root key on every ABI **open (design)**

The keystore share compensates per ABI so every ABI recovers the same root: emulating the x86_64 slice is as good
as emulating the arm64 one. An app that ships both slices hands the analyst the cheaper architecture. Per-ABI
roots would need per-ABI dex assets, which multiplies the APK's encrypted entries; not proposed.

### W20 — A same-signed sharedUserId companion runs in the genuine process **open here; historical fix below**

Two same-class bypasses from the same root: the runtime never pinned the signing certificate, so an attacker
re-signs the target with a throwaway key and presents same-cert companion packages. `am instrument` runs an
attacker `Instrumentation` in the target's process (the historical instrumentation attack, labelled `fix7`);
a helper app sharing `android:sharedUserId`, added to the unbound AAB manifest, declares a component in the
target's process and runs there (the historical
shared-user companion attack, labelled `fix8`). **Historical fix**:

- **The manifest seal** (unpinned): a new record folds a digest over every attribute of the installed
  manifest's `<manifest>` and `<application>` elements — canonicalised, sorted, volatile build-stamped names
  excluded — which the packer predicts from the AAB proto and the runtime reads from the installed binary AXML.
  Adding `sharedUserId` — or any identity-changing manifest edit — changes the digest and nothing decrypts.
- **Certificate pinning** (the class closure): `rasp pack --pin-certificate <PEM/DER>` folds the developer's
  certificate digest in as a signer record; the runtime parses the installed base APK's signing block (v3, then
  v2) and hashes the signer's certificates. A re-signed install — or a same-cert companion admitted under a
  different key — derives a different key and nothing decrypts. This is the anchor every prior round lacked:
  it removes the free re-signing these historical attacks relied on, and it closes both fix7 and fix8 at once.
  It is optional because a pinned pack must be signed with the pinned key (the customer's key for sideloads,
  Play's app-signing key for store distribution).

The historical seal enumerates the bound parts of the installed app in one encrypted list, the fold program:

- The library's own bytes (text, sections, ranges).
- The config region.
- The share.
- The decoys.
- The package.
- The stub dex.
- The base dexes.
- The manifest's semantics.
- The installed APK set (or its emptiness).
- The launch-wrapper absence.
- The signer.

There is no literal "hash file" beside it because the program itself is that file: it is sealed by chain A over
the library and any edit of it breaks the fold. What the enumeration binds per part is
constrained by the store's regeneration on the AAB path — a total byte hash of every file would refuse
legitimate store processing; the record list is the maximal stable set.

Verified on the device: a clean AAB split install of the packed app runs; the sharedUserId patch alone kills
decryption (the manifest seal); a pack pinned to the debug certificate runs signed with it, and the same pack
re-signed with a different key refuses on both the AAB and the APK path (the signer record). The `am instrument`
bypass closes by the same pinning: a target re-signed with an attacker key never decrypts (the pinned pack
refuses), and a target left under the developer's key admits no attacker instrumentation package (the platform
requires the same certificate, which the attacker cannot produce).

### W19 — The AAB base manifest and config-split content are unbound → debuggable + wrap.sh **open here; historical fix below**

With the AAB base dexes and code-carrying splits bound in the historical build, two surfaces stayed unbound on
the AAB path: the base manifest (the store regenerates its bytes, so the packer cannot bind them) and the
non-dex files inside a config split. Together they gave the platform's own in-process channel: patch
the manifest to `android:debuggable="true"` + `android:extractNativeLibs="true"`, plant `wrap.sh` and
a dumper library in the ABI config split, `install-multiple`, and the launch wrapper preloads the
dumper into the app's own process while every bound input still matches
(`2026-11-10-rasp-path2-fix5-aab-manifest-wrapsh-bypass.md`). **Fixed** with two bindings:

- the **not_debuggable** environment gate: the stub passes the platform's own `ApplicationInfo.flags`
  into the recovery, and the schedule refuses to decrypt when the platform sees the app as
  debuggable — the platform opens its channels (JDWP, heap dumps, the launch wrapper) for exactly that
  view, so the gate binds the decision the platform itself acts on, not the manifest bytes.
- the **launch-wrapper extension** of the splits record: no APK in the installed set — the base
  included — may carry a `wrap.sh`; the store never ships one, so a plant flips the fact wherever it
  sits, debuggable or not.

Historical end-to-end device observations:

- The full attack uses a sorted-position debuggable patch that the platform honours: `run-as` works and wrap.sh
  preloads a marker library into the app process. The app refuses to decrypt.
- The wrapper plant alone, without debuggable, fails on the record.
- The platform ignores wrap.sh without debuggable.
- A clean AAB split install of the same pack runs.
- On the APK path with the packer's manifest untouched, `extractNativeLibs=false` makes the platform refuse a
  planted wrapper (`INSTALL_FAILED_INVALID_APK` on the 16 KB-page device). A manifest edit breaks the entry digest.

Adjacent surfaces mapped and closed by the same historical bindings: `profileable` (no code-loading mechanism),
`uses-native-library` (no autoload), shadowing the runtime library from a split (chain A binds its bytes), repointing
`appComponentFactory` at an existing class (no code injection without a new dex).

### W18 — The AAB pack skipped the APK-set bindings **open here; historical fix below**

The entry digest and the installed-APK-set record were drawn only for APK packs: the packer cannot
predict how the store splits an AAB, so `_pack_aab` folded nothing in their place — and AAB is the
format Play requires, so the mainstream distribution path sat at the pre-entry-binding protection
level. Demonstrated black-box: an AAB-packed app's framework `classes.dex` was edited to load an
injected library, the stub left intact, and the app decrypted and ran the injected code
(`2026-11-10-rasp-path2-fix4-aab-unbound.md`). **Fixed** with two records drawn exactly where the
APK pair is absent, binding what the store's split generation provably preserves:

- the dex record: a digest over the base module's class-dex names and content. The store copies
  base-module dexes uncompressed, whichever way it splits the rest, so the packer predicts this
  digest from what it wrote. A repack that edits, adds or removes any class dex derives a different
  key and nothing decrypts — verified on the device.
- the dexless-splits record: the store's config splits (ABI, density, language) never hold a class
  dex, so the packer folds that fact; a split that carries code flips it. Verified: a dex-carrying
  split installed beside a genuine AAB-packed base fails the app at startup.

Also fixed in the same pass, exposed by testing the real split install: the runtime resolved its
APK from the config split its library maps from, where no stub or assets live — a real store split
install never decrypted at all.

The historical fix makes `self_apk_path` resolve the `base.apk` beside the split. A clean device-split install of
the packed AAB runs.

The remaining unbound surface in that historical AAB fix: the base manifest and resources the store regenerates (a manifest edit alone cannot load
code once the dexes are bound), and any dynamic-feature modules, which the packer does not yet read.

### W17 — A host app runs a genuine install inside its own process **open here; historical fix below**

The schedule's bindings cover the app's *files*: the base APK's entries, the APKs installed beside it,
the package in the install path. They did not cover the *process*: any app can read another app's
installed APK, so a virtualization host loads the genuine base's classes and library from the real
install path, every file-derived input matches, and the app decrypts inside the host's process, where
the host's code reads the plaintext (demonstrated on a clean device: a host resolved
`app.alkahf.MainActivity` from the genuine base). **Fixed** with two environment facts the host cannot
arrange, folded as gates:

- `owns_package_data` — the process's uid owns the package's data directory
  (`/data/user/<user>/<package>`), as the package's own process always does. A host carries its own
  uid and the fold comes out wrong; nothing decrypts. Verified: the same host attack now recovers
  nothing, while the genuine install of the same pack runs.
- `release_build` — `ro.debuggable` is absent or 0, so the platform opens no debugging channel to any
  app. On userdebug and eng builds (which run every app debuggable — `am dumpheap`, JDWP), nothing
  decrypts either; this also closes the debuggable-emulator route at the fold level, on top of the
  bootstrap canaries that already end such processes.

Historical release-build verification found these external channels blocked:

- ptrace: `EPERM`, with dumpable=0.
- `/proc/<pid>/mem` and maps: `EPERM`.
- JDWP: no socket, with `debuggable` stripped.
- `am dumpheap`: `SecurityException: not debuggable`.
- Repackaged base: class resolution fails before code runs.

A host extracting the library into its own data directory already failed the foreign-library guard. The surviving
variant, loading from the real install, is what the two historical gates close.

### W16 — A split APK installed beside a genuine base **open here; historical partial fix below**

The entry binding covers `base.apk` only, but Android runs code from split APKs installed beside the
base (`install-multiple`): a split shares the app's process and class loader while the base stays
byte-for-byte genuine — every base-derived input matches, the app decrypts, and the split's code reads
the decrypted classes in-process (demonstrated: `2026-11-10-rasp-path2-fix3-split-apk-bypass.md`).

**Historical fix for APK packs**: the schedule folds the installed APK set — a new record beside the APK entry
digest. The runtime lists the directory holding its base and hashes every other APK's filename; the
packer folds the clean install's set (the base alone), so any split beside the base derives a different
key and nothing decrypts. Verified on the device: a split installed beside a genuine packed base fails
the app at startup with its business classes unresolved, and the same base installed alone runs.

**Open in that historical fix for AAB packs**: the store generates the splits, so the packer cannot predict them.
The record stays absent, the way the APK entry digest does.

## The stub and the Java arm

### W9 — The stub dex is a plain, unobfuscated 4 KB dex **open here; historical reduction below**

`JArm.hkdf`, `observe`, `run`, `info`, and the `install/program/arm` natives decompile in minutes — but since the
per-app rename (W7) they no longer name the vendor: the classes, the source file and the library name are random per
pack, and the debug info is stripped at the stub build. **Remaining**: the method names and the HKDF-chain shape.
**Fix**: split the info-string assembly, scramble the native method names, or move the HKDF chain's shape per app.

### W10 — The arm's prediction table is small and public **open (TODO has the deeper fix)**

`CORE_STEPS` holds 10 core hierarchies and ships 4–7 steps per program.

**Next step**: the TODO tracks the packer-side dex reader that would step over the app's *own* classes, which a fake
loader must answer from the real dex.

## The on-device guards

### W11 — The sensor guard folds only two bits **open at this revision**

`Sensors{no_tracer, text_intact}` — both bypassable without touching the runtime: Frida Gadget runs in-process with
no ptrace; Java-level hooks (LSPosed) never write `librasp`'s `.text`; JDWP is invisible to `TracerPid`. A fully
instrumented real device decrypts everything happily.

**Fix**: fold a rolling digest of the checks' existing observations (maps hits, rwx regions, emulator props, build
props, root probes) into the dex-stage key, so an instrumented device that hooks anything the checks see derives a
wrong key and every tag fails silently. The checks already run; the work is in `observe_sensors` and its mirror.

### W12 — Checks report to nobody **open (TODO: transport)**

In a release build the checks run, but their observations are not sent to the server. No transport, install id
reporting or agent protocol exists yet on Android.

**Evidence at this revision**: [the Android monitoring loop](runtime/android/src/monitoring.cpp) handles local
panic and plugin callbacks, and logs observations only when `kLoggingEnabled`; it has no reporting call. The
[“Observations aren't sent to the server” TODO](TODO.md) records the missing transport.

**Next step**: implement the report transport and its server protocol. W11's local sensor binding is separate
work and does not deliver observations to the server.

## The core ceiling

### W13 — Every key input is app-derivable **open (TODO documents it)**

Full emulation is a ceiling, not a wall. Only key material an emulator cannot reproduce — the Android Keystore, a
TEE-held secret, or a server-enrolled share with attestation — turns it into a wall. Needs an enrollment or
first-run flow, not just the packer.

### W14 — `map.bin`'s size leaks the class count **open (minor)**

The encrypted class map ships at a size proportional to the class count (~1,500 classes → ~108 KB).

**Fix**: pad the entry to mask the count.

## Build pipeline

### W15 — Raw release artifacts carry the schedule's literals **open (accepted)**

The CI canary *requires* the data-read literals readable in the built library — the string pass must never encrypt
them. The shipped form hides them (at-rest encryption); a raw slice leaking from a build artifact fingerprints the
product. Keep raw artifacts private.

---

*Historical audit of the `feature/android-fold-program` branch, 2026-11-09. The original account attributed
quick wins W2/W3/W5/W6 to PR #190;
W7's surface (per-app names for the manifest, the classes, the library and the stub's origin) delivered on
`feature/lifecycle-checks`; the remaining work was ordered by leverage: W7's asset names, W11 (sensor guard
widening reported in later audited work, absent at this revision),
W1 (IKM), W9 (stub methods), W13 (enrollment). Renaming the classes also binds them: the armed master folds the
class name the runtime resolves, so a renamed-by-analyst stub class derives a wrong key and nothing decrypts.
Later rounds on `feature/lifecycle-checks`: W16 (the split-APK set bound into the fold), W17 (the process bound to
the package that owns it, and the build to a release build).*
