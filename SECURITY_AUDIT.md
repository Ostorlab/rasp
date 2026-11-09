# Security audit findings

Found by inspecting the built artifacts of the `feature/android-fold-program` branch: the packed Alkahf APK, its
shipped `librasp.so`, the stub dex, and the packer and runtime sources. Each finding says what leaks or breaks,
the evidence, and the fix. Items marked **done** were delivered in the quick-wins pass (PR #190); items marked
**open** remain.

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

### W2 — `.rasp_config` section name shipped **done**

The packer renamed `.stubcode`, `.packmeta` and `.stubrodata` but not `.rasp_config`. **Fixed**: the section now
ships as `.init`, and the runtime reads either name (`runtime_library.py`'s `_space`, PR #190).

### W3 — Check names in the config JSON **done**

The shipped library's config read `{"build_id":"…","checks":["debugger","emulator",…]}` — a list of exactly which
detectors to bypass. **Fixed**: the config ships `{"build_id":"…","m":127}` — a mask, one bit per group in run order
(PR #190).

### W4 — `DT_INIT` points at the self-decrypt trampoline **open (accepted)**

The dynamic table's `INIT` entry names the bootstrap's entry. The trampoline's computed branch already breaks static
flow; the entry is a signpost an analyst follows. No fix proposed short of restructuring the loader, which would
move the problem.

## The APK surface

### W5 — The packer preserved `android:debuggable=true` **done**

A debug build ships debuggable; the packed app accepted a Java debugger over JDWP, which `dbg.tracer_pid` (native
only) never sees. **Fixed**: the packer sets the attribute false on the APK manifest (in-place AXML edit) and removes
it on the AAB proto manifest (span edit), for both packaging flows (PR #190).

### W6 — Nothing bound the app identity into the fold **done (package bound)**

The fold's chain S gathered only the runtime's own artifacts; a repackaged APK with patched clear code or a
different package name still decrypted. **Partially fixed**: the fold now binds the package name (the `kPackage`
record, read from the APK's install path). The clear dexes and the manifest's *content* are still not folded — an
attacker can patch the app's third-party classes and resources and the runtime still decrypts, because the runtime
has no inflater to read compressed entries.

**Remaining**: fold a digest of the app's clear dexes and manifest. Needs a stored-entry (uncompressed) path or an
inflater in the runtime; larger than a quick win.

### W7 — Fixed vendor markers in the shipped APK **open**

`appComponentFactory="co.ostorlab.rasp.RaspStub"` in the manifest, `assets/rasp/*` entry names, `assets/business/`
prefix, `co/ostorlab/rasp/*` classes in the stub dex. Any packed app is fingerprinted as Ostorlab-protected in
seconds. **Fix**: randomize the entry names per app (record them in the root-sealed map), rename the stub's classes
per app, or strip the vendor string from the component-factory class name (the packer already renames the soname).

### W8 — The same root key on every ABI **open (design)**

The keystore share compensates per ABI so every ABI recovers the same root: emulating the x86_64 slice is as good
as emulating the arm64 one. An app that ships both slices hands the analyst the cheaper architecture. Per-ABI
roots would need per-ABI dex assets, which multiplies the APK's encrypted entries; not proposed.

## The stub and the Java arm

### W9 — The stub dex is a plain, unobfuscated 4 KB dex **open**

`JArm.hkdf`, `observe`, `run`, `info`, and the `install/program/arm` natives decompile in minutes and name the
vendor. **Fix**: per-app renamed classes, split the info-string assembly, scramble the native method names, or
move the HKDF chain's shape per app.

### W10 — The arm's prediction table is small and public **open (TODO has the deeper fix)**

`CORE_STEPS` holds 10 core hierarchies and ships 4–7 steps per program. The TODO already tracks the packer-side dex
reader that would step over the app's *own* classes, which a fake loader must answer from the real dex.

## The on-device guards

### W11 — The sensor guard folds only two bits **open**

`Sensors{no_tracer, text_intact}` — both bypassable without touching the runtime: Frida Gadget runs in-process with
no ptrace; Java-level hooks (LSPosed) never write `librasp`'s `.text`; JDWP is invisible to `TracerPid`. A fully
instrumented real device decrypts everything happily.

**Fix**: fold a rolling digest of the checks' existing observations (maps hits, rwx regions, emulator props, build
props, root probes) into the dex-stage key, so an instrumented device that hooks anything the checks see derives a
wrong key and every tag fails silently. The checks already run; the work is in `observe_sensors` and its mirror.

### W12 — Checks report to nobody **open (TODO: transport)**

In a release build the checks run and nobody sees the result. No transport, install id reporting or agent protocol
exists yet on Android.

## The core ceiling

### W13 — Every key input is app-derivable **open (TODO documents it)**

Full emulation is a ceiling, not a wall. Only key material an emulator cannot reproduce — the Android Keystore, a
TEE-held secret, or a server-enrolled share with attestation — turns it into a wall. Needs an enrollment or
first-run flow, not just the packer.

### W14 — `map.bin`'s size leaks the class count **open (minor)**

The encrypted class map ships at a size proportional to the class count (~1,500 classes → ~108 KB). Padding the
entry would mask the count.

## Build pipeline

### W15 — Raw release artifacts carry the schedule's literals **accepted**

The CI canary *requires* the data-read literals readable in the built library — the string pass must never encrypt
them. The shipped form hides them (at-rest encryption); a raw slice leaking from a build artifact fingerprints the
product. Keep raw artifacts private.

---

*Audit of the `feature/android-fold-program` branch, 2026-11-09. Quick wins W2/W3/W5/W6 delivered in PR #190; the
rest ordered by leverage: W11 (sensor guard widening), W1 (IKM), W9 (stub), W13 (enrollment).*
