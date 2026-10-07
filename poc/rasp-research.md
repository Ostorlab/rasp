# RASP: Solutions and Techniques for Protecting Apps

*Research snapshot, 2026-09-26. Claims marked ⚠️ could not be verified from a primary source.*

RASP (Runtime Application Self-Protection) means two different things depending on where the app runs:

- **Mobile RASP / app shielding.** The app defends itself on a device the attacker may fully control. It detects root/jailbreak, hooking, debugging, tampering and emulators, and hardens its own code with obfuscation and encryption.
- **Server-side RASP / ADR.** An agent inside the server process watches dangerous sinks (SQL, shell, filesystem, outbound HTTP, deserialization) and blocks exploits in real time.

Parts 1–3 cover mobile, part 4 covers server-side, and part 5 lists what to test.

---

## Part 1: Mobile RASP market (2025–2026)

### Consolidation
| Date | Event |
|---|---|
| 2025-03 | INKA Entworks (AppSealing) renamed to **DoveRunner** |
| 2025-08 | **Approov** £5M Series A |
| 2026-02-05 | **Guardsquare acquires Verimatrix XTD** (~$8.5M; Verimatrix goes back to video anti-piracy) |
| 2026-03-02 | **OneSpan acquires Build38** (SDK in-app protection and threat intelligence) |
| 2026-08-12 | **Promon acquires Codesealer** and launches Promon Shield for Web |

Common product direction: every vendor is adding a **telemetry backend with post-release policy control**:
- Promon: Insight and Control (Control is in private preview from Nov 2026).
- Guardsquare: ThreatCast.
- Appdome: ThreatScope and Threat Dynamics.
- Zimperium: zDefend over-the-air rules and a Mobile App Response Agent.
- Digital.ai: App Aware.
- Licel: Alice.

### Vendor comparison
| Vendor / product | Integration model | Differentiators | Open source |
|---|---|---|---|
| **Guardsquare** DexGuard / iXGuard (+XTD) | **Compiler/build plugin** | Polymorphic obfuscation, code virtualization, RASP checks spread through the code, different per build, ThreatCast telemetry | ProGuard only |
| **Promon** SHIELD | **Post-compile wrapping** or SDK | No code changes; screenshot, overlay and keylogger protection; Insight included; Control for OTA policy | No |
| **Talsec** freeRASP / RASP+ / AppiCrypt | **SDK** with callbacks | freeRASP is free (it sends telemetry to Talsec and ships one generic binary to all apps). RASP+ adds a per-app binary, overlay and accessibility detection, dynamic pinning, and AppiCrypt backend attestation | Wrappers MIT; core is binary |
| **Appdome** | **No-code** binary injection ("Fusion") | Claims 400+ defenses, anti-bot and anti-fraud, ThreatScope XDR, per-binary subscription | No |
| **Zimperium** zShield / zDefend / zKeyBox | Build-time hardening plus SDK | On-device ML threat detection, OTA rules, **white-box crypto** (from whiteCryption) | No |
| **Digital.ai** (formerly Arxan) | Post-build "guard network" | Guard networks that check each other, white-box crypto, App Aware, LLM-assisted Quick Protect Agent v2 | No |
| **Licel** DexProtector / vTEE | Post-build, offline | **EMVCo SBMP-approved** software TEE and SPT, strong fit for SoftPOS | No |
| **OneSpan** App Shielding (+Build38) | Shielding plus SDK | Banking focus; ⚠️ historically said to be built on Promon technology through an OEM deal | No |
| **Approov** | SDK plus cloud attestation | Verdict decided in the cloud, not on the device; short-lived JWT attached to each request; **dynamic pinning**; secrets delivered at runtime; public pricing tiers by monthly active users | No |
| **Irdeto** Cloakware / Denuvo Mobile | Source transformation / post-build | White-box crypto; anti-cheat for games | No |
| **Google** Play Integrity + Automatic Integrity Protection (pairip) | API / Play Console toggle | Free; anti-repackaging; custom anti-tamper only for select partners | No |
| **Open source** | LLVM pass / ProGuard / libraries | O-MVLL, dProtect, IOSSecuritySuite, RootBeer | Yes |

Also in the market: DoveRunner, PreEmptive, Jscrambler, Wultra, Protectt.ai, Kobil, and the Chinese packers (Jiagu, SecNeo, Ijiami, Tencent, NetEase), which account for about 75% of packed apps in one academic dataset.

### Integration models: trade-offs
- **Compiler/build plugin** (Guardsquare, O-MVLL). Checks can be woven deep into the app code, and the output differs per build. The cost is coupling to the build toolchain.
- **Post-compile wrapping** (Promon, Appdome, Licel, Digital.ai, Google's Automatic Integrity Protection). Fast to adopt and needs no source code. Checks tend to sit at the edges of the app (initializers, loader), which makes them easier to find and remove.
- **SDK** (Talsec, zDefend, Approov, Build38). The developer controls the reaction logic, but the callbacks are a surface an attacker can hook.

---

## Part 2: Mobile protection techniques

### Root detection (Android)
- **Attacker stack in 2026:**
  - Root managers: Magisk, KernelSU / KernelSU-Next, APatch.
  - Zygisk implementations: Zygisk Next, ReZygisk, NeoZygisk.
  - Hiding modules: Shamiko, Zygisk-Assistant, SUSFS (kernel-level hiding).
  - Integrity spoofing: PlayIntegrityFix plus TrickyStore with leaked keyboxes.
- **Dead checks:** `su` binaries, root-manager package names, `test-keys`, `ro.debuggable`. DenyList and Shamiko unmount root artifacts from each app's mount namespace, and Zygisk loads modules before any app code runs.
- **Checks that still work:** mount-namespace and PID-namespace inconsistencies, anomalies in `/proc/self/mountinfo`, behavioral and consistency fingerprinting, and many independent signals combined. The hiders change what the app can see, not what is actually on the device.
- **Hardware attestation is the strongest signal:**
  - Since May 2025 on Android 13+, `MEETS_DEVICE_INTEGRITY` effectively requires a locked bootloader.
  - `MEETS_STRONG_INTEGRITY` requires hardware Key Attestation and a security patch from the last 12 months.
  - A new EC P-384 attestation root has been in use since 2026-02-01.
  - Remote Key Provisioning (RKP) makes leaked factory keyboxes useless.
  - Oct 2025 additions: `appAccessRiskVerdict`, a Play Protect verdict, `recentDeviceActivity`, and device recall (beta).
- **Caveat: attestation relay** (Quarkslab, 2026-08-11). An attacker hooks `generateAttestedKey()` with Frida and relays the challenge to a clean phone, which returns a genuine certificate chain. The fix is server-side: check `attestationApplicationId` (package name and signing-certificate digest) in the certificate. Many backends skip this.

### Jailbreak detection (iOS)
- **Current jailbreaks:**
  - **Dopamine**: rootless; tweaks live under `/var/jb`; uses the ElleKit hooking engine.
  - **palera1n**: uses the checkm8 bootrom exploit on A8–A11 devices, so Apple cannot patch it.
- **Hiding:** RootHide randomizes the `/var/jb` path. Dopamine 2.4's **Hide Jailbreak** unmounts `/var/jb` for the target app. The Shadow and Choicy tweaks hide the jailbreak from specific apps.
- **Result:** classic checks on file paths, `canOpenURL`, `_dyld_image_count` and sandbox writes are only cheap first layers now.
- **What works:** detect what a jailbreak *enables* (code patching, hooks, memory tampering), use App Attest, and correlate several signals.

### Anti-hooking and anti-instrumentation
- **Frida detection vectors:**
  - `frida-agent`/gadget entries in `/proc/self/maps`, or in dyld images on iOS.
  - Thread names (`gum-js-loop`, `gmain`).
  - Named pipes, and a D-Bus handshake on port 27042.
  - RWX or anonymous executable memory.
  - **Inline-hook trampolines**, found by comparing function prologues in memory with the on-disk `.text`.
  - Checksums of the app's own code pages.
- **Attacker response:** renamed or stealth Frida forks such as strongR-frida, Florida, hluda, undetected-frida and phantom-frida. phantom-frida carries about 90 patches against 16 detection vectors and is rebuilt weekly. Static signatures lose against these.
- **Xposed / LSPosed:** detect via stack traces, `ArtMethod` tampering, and class-loader enumeration.
- **iOS (Substrate / ElleKit, Objection):** dyld image checks, fishhook symbol-pointer checks, `__TEXT` hashing.
- **Next frontier: kernel-level evasion.** **Purifire** (arXiv, Sep 2025) uses eBPF to rewrite syscall arguments and patch anti-analysis code, invisibly from userspace. It let Frida run on 28% of the apps in its dataset that had previously crashed Frida. SUSFS does the same kind of kernel-level hiding for root.

### Anti-debug
- **Android:** `TracerPid` in `/proc/self/status`, self-`ptrace`, `Debug.isDebuggerConnected()`/JDWP, timing checks.
- **iOS:** `ptrace(PT_DENY_ATTACH)` resolved through `dlsym`, the `sysctl` `P_TRACED` flag, `getppid() != 1`, exception ports.
- Each check is easy to patch on its own. They only hold up when duplicated and inlined.

### Emulator detection
- Build properties, telephony and sensor oddities, QEMU pipes, CPU features.
- On iOS: simulator checks, and detection of iOS apps running on Apple-silicon Macs.
- Frida 17.4's simulator backend makes instrumenting simulators easier, which makes these checks more important.

### Tamper and repackaging detection
- Signer digest or team ID embedded in several places.
- Checksums over dex, `.so`, `__TEXT` and resources.
- Installer-source checks and the Play Integrity `appRecognitionVerdict`.

### Obfuscation
- Name obfuscation, control-flow flattening, opaque predicates, bogus control flow, instruction substitution.
- String and constant encryption; class/dex encryption with loading at runtime; native packing.
- **Code virtualization** (Guardsquare, Google's pairip VM).
- OLLVM lineage: O-MVLL, Hikari, Pluto.
- Per-build polymorphism, so that public bypass scripts don't carry over to the next release.

### Anti-memory-dumping
- Decrypt just in time and wipe afterwards.
- Detect `/proc/self/mem` or `process_vm_readv` access and ptrace-based dumpers.
- On iOS, check `LC_ENCRYPTION_INFO` `cryptid` to spot a decrypted (dumped) binary being resigned.

### SSL pinning
- Static pinning (NSC, OkHttp `CertificatePinner`, TrustKit) falls to a single Objection or Frida script.
- Stronger options:
  - Native pinning wrapped in integrity checks.
  - **Dynamic pinning** delivered from the cloud (Approov, Talsec).
  - Proxy and VPN detection.
- **Most important:** tie API authorization to attestation, so a successful MITM yields no usable requests.

### Screen capture, overlays and accessibility malware
- **Android APIs:** `FLAG_SECURE`, the Android 14 screenshot callback, `setHideOverlayWindows`, `accessibilityDataSensitive`.
- **Android 15 `addScreenRecordingCallback`** has limits:
  - It needs the `DETECT_SCREEN_RECORDING` permission.
  - It only detects MediaProjection recorders, so scrcpy is missed.
  - It fires only on state changes, so read the initial state it returns.
- **Play Integrity `appAccessRiskVerdict`** flags installed apps that can capture the screen, draw overlays or control the device through accessibility.
- **iOS:** `UIScreen.isCaptured` and `userDidTakeScreenshotNotification`.

### Attestation
- **Play Integrity:** always decode and verify the verdict on the server.
- **Apple App Attest:**
  - The key lives in the Secure Enclave.
  - Each request carries an assertion with a counter that must strictly increase.
  - A **risk metric** (count of attested keys on the device over 30 days) detects "broker" devices serving many app instances.
  - WWDC26 added macOS 27 support and new iOS 27 authenticator-data extensions (TestFlight vs App Store, bundle version).
- **DeviceCheck:** 2 bits per device.
- **Commercial alternatives:** Approov, AppiCrypt, Build38.

### White-box crypto and secrets
- White-box crypto: Zimperium zKeyBox, Irdeto Cloakware, Digital.ai, Licel vTEE. In one published pentest, the white-box held up even after the RASP layer was bypassed.
- Baseline storage: Android Keystore (TEE or StrongBox) and iOS Keychain / Secure Enclave.
- Better still, keep secrets out of the binary: deliver them at runtime (Approov) or keep them in a vault (Talsec RASP+).

### Reaction strategies
- Options: kill the app, warn the user, degrade features, send a silent report, or let the server decide.
- The server-side decision, driven by telemetry, is becoming the standard.

### Implementation practices that make RASP robust
1. **Native checks, not Java/Kotlin/Swift.** Java-layer checks fall to a single Frida or LSPosed hook. Use obfuscated C/C++ and `RegisterNatives` with encrypted names, not exported `Java_*` symbols.
2. **Inline syscalls.** Issue `svc #0` directly on arm64 so libc and PLT/GOT hooks see nothing. Use many inlined `svc` sites rather than one wrapper, and hash those sites.
3. **Redundant and diverse checks.** Detect the same threat several ways, in several places, varied per build.
4. **Delay and randomize the reaction.** Separate detection from response. Corrupt state quietly (poison keys, change request signatures) instead of calling `exit()`, which points the attacker straight at the check.
5. **Tie checks to business logic.** Make integrity hashes inputs to key derivation or request signing, so removing a check breaks the feature.
6. **Check continuously, not only at startup.** Re-check in sensitive flows.
7. **Decentralize enforcement.** Avoid a single verdict variable or callback that can be flipped.
8. **Enforce on the server.** Bind attestation to each request with a nonce or `clientDataHash`. Verify the package and signer in attestation chains, check the CRL, and apply risk scoring.
9. **Check self-integrity on iOS** (hash `__TEXT`). It is often missing.

---

## Part 3: Bypass, evaluation and standards (mobile)

### Standards
- **OWASP MASVS v2, MASVS-RESILIENCE:**
  - RESILIENCE-1: platform integrity (root, jailbreak, emulator).
  - RESILIENCE-2: anti-tampering.
  - RESILIENCE-3: anti-static analysis.
  - RESILIENCE-4: anti-dynamic analysis.
- **MASWE** is the weakness layer between MASVS and the MASTG atomic tests and demos. The MASTG now includes bypass demos, e.g. MASTG-DEMO-0108 (Frida detection via `/proc/self`).
- **PCI MPoC** makes **Attestation & Monitoring (A&M)** mandatory:
  - Integrity violations detected on the device must be reported to a backend.
  - The data must be fresh and authentic.
  - PIN processing is allowed only after A&M approval.
- **EMVCo SBMP** evaluates SDKs, TEEs, attestation and software-protection tools. **PCI SSS / Secure SLC** covers the software lifecycle.
- **Regulators:**
  - Explicit mobile-protection requirements: MAS TRM (Singapore), RBI (India), BNM RMiT (Malaysia).
  - ⚠️ EBA (EU) and SAMA (Saudi Arabia) requirements are mostly claimed by vendors; I could not confirm them from the regulators' own text.
- **Gartner:** mobile RASP falls under the "in-app protection" category.

### Attacker toolkit (what to test against)
- **Dynamic instrumentation:**
  - Frida via `frida-server` or `frida-gadget` in a repackaged app; Stalker for tracing; Objection for turnkey bypasses.
  - Stealth Frida forks.
- **Hooking without repackaging:** LSPosed modules. LucidBit Labs found **one LSPosed module bypassed root detection in every target app**. Commercial RASP usually funnels into one to three decision branches, and hooking those is enough.
- **Play Integrity spoofing:**
  - PIF plus TrickyStore plus keyboxes can still sometimes reach DEVICE integrity.
  - STRONG fails once keyboxes are revoked or RKP is in use.
- **iOS:** Shadow, Choicy, Dopamine Hide Jailbreak, RootHide.
- **Static patching:** apktool/smali edits; NOP-ing native branches; scripted ELF/Mach-O rewrites with LIEF.
- **Emulation:** **unidbg** runs native Android libraries including JNI; **Qiling** adds syscall handling and reverse debugging. Both let an analyst run protection code without the RASP's environment present.
- **Locating checks:** syscall tracing with strace, seccomp or eBPF shows where checks read `/proc`, call `ptrace`, or `stat` root artifacts.

### Public research
- **Ostorlab, 2026-08-12, ["Mobile shielding: the RASP detection–enforcement gap"](https://blog.ostorlab.co/mobile-shielding-rasp-detection-enforcement-gap.html).** Across shielded banking apps, detection was consistently good and enforcement consistently weak:
  - One Android app routed every verdict through a single Java method returning one integer, read by eight enforcement sites.
  - One iOS app never verified its own code; three instruction patches disabled both its jailbreak detection and its pinning.
  - Frida detection sampled `/proc/self/status` only once at startup.
  - Detection trusted system properties an attacker could write.
  - Server-side authorization was missing.
- **Promon SHIELD:**
  - DIMVA 2018, "Honey, I Shrunk Your App Security": removed the protection statically and disabled it dynamically at runtime.
  - Recent public reversing of SHIELD ~7.x, including a PoC repo (`KiFilterFiberContext/promon-reversal`). ⚠️ Promon disputes that it bypasses any current, supported configuration.
- **arXiv 2601.21258 (2026), accessibility-abuse attacks on East/SE-Asian banking apps:** only about 9% of apps used protector-type RASP, but 6 of those 8 resisted the attacks. Strong protection is rare, and effective when present.
- **Quarkslab (2026-08):** the hardware-attestation relay attack described in Part 2.
- ⚠️ I found no authoritative, current public end-to-end break of DexGuard or Appdome.

---

## Part 4: Server-side RASP / ADR

### State of the category
- Gartner dropped RASP from its AppSec Hype Cycle in **2021**; several 2025 summaries give the wrong year. It now recommends "ADR or RASP solutions to augment a WAF."
- The category now sells under other names:
  - **ADR (Application Detection & Response):** Contrast, Oligo, Miggo.
  - **Exploit Prevention inside APM tracers:** Datadog, Dynatrace.
  - **In-app firewall:** Aikido Zen.
- Market events:
  - Harness and Traceable completed their merger (Mar 2025).
  - Oligo raised $50M (Jan 2025) and $60M (Aug 2026), and launched Runtime Exploit Blocking in Apr 2026.
  - Miggo raised a $17M Series A (Apr 2025).
  - Contrast launched **CVE Shield** (Jul 2026).
  - **Imperva RASP is being wound down:** 4.5.x end of support Oct 2025, 4.4.x LTS Oct 2026.

### Vendor comparison
| Solution | Languages | Approach | Open source |
|---|---|---|---|
| **Contrast ADR** (formerly Protect) | Java, .NET, Node, Python, Go, PHP | In-process agent; checks the actual query or command at the sink; CVE Shield micro-sandboxes (60 Java CVEs so far) | No |
| **Datadog App & API Protection** (Sqreen lineage) | .NET, Java, Node, Python, Go, PHP, Ruby | Built into the APM tracer; `libddwaf` engine; heuristics at the sink rather than taint tracking; Go instrumented at compile time (Orchestrion) | Engine and tracers yes |
| **Dynatrace Runtime Application Protection** | Java (fullest coverage); .NET and Go (SQLi and command injection only) | OneAgent instrumentation; monitor or block per rule | No |
| **Imperva RASP** (Prevoty) | Java, .NET, Node | "LangSec" grammar parsing at the sink | No, **end of life** |
| **Fastly Next-Gen WAF** (Signal Sciences) | Java, .NET, Node, Go, plus web-server modules | In-process module that inspects requests; effectively an in-app WAF, not sink hooking | No |
| **Waratek** | Java, .NET | JVM bytecode plus taint-aware lexical analysis; virtual patches with no restart | No |
| **OpenRASP** (Baidu) | Java, PHP 5.3–7.4 | Hooks plus JS detection plugins; little recent activity | Apache-2.0 |
| **Aikido Zen** | Node, Python, PHP, Java, .NET, Go | Library hooks plus a shared Rust tokenizer; detection by default, blocking opt-in | AGPL |
| **Oligo** | Any language | **eBPF** sensor that tracks library and function execution; claims mid-exploit blocking | No |
| **Miggo** | ⚠️ not published | eBPF plus OpenTelemetry "DeepTracing"; responds mostly by generating rules for an external WAF | No |
| **Traceable** (Harness) | Java, Go, Python, Node, plus eBPF | API-security focus; **no blocking in eBPF mode** | No |
| **Falco / Sysdig** | Any | Syscall rules: a CWPP tool, not RASP | Falco yes |

### How detection works
- **How agents get into the application:**

  | Runtime | Mechanism |
  |---|---|
  | Java | `java.lang.instrument` agent rewrites bytecode at sinks (`Statement.execute`, `ProcessBuilder.start`, `InitialContext.lookup`, `ObjectInputStream.resolveClass`) |
  | .NET | CLR profiler with IL rewriting or ReJIT |
  | Node.js | `require-in-the-middle` / `import-in-the-middle`; ESM plus bundlers often break it |
  | Python | Monkey-patching and import hooks |
  | PHP | Zend extensions that override internal functions |
  | Go | Compile-time instrumentation |

- **Sink-based detection with the request input (the Sqreen model).** At the sink, the agent takes the final SQL, command, path or URL and asks whether a request parameter crosses a token boundary and changes the grammar. For example, `105 OR 1=1` turns into keywords and operators instead of staying one literal. The same idea covers:
  - Command injection, with a shell tokenizer.
  - Path traversal, when input resolves outside the expected root.
  - SSRF, when input controls the scheme or host, or the request goes to an internal or metadata IP.

  This is why false positives stay low: an alert fires only when input actually changes the structure.
- **Taint tracking** (IAST-style: Contrast Assess, Waratek, Hdiv). More precise, but heavier, which is why Datadog avoids it in production.
- **Behavior sandboxing** for deserialization, XXE and JNDI: block what the code tries to *do* (remote class loading, spawning processes, outbound LDAP/RMI) rather than matching input. This is how virtual patching of Log4Shell-class bugs works.
- **eBPF:** works for any language and changes nothing in the application, which makes it good for reachability ("was the vulnerable function executed?") and for post-exploit behavior (a Java process spawning `sh`). It is weak at connecting a specific HTTP parameter to a specific SQL token, runs only on Linux, needs privileges, and can only block coarsely.
- **Known bypasses (Java), once the attacker already has code execution in the JVM:**
  - Reflection into `ProcessImpl` or `Unsafe` to get below the hooks.
  - Attaching a second agent that disables the first.
  - `System.load` of a native library.
  - Spawning a child JVM with no agent.

  RASP is good at stopping the first exploit step and weak after in-process code execution.
- **Overhead:** vendor claims only (Waratek ≤2%, Oligo <1%, Datadog "negligible"). ⚠️ I found no independent benchmark.

### Category comparison
| | WAF | RASP | IAST | ADR | CWPP |
|---|---|---|---|---|---|
| Where | Edge | In process | In process, pre-production | Agent or eBPF, plus a SOC workflow | Kernel / host |
| Blocks | Yes | Yes, precisely | No | Varies | Process-level kill or deny |
| False positives | High | Low | Very low | Low to medium | Medium |
| Main weakness | Encoding tricks, logic flaws | Per-language agents; evaded after code execution | Test environments only | eBPF lacks request context | Blind to app-layer injection |

**Why standalone RASP stalled:** teams feared production instability, every language needed its own agent, the ROI was unclear, it competed with the WAF for budget, and it pulled security and development teams in different directions. It survives bundled into APM tools (Datadog, Dynatrace) or as open source (Aikido Zen, OpenRASP).

---

## Part 5: Pentest checklist for mobile RASP

1. **Root/jailbreak baseline.** Test with Magisk + Shamiko, KernelSU, APatch, and Dopamine / palera1n rootless. Does the app detect it, and does it actually **enforce** something, not just log?
2. **Instrumentation.** Try vanilla Frida, stealth forks, gadget injection in a repackaged app, Objection and LSPosed.
3. **Single point of failure.** Can one to three hooks at the decision branch turn everything off?
4. **Attestation.** Try PIF + TrickyStore at the BASIC, DEVICE and STRONG levels. Is the verdict enforced on the **server**? Does the backend check `attestationApplicationId` (relay attack)? Is the App Attest counter enforced?
5. **Tamper.** Re-sign a modified APK or IPA and patch the native `.so`. Do the integrity checks fire, and do they get reported?
6. **Timing.** Attach after startup. Are the checks continuous, or one sample at launch?
7. **Pinning.** Does a Frida or Objection bypass yield *usable* API calls, or is authorization tied to attestation?
8. **Anti-debug.** JDWP and native ptrace on Android; `PT_DENY_ATTACH` and `sysctl` on iOS.
9. **Telemetry.** Trigger violations and confirm the backend receives them, correlates them and acts on them (the PCI MPoC A&M model).
10. **Static resilience.** Run APKiD to identify the protector. Can strings and logic be recovered with jadx or Ghidra? Can the native checks be emulated in unidbg?

**Bottom line for clients:** on a device the attacker fully controls, no client-side RASP is unbypassable. Its value is raising attacker cost, generating telemetry, and feeding a **server-side trust decision**. An evaluation should judge enforcement and reporting, not just detection.

---

## Key sources
- OWASP MAS: https://mas.owasp.org/MASVS/ · https://mas.owasp.org/MASWE/ · https://mas.owasp.org/MASTG-DEMO-0108/
- Play Integrity: https://android-developers.googleblog.com/2024/12/making-play-integrity-api-faster-resilient-private.html · https://android-developers.googleblog.com/2025/10/stronger-threat-detection-simpler.html · https://developer.android.com/privacy-and-security/security-key-attestation
- Apple App Attest (WWDC26): https://developer.apple.com/videos/play/wwdc2026/201/
- Ostorlab detection–enforcement gap: https://blog.ostorlab.co/mobile-shielding-rasp-detection-enforcement-gap.html
- Quarkslab attestation relay: https://blog.quarkslab.com/bypassing-android-hardware-attestation.html
- LucidBit Labs: https://lucidbitlabs.com/blog/commercial-root-detection-vs-sophisticated-adversary/
- Purifire / Chinese packers: https://arxiv.org/html/2509.16340v1 · Banking apps study: https://arxiv.org/html/2601.21258v1
- DIMVA 2018 Promon: https://obfuscator.re/nomorp-paper-dimva2018.pdf · https://github.com/KiFilterFiberContext/promon-reversal
- Guardsquare/XTD: https://www.guardsquare.com/press-release/guardsquare-acquires-verimatrix-xtd · OneSpan/Build38: https://www.onespan.com/about/news/onespan-completes-acquisition-build38 · Promon/Codesealer: https://promon.io/security-news/promon-completes-acquisition-of-codesealer-extending-protection-to-web-applications-and-the-apis-behind-them
- Talsec: https://docs.talsec.app/ · Approov: https://approov.io/pricing · O-MVLL: https://obfuscator.re/
- Frida 17: https://frida.re/news/2025/05/17/frida-17-0-0-released/ · strongR-frida: https://github.com/hzzheyang/strongR-frida-android · unidbg: https://github.com/zhkl0228/unidbg · Qiling: https://github.com/qilingframework/qiling
- Root hiding: https://github.com/snake-4/Zygisk-Assistant · iOS: https://github.com/jjolano/shadow · https://github.com/roothide/Dopamine2-roothide
- PCI MPoC: https://www.guardsquare.com/blog/navigate-pci-mpoc-compliance · EMVCo SBMP: https://www.emvco.com/processes/software-based-mobile-payment-evaluation-process/
- Server-side: https://docs.contrastsecurity.com/en/adr-technology.html · https://docs.datadoghq.com/security/application_security/threat_protection/exploit-prevention/ · https://github.com/DataDog/libddwaf · https://github.com/AikidoSec/zen-internals · https://github.com/baidu/openrasp · https://ramimac.me/rasp · https://www.deep-kondah.com/smashing-runtime-application-self-protection-rasp/ · https://www.imperva.com/support/wp-content/uploads/sites/26/2024/10/RASP-EOL-Notice-October-31_-2024.pdf

## ⚠️ Unverified or treat with caution
- Talsec RASP+ pricing (~€284/month) comes from a third-party site.
- OneSpan's historical OEM basis on Promon technology is unconfirmed.
- Dopamine and palera1n version ranges come from inconsistent README and wiki data.
- The RKP date for moving exclusively to the new root, and whether that root is RSA-4096 or ECDSA P-384, are unconfirmed.
- The KernelSU `0xDEADBEEF` detection side channel comes from a single source.
- Promon disputes the claimed bypass of SHIELD.
- Oligo and Miggo language coverage and blocking internals are not published.
- There are no independent overhead or false-positive benchmarks for any server-side vendor.
- Vendor "agentic AI" claims come from press releases and were not tested.
