# Remaining platform delivery

Scope confirmed: all remaining items in `TODO.md`, configurable external
integrations with local infrastructure, proprietary packages, no public
release. PRs stay open for human review and merge.

Delivery order and acceptance boundaries:

| Workstream | Deliverables in scope |
| --- | --- |
| Validation foundation | Core CI, enforcement checker with positive control, size/latency evidence gates, proprietary notice |
| Native binary hygiene | String-literal registry for encryption/renaming, encrypted constants, symbol renaming, source- and binary-size/hygiene gates, identical network behavior between hardened and development builds, Android ABI builds |
| Trust foundation | Strict claims/build identity/rebinding rules, tenant-scoped Postgres persistence, atomic challenges/counters, Play Integrity verdict decoding, Apple attestation/assertions |
| Mobile protection | Compiled Android/Dart trust flow, Play Integrity, pinned transport, erasable SecureStore, signed-policy consumption, delayed/silent reactions |
| Apple and adapters | iOS detections/App Attest/self-integrity/Keychain plus private native wrappers and platform compile checks |
| Control plane | Policy signing, staged rollout/rollback, persistent signing rotation, entitlement-gated risk-scoped secrets, telemetry/outbox/SIEM, risk-model tooling |
| Console | Authenticated scoped dashboards, install timeline, bypass watch, policy editor and rollout controls |
| Deep hardening | Compiler and Gradle integration, call weaving, control-flow/MBA/virtualization, class/asset encryption, encoded white-box tables and integrity-bound data |
| Server protection | Java/.NET/Node/Python/Go/PHP sink instrumentation, SCA-selected virtual patches, optional eBPF observation |
| Device evidence | Bypass regression matrix, tuned detectors, coverage/size budgets, measured reference devices, private crash mapping |

**Shared trust rules:**

- Device observations remain advisory; the server enforces fresh attestation and session-key possession.
- App Attest does not prove biometric authentication of another key.
- Signed policy bytes are verified exactly. Revisions never decrease; rollback republishes a higher revision; pins retain bootstrap trust.
- Database keys and operations always include tenant/application scope.
- ML cannot lower deterministic security floors.

## Which claims still require external evidence?

Local tests and configurable adapters do not establish successful live Google or
Apple attestation, physical-device behavior, resistance to DCA/DFA, or production
ML accuracy. These claims require the corresponding external evidence. Track
implemented and validated states separately in each PR and in `TODO.md`.
