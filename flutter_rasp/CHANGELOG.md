# Changelog

## Unreleased

### Trust service

* The backend is now a trust service: it binds an install with Key Attestation and issues short-lived ES256
  integrity tokens (published JWKS) from a sealed RASP report, the hardware attestation and a platform
  (Play Integrity) verdict. Resource servers verify the token and a DPoP-style per-request proof, then map
  risk to allow / step-up / deny. Replaces the direct signed-transaction (`rasp-tx-1`) path.
* The native core seals its report: it MACs the exact report bytes with a per-build key (HMAC-SHA256), so a
  repackaged build's report is refused. Native methods are bound with `RegisterNatives`.
* Two device keys: a hardware-backed, user-auth install key authorizes token issuance (one biometric
  prompt), and an ephemeral session key signs each request's proof silently.

### Detection

* New `netMitm` threat: an HTTP proxy or a user-installed CA.
* New behavioral hooking detector: executable mappings backed by tmp/memfd/deleted files.

### Fixes

* No longer crashes on Android 7–8.1 when a user-auth signature is requested: the platform `BiometricPrompt`
  (API 28+) is guarded and `auth_unsupported` is surfaced instead.
* The accessibility allowlist now includes the major password managers (their autofill uses an accessibility
  service), so they are no longer flagged as abuse.

### Platform SDK additions

* Android shared client, pinned native HTTPS, genuine Play Integrity tokens, signed policy updates and erasable authenticated storage.
* iOS App Attest enrollment/assertions, request signatures, Keychain envelope storage, integrity manifests, pinned HTTPS and Flutter adapter.
* Packages remain proprietary; public publication is disabled. Platform-specific validation requirements are documented in `docs/mobile-platform.md`.

## 0.0.1

* Initial on-device release: root/emulator/debugger/hooking/tamper/installer detection, local policy and
  reactions, fraud protections, and device binding.
