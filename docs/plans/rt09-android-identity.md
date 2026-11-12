# RT09 Android signer observations implementation plan

Goal: add bounded, versioned current signer sets, public PackageManager rotation history, and supported Application package identity while preserving every legacy scalar and default group.

Architecture: keep legacy readers intact. Add shared certificate bounds/digest normalization, a strict complete-set path in the existing archive parser, and a public retained-Context JNI collector consumed by the actual identity dispatcher. Register draft expectations only in tests; root supplies the integrated parent and final catalogue revision.

- [x] Publish exact additive contracts and portable consumer controls in `docs/android-signer-observations.md` and `docs/fixtures/android-signer-observations-v1.json`.
- [x] Add failing archive and identity regressions, configure isolated host build with cached GoogleTest, then implement shared certificate handling and complete archive selection. Cover v2 parallel signers versus chain entries; v3 range matching; API31/33/34 v3.1 targeting; malformed/over-limit input and unsupported developer-release rotation.
- [x] Add real-JVM tests invoking compiled production identity dispatch, with only Android API boundaries simulated. Implement supported Context package/SigningInfo collector, per-field failures, bounded arrays/refs/bytes, history ordering and no private fallback. Wire sources into shipped Android and host/JVM test targets.
- [x] Extend compiled capability expectations with task-local draft rows, preserve legacy catalogue revision, and test portable consumer fixtures.
- [x] Validate focused/full host, ASan/UBSan/LSan, TSan, real JVM, four Android ABIs Debug/Release, artifact gates, formatter/tidy in matching compilation contexts, and packer compatibility/PK01. Maximum two jobs, no workers.
- [x] Self-review, update `/tmp/mega-adr/reports/rt09.md` with exact base/head and evidence, commit independent scope and STOP before publishing or parent integration.

Independent scope is ready for root review. The two documented Clang20 ELF32 baseline failures remain visible; exact-head CI, ART/device execution and final catalogue integration are root/platform-owned. See `/tmp/mega-adr/reports/rt09.md` for exact heads and validation evidence.
