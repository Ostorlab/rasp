# RT09 Android signer observations implementation plan

Goal: add bounded, versioned current signer sets, public PackageManager rotation history, and supported Application package identity while preserving every legacy scalar and default group.

Architecture: keep legacy readers intact. Add shared certificate bounds/digest normalization, a strict complete-set path in the existing archive parser, and a public retained-Context JNI collector consumed by the actual identity dispatcher. Ordinary-merge the exact approved RT07 parent and register the four outputs once in canonical schema1revision5, with the same generated cycle and capability expectations.

- [x] Publish exact additive contracts and portable consumer controls in `docs/android-signer-observations.md` and `docs/fixtures/android-signer-observations-v1.json`.
- [x] Add failing archive and identity regressions, configure isolated host build with cached GoogleTest, then implement shared certificate handling and complete archive selection. Cover v2 parallel signers versus chain entries; v3 range matching; API31/33/34 v3.1 targeting; malformed/over-limit input and unsupported developer-release rotation.
- [x] Add real-JVM tests invoking compiled production identity dispatch, with only Android API boundaries simulated. Implement supported Context package/SigningInfo collector, per-field failures, bounded arrays/refs/bytes, history ordering and no private fallback. Wire sources into shipped Android and host/JVM test targets.
- [x] Register canonical revision5 with36Android/26iOS identities, remove the draft overlay, and test portable consumer fixtures plus actual nine-output cycle handoff.
- [x] Validate focused/full host, ASan/UBSan/LSan, TSan, real JVM, four Android ABIs Debug/Release, artifact gates, formatter/tidy in matching compilation contexts, and packer compatibility/PK01. Maximum two jobs, no workers.
- [x] Self-review, update `/tmp/mega-adr/reports/rt09.md` with exact base/head and evidence, commit the combined reviewed scope and STOP before publishing for root review.

Independent scope is ready for root review. The two documented Clang20 ELF32 baseline failures remain visible; exact-head CI and ART/device execution are root/platform-owned; canonical integration is completed locally. See `/tmp/mega-adr/reports/rt09.md` for exact heads and validation evidence.

Approved integration: ordinary-merge root RT07 parent70d938b2cc33edea6bba3f715b32cd286c94d592, preserve both scopes, register schema1revision5 (36 Android/26 iOS), remove draft overlay, exercise nine identity outputs through caller/worker immutable cycle handoff, then rebuild all combined artifacts and actual installed-wheel PK01 controls before the final review commit.

All combined local gates completed: host660/662; ASan/UBSan/LSan and TSan652/654 with only the two visible inherited ELF32 limits; full configure-only tidy95sources; eight native build/stage/full-target-tidy/artifact configs; source packer426/19format-specific skips; actual installed wheel/publicAAB/PK01 and foreign-revision4/corruption/damaged-stage/mixed controls. Real configure regeneration/fatal failure/restoration passed.
