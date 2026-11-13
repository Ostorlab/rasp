# PK03 Stage A design addendum: current backend provenance

This addendum corrects the backend inventory in the historical
`/tmp/mega-adr/contracts/native-protection-diversity.md` and its original PK03
report. Those original files remain unchanged as historical evidence. Their
inspection of backend main `2fe4e310...` does not describe the approved program
baseline. In particular, the suggestion that worker/parser/registration provenance
must be built from scratch is withdrawn.

This is an inventory correction and Stage A boundary, not a backend schema change
or authorization for Stage B.

## Actual source association

Root approved read-only snapshot:
`/tmp/mega-adr/rt17-stage1-concrete-followup/backend10593`, commit
`10593b8681d578e7dd73e50a1853ce565a3dd77e`. The RT17 source association names
`/tmp/be18-genuine-apple-health-acceptance/backend-final.tar`, **590 regular files**,
SHA256 `5a59cd7a3eeee5b8d6cdf3a89648f54641d8b4caa71daba1d56d43b1bf812784`.

PK03 verified the ten relevant contract/caller/document files against the existing
`backend-source-inspection.json` hashes. Their exact digests and that record's
digest are in `/tmp/mega-adr/pk03-stage-a-evidence/backend-reference.json`. This
references existing proof; it creates no second backend snapshot and makes no
claim about uninspected active branches or deployed services. No backend source,
database or model was changed or executed.

## Existing closed contract and callers

All paths below are relative to that approved backend snapshot.

| Source | Actual behavior |
|---|---|
| `rasp_adr/rasp/build_capabilities.py::validate` | Closed schema **1**, exactly five keys: `schema_version`, `build_id`, `platform`, `effective_checks`, `capability_bindings`. Booleans cannot stand in for integer schema versions. Unknown keys/versions, build/platform mismatch, malformed digests, duplicate/invalid ABI bindings or wrong OS floors fail. Effective groups are bounded to 64, unique and sorted. Serialized provenance is capped at **16 KiB**. |
| `build_capabilities.py::unique_object` | Rejects duplicate keys at every decoded JSON object depth. |
| `build_capabilities.py::from_pack_result` | Adapts actual installed PackResult groups and pristine native bindings. Both attributes absent is the sole legacy path. Bindings contain exactly `schema_version`, `catalogue_id`, `artifact_sha256`, `platform`, `abi`, `minimum_os`; a null binding set preserves unknown/mixed capability state. Android supports the existing four ABIs/floor31; iOS supports arm64/floor12.0. Foreign catalogue hashes do not create backend output expectations. |
| `rasp_adr/rasp/pack_app.py::_pack` | Calls the installed public packer, converts actual results with `from_pack_result`, and includes present `capability_provenance` in subprocess JSON. |
| `rasp_adr/rasp/packing.py::pack` / `PackedApp` | Parses bounded subprocess results, strictly validates present provenance against build/platform, and carries it on `PackedApp.capability_provenance`. Invalid present metadata is a packing error; absence remains legacy unknown. |
| `rasp_adr/rasp/build_jobs.py::_pack` / `_register_build` | Revalidates returned metadata before registration, checks current claim/tenant/application ownership, stores provenance on Build, and refuses conflicting successful-build provenance. Output objects are attempt/claim scoped. Existing reuse and lifecycle rules are not a new seed-attempt persistence service. |
| `rasp_adr/rasp/models.py::Build` | Already has nullable, noneditable `capability_provenance` JSON separate from backend-selected `checks`, plus `artifact_object`. Historical/admin builds may be unknown. |
| `rasp_adr/rasp/schemas/types.py::BuildType` | Exposes actual effective groups/provenance and distinguishes RECORDED, UNKNOWN and MINIMIZED. RECORDED pristine bindings do not establish execution or attestation. |
| `rasp_adr/rasp/check_health_reads.py` | SQL only returns provenance text at or below **16384 bytes**, records oversize separately, and passes bounded/invalid state to downstream assessment. This read ceiling is not permission to enlarge the worker protocol. |
| `rasp_adr/rasp/retention_contract.py` / `metadata_controls.py` | Already name Build provenance/artifact lifecycle and tenant scope. Explicit Build metadata minimization clears `checks` and `capability_provenance`. No independent PK03 TTL, hold, private-symbol registry or recovery policy may be grafted onto these controls. |
| `docs/build-capability-provenance.md` | Existing backend documentation for actual pristine-artifact provenance and its limits. |

## Correct remaining PK03 gap and allocation

The current five-key protocol carries groups and pristine runtime capability
bindings. It does **not** carry the proposed native compiler/plugin/config/seed
manifest, private source symbols or an address-to-source diagnostic map. Adding
any of those to this JSON would collide with its closed v1 validator. The
historical PK03 proposal for a separate bounded local native sidecar was not an
allocation to increase this backend ceiling.

RT17 owns the coordinated proposed schema2/customer_integrity work. PK03 must not
independently add keys, activate schema2, raise the **16KiB** ceiling, allocate a
catalogue revision or change build-id deduplication. Any later backend-native
association requires root's concrete schema/ownership/size/lifecycle contract
against the assigned current backend parent, integrating the existing
`pack_app -> packing -> build_jobs -> Build` path. No imaginary new service or
replacement persistence model is necessary to describe that future work.

Stage A implements only canonical/frozen seed policy and guarded compilation on
the existing iOS target, with accurate coverage comments. New opt-in target hooks,
source annotations, native sidecar production, packer/publisher association,
Android plugin selection and backend/schema work remain **Stage B, not started**.
Root still assigns final runtime/plugin/publisher composition and actual platform
validation. No symbol-retention service or private-key/signing operation exists
as a result of this addendum.
