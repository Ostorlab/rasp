"""Packing of Android apps: adds the runtime to a built APK or AAB, for on-demand loading.

The packer keeps the app's framework and library dexes in the clear and encrypts only the app's own
("business") dexes, each on its own, so the runtime decrypts one business dex the first time a class
in it is needed. A screen the user never opens is never decrypted, and a decrypted dex is wiped as
soon as the class loader has copied it.

It produces the entries the runtime reads from the app's own APK (names and rules taken from the
runtime's ``payload/dex_store.*``, ``payload/assets.h``, ``payload/key_schedule.*`` and
``loader/loader_dex.*``):

- ``assets/rasp/s.bin`` — one input of the key schedule's fold, not a key by itself (key_schedule).
- ``assets/rasp/map.bin`` — the class map (see loader_map), encrypted, stored.
- ``assets/business/<i>.dex`` — one encrypted business dex per file, stored.
- the framework dexes and the stub, in the clear, as ``classes.dex`` … ``classesN.dex``.
- ``lib/<abi>/librasp.so`` — the runtime library, one per ABI, with the runtime's config and a
  per-ABI keystore share written into its ``.rasp_config`` section (see runtime_library). The
  loader's own dex is already embedded in it at the runtime's build.

No key ships in the app: every frame's key is derived, on the device, from the schedule in
``payload/key_schedule.*`` — the library's own sections, the s.bin entry, the map frame as shipped,
and environment gates that only a real Android runtime passes (key_schedule for the scheme).

For AAB files, all paths live under ``base/`` (e.g. ``base/assets/rasp/s.bin``,
``base/dex/classes.dex``, ``base/lib/<abi>/librasp.so``).  The manifest is in protobuf format
instead of binary AXML, and no zipalign or v1 signature stripping is needed.

It sets the manifest's appComponentFactory to the stub, raises minSdk to the runtime's floor (API 31,
which the in-memory loader and ``JNI_GetCreatedJavaVMs`` need), drops the app's original dexes and v1
signatures (APK only), and returns the protected app unsigned, so the customer signs it. The stub and
the native runtime are prebuilt artifacts from the runtime build; see resources.
"""

import collections.abc
import hashlib
import pathlib
import random
import zipfile

from rasp_packer import errors
from rasp_packer import identity
from rasp_packer import runtime_config
from rasp_packer.android import cipher
from rasp_packer.android import injection
from rasp_packer.android import java_program
from rasp_packer.android import key_schedule
from rasp_packer.android import loader_map
from rasp_packer.android import resources as resources_module
from rasp_packer.android import runtime_library
from rasp_packer.android import self_encrypt
from rasp_packer.android import split as split_module
from rasp_packer.android.aab import archive as aab_archive
from rasp_packer.android.aab import manifest as aab_manifest_module
from rasp_packer.android.apk import archive as apk_archive
from rasp_packer.android.apk import manifest as apk_manifest_module

PRIMARY_DEX = "classes.dex"
MINIMUM_API_LEVEL = 31

ASSET_DIRECTORY = "assets/rasp"
SHARE_ENTRY = f"{ASSET_DIRECTORY}/s.bin"
MAP_ENTRY = f"{ASSET_DIRECTORY}/map.bin"
JAVA_PROGRAM_ENTRY = java_program.PROGRAM_ENTRY
ASSET_PREFIX = "assets/"

_AAB_BASE = "base/"
_AAB_DEX_PREFIX = "base/dex/"
AAB_SHARE_ENTRY = f"{_AAB_BASE}{SHARE_ENTRY}"
AAB_MAP_ENTRY = f"{_AAB_BASE}{MAP_ENTRY}"
AAB_JAVA_PROGRAM_ENTRY = f"{_AAB_BASE}{JAVA_PROGRAM_ENTRY}"
AAB_ASSET_PREFIX = f"{_AAB_BASE}{ASSET_PREFIX}"

type Splitter = collections.abc.Callable[[pathlib.Path, str], split_module.Split]
type AabSplitter = collections.abc.Callable[[dict[str, bytes], str], split_module.Split]


def pack(
    *,
    app: pathlib.Path,
    output: pathlib.Path,
    config: runtime_config.RuntimeConfig,
    artifacts: resources_module.Artifacts | None = None,
    splitter: Splitter = split_module.split,
    aab_splitter: AabSplitter = split_module.split_from_dex_entries,
) -> identity.AppIdentity:
    """Packs an Android app (APK or AAB), writing the protected output.

    Args:
        app: The built APK or AAB to protect.
        output: Where to write the protected app. It is unsigned.
        config: The runtime's config, written into the app.
        artifacts: The prebuilt stub and libraries. Loaded from the package resources when not given.
        splitter: Splits an APK's classes. The default runs the bundled splitter.
        aab_splitter: Splits an AAB's classes from pre-extracted DEX entries.

    Returns:
        The app's package name and version, read from its manifest.

    Raises:
        InvalidApkError: The APK is invalid or missing required entries.
        InvalidAabError: The AAB is invalid or missing required entries.
        ManifestError: The app's manifest cannot be read or edited.
        MissingRuntimeArtifactError: A prebuilt runtime artifact is missing.
        InvalidRuntimeError: A runtime library is not an ELF file or has no ``.rasp_config`` section.
        ConfigTooLargeError: The runtime's config does not fit in a runtime library.
        UnsupportedAbiError: The app ships native libraries for an ABI the runtime is not built for.
        AlreadyProtectedError: The app already holds the map, or its manifest already names the stub.
        SplitError: The app's classes cannot be read or split.
    """
    if artifacts is None:
        artifacts = resources_module.load()
    if _is_aab(app):
        return _pack_aab(
            app=app,
            output=output,
            config=config,
            artifacts=artifacts,
            splitter=aab_splitter,
        )
    return _pack_apk(
        app=app,
        output=output,
        config=config,
        artifacts=artifacts,
        splitter=splitter,
    )


def _is_aab(app: pathlib.Path) -> bool:
    """An AAB contains ``BundleConfig.pb``; an APK does not."""
    try:
        with zipfile.ZipFile(app) as zf:
            return "BundleConfig.pb" in zf.namelist()
    except zipfile.BadZipFile, OSError:
        return False


def _pack_apk(
    *,
    app: pathlib.Path,
    output: pathlib.Path,
    config: runtime_config.RuntimeConfig,
    artifacts: resources_module.Artifacts,
    splitter: Splitter,
) -> identity.AppIdentity:
    """Packs an APK."""
    apk = apk_archive.Apk.read(app)
    dex_names = apk.dex_names()
    if PRIMARY_DEX not in dex_names:
        raise errors.InvalidApkError(f"APK has no {PRIMARY_DEX} to protect")
    manifest = apk.manifest()
    app_identity = apk_manifest_module.app_identity(manifest)
    if (
        MAP_ENTRY in apk.names()
        or apk_manifest_module.app_component_factory(manifest)
        == resources_module.STUB_FACTORY_CLASS
    ):
        raise errors.AlreadyProtectedError("the app is already protected")

    result = splitter(app, app_identity.package_name)

    patched_manifest = apk_manifest_module.set_app_component_factory(
        apk_manifest_module.clear_debuggable(
            apk_manifest_module.raise_min_sdk_version(manifest, MINIMUM_API_LEVEL)
        ),
        resources_module.STUB_FACTORY_CLASS,
    )
    libraries: dict[str, bytes] = {}
    digests: dict[str, bytes] = {}
    for name, library in injection.library_entries(apk, artifacts).items():
        configured = runtime_library.write_config(library, config)
        libraries[name] = self_encrypt.encrypt_library(configured)
        digests[name] = hashlib.sha256(runtime_library.text_region(configured)).digest()
    root, share_asset, lib_entries, decoy_entries = _schedule_libraries(
        libraries, digests, config, app_identity.package_name.encode()
    )
    map_frame, program_frame, dex_entries = _encrypt_payload(
        result.business, root, random.SystemRandom()
    )
    base_dexes = injection.base_dex_entries(result.framework, artifacts.stub_dex)
    apk.write(
        output,
        replace={apk_archive.MANIFEST_ENTRY: patched_manifest},
        add={
            SHARE_ENTRY: share_asset,
            MAP_ENTRY: map_frame,
            JAVA_PROGRAM_ENTRY: program_frame,
            **dex_entries,
            **decoy_entries,
            **base_dexes,
            **lib_entries,
        },
        remove=set(dex_names) | injection.stale_signature_entries(apk),
    )
    return app_identity


def _pack_aab(
    *,
    app: pathlib.Path,
    output: pathlib.Path,
    config: runtime_config.RuntimeConfig,
    artifacts: resources_module.Artifacts,
    splitter: AabSplitter,
) -> identity.AppIdentity:
    """Packs an AAB."""
    aab = aab_archive.Aab.read(app)
    dex_names = aab.dex_names()
    aab_primary_dex = f"{_AAB_DEX_PREFIX}{PRIMARY_DEX}"
    if aab_primary_dex not in dex_names:
        raise errors.InvalidAabError(f"AAB has no {aab_primary_dex} to protect")
    manifest = aab.manifest()
    app_identity = aab_manifest_module.app_identity(manifest)
    if (
        AAB_MAP_ENTRY in aab.names()
        or aab_manifest_module.app_component_factory(manifest)
        == resources_module.STUB_FACTORY_CLASS
    ):
        raise errors.AlreadyProtectedError("the app is already protected")

    dex_entries: dict[str, bytes] = {}
    for name in dex_names:
        data = aab.get(name)
        if data is not None:
            dex_entries[name.removeprefix(_AAB_DEX_PREFIX)] = data
    result = splitter(dex_entries, app_identity.package_name)

    patched_manifest = aab_manifest_module.set_app_component_factory(
        aab_manifest_module.clear_debuggable(
            aab_manifest_module.raise_min_sdk_version(manifest, MINIMUM_API_LEVEL)
        ),
        resources_module.STUB_FACTORY_CLASS,
    )
    abis = injection.resolve_abis(_aab_native_abis(aab), artifacts)
    libraries: dict[str, bytes] = {}
    digests: dict[str, bytes] = {}
    for abi in sorted(abis):
        configured = runtime_library.write_config(artifacts.libraries[abi], config)
        entry = f"base/lib/{abi}/{resources_module.RUNTIME_LIBRARY}"
        libraries[entry] = self_encrypt.encrypt_library(configured)
        digests[entry] = hashlib.sha256(
            runtime_library.text_region(configured)
        ).digest()
    root, share_asset, lib_entries, decoy_entries = _schedule_libraries(
        libraries, digests, config, app_identity.package_name.encode()
    )
    map_frame, program_frame, dex_data_entries = _encrypt_payload(
        result.business, root, random.SystemRandom()
    )
    base_dexes = {
        f"{_AAB_DEX_PREFIX}{name}": data
        for name, data in injection.base_dex_entries(
            result.framework, artifacts.stub_dex
        ).items()
    }
    aab.write(
        output,
        replace={aab_archive.MANIFEST_ENTRY: patched_manifest},
        add={
            AAB_SHARE_ENTRY: share_asset,
            AAB_MAP_ENTRY: map_frame,
            AAB_JAVA_PROGRAM_ENTRY: program_frame,
            **{f"{_AAB_BASE}{name}": data for name, data in dex_data_entries.items()},
            **{f"{_AAB_BASE}{name}": data for name, data in decoy_entries.items()},
            **base_dexes,
            **lib_entries,
        },
        remove=set(dex_names),
    )
    return app_identity


def _schedule_libraries(
    libraries: dict[str, bytes],
    digests: dict[str, bytes],
    config: runtime_config.RuntimeConfig,
    package: bytes,
) -> tuple[bytes, bytes, dict[str, bytes], dict[str, bytes]]:
    """Builds the schedule's fold over the app's runtime libraries.

    It invents a fresh fold program — the per-app recipe of real inputs and decoys, in a random order — and the decoy entries the program names, then writes into each ABI's library its per-ABI keystore share, the share that makes that library's chains recover the root: the share cancels its ABI's chains, so every ABI recovers the same root. It also writes each library's expected plaintext `.text` digest before the fold's inputs are gathered, so the region digest binds the expectation into the root: a patched digest in the shipped file breaks every decryption, and the integrity check and the sensor guard can only compare the running code against the expectation the app decrypts with. The libraries arrive with their config written and their code and read-only data self-encrypted, and the fold gathers its digests from those shipped bytes: they stay encrypted on disk, and the runtime reads the library file — not the decrypted memory — so both sides gather the same digests.

    Args:
        libraries: The runtime libraries with their config written and their code and read-only data self-encrypted, by APK entry name. Each already carries the same config.
        digests: The SHA-256 of each library's plaintext `.text` section, by APK entry name.
        config: The runtime's config.
        package: The app's package name, which the fold program folds in, the way the runtime reads
            it from its APK's install path.

    Returns:
        The root key, the asset share to ship as the s.bin entry, the finished libraries, by APK
        entry name, and the decoy entries the fold program names, by APK entry name.

    Raises:
        InvalidRuntimeError: A library is not an ELF file or has no required section.
        ConfigTooLargeError: The config does not fit in a library's section.
    """
    generator = random.SystemRandom()
    sections = frozenset().union(
        *(runtime_library.fold_sections(library) for library in libraries.values())
    )
    smallest = min((len(library) for library in libraries.values()), default=0)
    spans = tuple(
        runtime_library.keystore_span(library) for library in libraries.values()
    )
    program = key_schedule.build_program(
        generator, sections=tuple(sections), library_size=smallest, keystore_spans=spans
    )
    encoded = key_schedule.encode_program(program)
    decoys = {
        key_schedule.decoy_entry_name(index): key_schedule.new_decoy_entry()
        for index in program.decoy_entries
    }

    root = key_schedule.new_root()
    share_asset = key_schedule.new_share()
    lib_entries: dict[str, bytes] = {}
    for name, library in libraries.items():
        with_digest = runtime_library.write_text_digest(
            runtime_library.write_program(
                runtime_library.write_config(library, config), encoded
            ),
            digests[name],
        )
        gather = _resolver(with_digest, program, share_asset, decoys, package)
        a_state = key_schedule.run_chain(
            bytes(key_schedule.KEY_SIZE), program.chain_a, gather, "a"
        )
        s_state = key_schedule.run_chain(
            bytes(key_schedule.KEY_SIZE), program.chain_s, gather, "s"
        )
        lib_entries[name] = runtime_library.write_keystore(
            with_digest, key_schedule.fold(a_state, s_state, root)
        )
    return root, share_asset, lib_entries, decoys


def _resolver(
    library: bytes,
    program: key_schedule.FoldProgram,
    share_asset: bytes,
    decoys: dict[str, bytes],
    package: bytes,
) -> collections.abc.Callable[[key_schedule.FoldRecord], bytes]:
    """Returns the gatherer of one library's fold inputs, the packer's side of the interpreter.

    Args:
        library: The library with its config and fold program already written.
        program: The fold program the library carries.
        share_asset: The asset share to ship as the s.bin entry.
        decoys: The decoy entries the program names, by APK entry name.
        package: The app's package name, which the runtime reads from its APK's install path.

    Returns:
        A function that returns the 32 bytes each fold record's source holds, the same values the
        runtime gathers from the shipped library and APK.
    """

    def resolve(record: key_schedule.FoldRecord) -> bytes:
        if record.kind == key_schedule.KIND_TEXT:
            return hashlib.sha256(runtime_library.text_region(library)).digest()
        if record.kind == key_schedule.KIND_SECTION:
            return hashlib.sha256(
                runtime_library.section_region(
                    library, key_schedule.SECTION_NAMES[record.param]
                )
            ).digest()
        if record.kind == key_schedule.KIND_RANGE:
            return hashlib.sha256(
                library[record.param32 : record.param32 + record.param]
            ).digest()
        if record.kind == key_schedule.KIND_SHARE:
            return share_asset
        if record.kind == key_schedule.KIND_REGION:
            return hashlib.sha256(runtime_library.config_region(library)).digest()
        if record.kind == key_schedule.KIND_GATES:
            return key_schedule.CLEAN_GATES
        if record.kind == key_schedule.KIND_CONSTANT:
            return program.constants[record.param]
        if record.kind == key_schedule.KIND_PACKAGE:
            return hashlib.sha256(package).digest()
        return hashlib.sha256(
            decoys[key_schedule.decoy_entry_name(record.param)]
        ).digest()

    return resolve


def _encrypt_payload(
    business: tuple[split_module.BusinessDex, ...],
    root: bytes,
    generator: random.Random,
) -> tuple[bytes, bytes, dict[str, bytes]]:
    """Encrypts the class map, the Java program, and the business dexes under the schedule.

    The map and the Java program are sealed under keys derived from the root alone: the loader needs them before the
    stub can arm. Every business dex is sealed under the armed master — the dex seed bound to the Java share the
    program's steps produce on a real runtime — and then under the sensor guard of a clean process. Each frame's
    nonce is fresh, and its key is derived from the nonce and the frame's own APK entry name.

    Args:
        business: The business dexes the splitter produced.
        root: The schedule's root key.
        generator: The source of randomness for this app's Java program.

    Returns:
        The map frame, the Java program frame, and the encrypted business dexes by APK entry name.
    """
    map_nonce = cipher.new_nonce()
    map_key = key_schedule.frame_key(root, map_nonce, MAP_ENTRY)
    map_frame = cipher.encrypt(
        map_key, map_nonce, loader_map.build(business).encode("utf-8")
    )

    program = java_program.build_program(generator)
    program_nonce = cipher.new_nonce()
    program_key = key_schedule.frame_key(root, program_nonce, JAVA_PROGRAM_ENTRY)
    program_frame = cipher.encrypt(
        program_key, program_nonce, java_program.encode_program(program)
    )

    armed = key_schedule.armed_master(
        key_schedule.seed_from(root, map_frame),
        java_program.run_reference(program),
    )
    guard = key_schedule.guarded_master(armed, key_schedule.CLEAN_SENSORS)
    dex_entries: dict[str, bytes] = {}
    for dex in business:
        entry = ASSET_PREFIX + dex.path
        nonce = cipher.new_nonce()
        key = key_schedule.frame_key(guard, nonce, entry)
        dex_entries[entry] = cipher.encrypt(key, nonce, dex.data)
    return map_frame, program_frame, dex_entries


def _aab_native_abis(aab: aab_archive.Aab) -> set[str]:
    """Returns the ABIs the AAB ships native libraries for under ``base/lib/``."""
    abis: set[str] = set()
    for name in aab.names():
        parts = name.split("/")
        if (
            len(parts) == 4
            and parts[0] == "base"
            and parts[1] == "lib"
            and parts[3].endswith(".so")
        ):
            abis.add(parts[2])
    return abis
