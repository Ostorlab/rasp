"""Build harmless real D8/R8 multidex APK/AAB inputs, without signing or device operations."""

import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import zipfile


def _run(arguments: list[str]) -> None:
    subprocess.run(
        arguments,
        check=True,
        env={**os.environ, "JAVA_TOOL_OPTIONS": "-XX:ActiveProcessorCount=2"},
    )


def _jar(
    output: pathlib.Path, classes: pathlib.Path, names: list[pathlib.Path]
) -> None:
    with zipfile.ZipFile(output, "w") as archive:
        for name in sorted(names):
            archive.write(name, name.relative_to(classes).as_posix())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("--bridge", required=True, type=pathlib.Path)
    parser.add_argument(
        "--sdk",
        type=pathlib.Path,
        default=pathlib.Path(
            os.environ.get("ANDROID_HOME", pathlib.Path.home() / "Android/Sdk")
        ),
    )
    arguments = parser.parse_args()
    source = pathlib.Path(__file__).resolve().parent
    output: pathlib.Path = arguments.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    tools = arguments.sdk / "build-tools/35.0.1"
    android = arguments.sdk / "platforms/android-35/android.jar"
    classes = output / "classes"
    classes.mkdir(exist_ok=True)
    java = sorted((source / "src").rglob("*.java"))
    _run(
        [
            "javac",
            "--release",
            "8",
            "-g",
            "-encoding",
            "UTF-8",
            "-classpath",
            os.pathsep.join((str(android), str(arguments.bridge))),
            "-d",
            str(classes),
            *map(str, java),
        ]
    )
    extra = classes / "fixture/external/Extra.class"
    _jar(output / "extra.jar", classes, [extra])
    _jar(
        output / "program.jar",
        classes,
        [path for path in classes.rglob("*.class") if path != extra],
    )
    extra_dex = output / "extra-dex"
    plain_dex = output / "plain-dex"
    release_dex = output / "release-dex"
    for directory in (extra_dex, plain_dex, release_dex):
        directory.mkdir(exist_ok=True)
    _run(
        [
            str(tools / "d8"),
            "--min-api",
            "31",
            "--lib",
            str(android),
            "--output",
            str(extra_dex),
            str(output / "extra.jar"),
        ]
    )
    _run(
        [
            str(tools / "d8"),
            "--min-api",
            "31",
            "--lib",
            str(android),
            "--lib",
            str(arguments.bridge),
            "--classpath",
            str(output / "extra.jar"),
            "--output",
            str(plain_dex),
            str(output / "program.jar"),
        ]
    )
    _run(
        [
            "java",
            "-XX:ActiveProcessorCount=2",
            "-cp",
            str(tools / "lib/d8.jar"),
            "com.android.tools.r8.R8",
            "--release",
            "--min-api",
            "31",
            "--lib",
            str(android),
            "--lib",
            str(arguments.bridge),
            "--lib",
            str(output / "extra.jar"),
            "--pg-conf",
            str(source / "keep.pro"),
            "--pg-map-output",
            str(output / "mapping.txt"),
            "--output",
            str(release_dex),
            str(output / "program.jar"),
        ]
    )
    for protobuf in (False, True):
        base = output / ("manifest-proto.apk" if protobuf else "manifest.apk")
        _run(
            [
                str(tools / "aapt2"),
                "link",
                "--manifest",
                str(source / "AndroidManifest.xml"),
                "-I",
                str(android),
                "--min-sdk-version",
                "31",
                "-o",
                str(base),
                *(["--proto-format"] if protobuf else []),
            ]
        )
        for label, dex in (("plain", plain_dex), ("r8", release_dex)):
            target = output / f"{label}.{'aab' if protobuf else 'apk'}"
            with (
                zipfile.ZipFile(base) as original,
                zipfile.ZipFile(target, "w") as archive,
            ):
                if protobuf:
                    archive.writestr("BundleConfig.pb", b"")
                for name in original.namelist():
                    path = (
                        "base/manifest/AndroidManifest.xml"
                        if protobuf and name == "AndroidManifest.xml"
                        else f"base/{name}"
                        if protobuf
                        else name
                    )
                    archive.writestr(path, original.read(name))
                prefix = "base/dex/" if protobuf else ""
                archive.writestr(
                    prefix + "classes.dex", (dex / "classes.dex").read_bytes()
                )
                archive.writestr(
                    prefix + "classes2.dex", (extra_dex / "classes.dex").read_bytes()
                )
                if protobuf:
                    archive.writestr(
                        "feature/assets/unchanged.txt", b"unrelated feature asset\n"
                    )
    inputs = [
        *java,
        source / "AndroidManifest.xml",
        source / "keep.pro",
        arguments.bridge,
        android,
        tools / "lib/d8.jar",
        tools / "aapt2",
        tools / "dexdump",
    ]
    outputs = [
        output / name
        for name in ("plain.apk", "plain.aab", "r8.apk", "r8.aab", "mapping.txt")
    ]
    manifest = {
        "expected_log": "PK02_RESULT=42 PACKAGE_PRIVATE_OK",
        "art_execution": "NOT RUN",
        "signing": "NOT RUN",
        "toolchain": "Android SDK35 / build-tools 35.0.1; javac --release 8",
        "sha256": {
            str(path): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in inputs + outputs
        },
    }
    (output / "fixture.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"output": str(output), "art_execution": "NOT RUN"}))


if __name__ == "__main__":
    main()
