"""Pack real independent ELF programs, never mocks of ELF rewriting."""

from __future__ import annotations

import pathlib
import shutil
import stat
import subprocess
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric import ed25519

from rasp_elf import protocol

try:
    from rasp_elf import packer
except ImportError:
    packer = None

SOURCE = r"""
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <dlfcn.h>
int main(int argc, char **argv) {
    const char *message = argc > 1 ? argv[1] : "clean";
    if (strcmp(message, "connect") == 0) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in address = {0};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = htons((unsigned short)atoi(argv[2]));
        if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) { perror("app-connect"); return 8; }
        puts("APP:connected");
        close(fd);
        return 0;
    }
    if (strcmp(message, "prepare") == 0) {
        int (*prepare)(const void *, size_t, char *, size_t) = dlsym(RTLD_DEFAULT, "rasp_prepare_request");
        if (prepare == NULL) return 10;
        char evidence[8192];
        int length = prepare("amount=5000", 11, evidence, sizeof(evidence));
        if (length < 0) return 11;
        if (fwrite(evidence, 1, (size_t)length, stdout) != (size_t)length) return 12;
        return 0;
    }
    if (strcmp(message, "checkpoint") == 0) {
        int (*checkpoint)(const void *, size_t) = dlsym(RTLD_DEFAULT, "rasp_checkpoint");
        if (checkpoint == NULL || checkpoint("amount=5000", 11) != 0) return 9;
        puts("APP:approved");
        return 0;
    }
    printf("APP:%s\n", message);
    fflush(stdout);
    if (strcmp(message, "wait") == 0) sleep(8);
    return strcmp(message, "exit") == 0 ? 7 : 0;
}
"""


class PackerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.assertIsNotNone(packer, "ELF packer is not implemented")
        self.temp = tempfile.TemporaryDirectory(prefix="rasp elf test ")
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.publisher = ed25519.Ed25519PrivateKey.generate()
        self.source = self.root / "target.c"
        self.source.write_text(SOURCE)
        self.input = self.root / "demo"
        subprocess.run(
            ["gcc", "-Wall", "-Wextra", "-Werror", str(self.source), "-ldl", "-o", str(self.input)],
            check=True,
            capture_output=True,
        )

    def pack(self, source: pathlib.Path | None = None, **kwargs: object) -> pathlib.Path:
        output = self.root / "protected"
        packer.pack(source if source is not None else self.input, output, self.publisher, **kwargs)
        return output

    def execute(
        self, executable: pathlib.Path, *args: str, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(executable), *args], text=True, capture_output=True, check=False, timeout=10, env=env
        )

    def testPacker_whenCleanPIE_runsOriginalProgramWithoutPreload(self) -> None:
        original = self.input.read_bytes()
        output = self.pack()
        result = self.execute(output / "demo", "hello world")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("APP:hello world\n", result.stdout)
        self.assertEqual(original, self.input.read_bytes())
        dynamic = subprocess.run(
            ["readelf", "-d", str(output / "demo")], text=True, capture_output=True, check=True
        ).stdout
        self.assertIn("$ORIGIN/librasp_runtime.so", dynamic)
        self.assertEqual(
            "rasp-elf-manifest-1",
            protocol.validate_manifest((output / "rasp.manifest").read_bytes(), protocol.public_hex(self.publisher))[
                "v"
            ],
        )

    def testPacker_whenNonPIEStripped_preservesExitCode(self) -> None:
        subprocess.run(["gcc", "-no-pie", "-s", str(self.source), "-ldl", "-o", str(self.input)], check=True)
        output = self.pack()
        result = self.execute(output / "demo", "exit")
        self.assertEqual(7, result.returncode, result.stderr)
        self.assertEqual("APP:exit\n", result.stdout)

    def testPacker_whenBundleRelocated_runsWithCompanions(self) -> None:
        output = self.pack()
        moved = self.root / "another directory"
        shutil.move(str(output), moved)
        self.assertEqual(0, self.execute(moved / "demo").returncode)

    def testPacker_whenExecutableModified_blocksBeforeMain(self) -> None:
        output = self.pack()
        with (output / "demo").open("ab") as stream:
            stream.write(b"modified")
        result = self.execute(output / "demo")
        self.assertEqual(173, result.returncode, result.stderr)
        self.assertEqual("", result.stdout)
        self.assertIn("tamper", result.stderr)

    def testPacker_whenRuntimeModified_blocksBeforeMain(self) -> None:
        output = self.pack()
        with (output / "librasp_runtime.so").open("ab") as stream:
            stream.write(b"modified")
        result = self.execute(output / "demo")
        self.assertEqual(173, result.returncode, result.stderr)
        self.assertEqual("", result.stdout)

    def testPacker_whenManifestMissing_blocksBeforeMain(self) -> None:
        output = self.pack()
        (output / "rasp.manifest").unlink()
        result = self.execute(output / "demo")
        self.assertEqual(173, result.returncode, result.stderr)
        self.assertEqual("", result.stdout)

    def testPacker_whenManifestModified_blocksBeforeMain(self) -> None:
        output = self.pack()
        manifest = output / "rasp.manifest"
        manifest.write_bytes(manifest.read_bytes().replace(b"interval_ms=250", b"interval_ms=251"))
        result = self.execute(output / "demo")
        self.assertEqual(173, result.returncode, result.stderr)
        self.assertEqual("", result.stdout)

    def testPacker_whenRuntimeMissing_loaderRefusesToRun(self) -> None:
        output = self.pack()
        (output / "librasp_runtime.so").unlink()
        result = self.execute(output / "demo")
        self.assertNotEqual(0, result.returncode)
        self.assertEqual("", result.stdout)

    def testPacker_whenForeignArchitecture_rejectsInput(self) -> None:
        blob = bytearray(self.input.read_bytes())
        blob[18:20] = (183).to_bytes(2, "little")
        self.input.write_bytes(blob)
        with self.assertRaisesRegex(ValueError, "x86"):
            self.pack()
        self.assertFalse((self.root / "protected").exists())

    def testPacker_whenNotELF_rejectsInput(self) -> None:
        self.input.write_bytes(b"this is not an ELF")
        with self.assertRaisesRegex(ValueError, "ELF"):
            self.pack()

    def testPacker_whenSharedLibrary_rejectsInput(self) -> None:
        subprocess.run(["gcc", "-shared", "-fPIC", str(self.source), "-ldl", "-o", str(self.input)], check=True)
        with self.assertRaisesRegex(ValueError, "executable"):
            self.pack()

    def testPacker_whenPrivilegedExecutable_rejectsInput(self) -> None:
        self.input.chmod(self.input.stat().st_mode | stat.S_ISUID)
        with self.assertRaisesRegex(ValueError, "setuid"):
            self.pack()

    def testPacker_whenOutputExists_refusesOverwrite(self) -> None:
        output = self.root / "protected"
        output.mkdir()
        marker = output / "keep"
        marker.write_text("user data")
        with self.assertRaises(FileExistsError):
            self.pack()
        self.assertEqual("user data", marker.read_text())

    def testPacker_whenAlreadyPacked_rejectsRepacking(self) -> None:
        output = self.pack()
        with self.assertRaisesRegex(ValueError, "already"):
            packer.pack(output / "demo", self.root / "twice", self.publisher)

    def testPacker_whenReportInspected_verifiesHashesAndPublisherSignature(self) -> None:
        output = self.pack()
        report = packer.inspect(output, protocol.public_hex(self.publisher))
        self.assertTrue(report["verified"])
        self.assertEqual("software", report["evidence_trust"])
        self.assertIn("connect", report["instrumentation"])
        with (output / "demo").open("ab") as stream:
            stream.write(b"modified")
        with self.assertRaisesRegex(ValueError, "hash"):
            packer.inspect(output, protocol.public_hex(self.publisher))

    def testPacker_whenKeygenCalled_keepsPrivateKeysOutsideBundle(self) -> None:
        keys = self.root / "keys"
        packer.keygen(keys)
        self.assertEqual(0o600, stat.S_IMODE((keys / "publisher.key").stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE((keys / "backend.key").stat().st_mode))
        output = self.pack()
        for path in output.iterdir():
            self.assertNotIn(protocol.private_hex(self.publisher).encode(), path.read_bytes())
        self.assertEqual(4, len(list(keys.iterdir())))

    def testPacker_whenStaticExecutable_rejectsInput(self) -> None:
        self.source.write_text("int main(void) { return 0; }\n")
        subprocess.run(["gcc", "-static", str(self.source), "-o", str(self.input)], check=True, capture_output=True)
        with self.assertRaisesRegex(ValueError, "static"):
            self.pack()
        self.assertFalse((self.root / "protected").exists())

    def testPacker_whenSystemUtilityPacked_preservesBehavior(self) -> None:
        cases = (
            ("/usr/bin/true", []),
            ("/usr/bin/false", []),
            ("/usr/bin/printf", ["hello %s\n", "world"]),
            ("/usr/bin/echo", ["hello world"]),
            ("/usr/bin/cat", ["/dev/null"]),
            ("/usr/bin/head", ["-n", "1", str(self.source)]),
            ("/usr/bin/ls", ["--version"]),
        )
        for source, arguments in cases:
            with self.subTest(source=source):
                original = subprocess.run([source, *arguments], check=False, capture_output=True)
                output = self.root / (pathlib.Path(source).name + "-bundle")
                packer.pack(pathlib.Path(source), output, self.publisher)
                protected = subprocess.run(
                    [str(output / pathlib.Path(source).name), *arguments], check=False, capture_output=True, timeout=5
                )
                self.assertEqual(
                    (original.returncode, original.stdout, original.stderr),
                    (protected.returncode, protected.stdout, protected.stderr),
                )
