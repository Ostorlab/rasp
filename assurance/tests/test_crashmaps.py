from __future__ import annotations

import contextlib
import io
import pathlib
import stat
import tempfile
import unittest
from unittest import mock

from cryptography import exceptions
from rasp_assurance import crashmaps


class CrashMapTest(unittest.TestCase):
    def testSymbolize_whenTraceContainsInvalidUtf8_preservesReadableSymbols(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            artifact = root / "app.so"
            artifact.write_bytes(b"fixture")
            key_file = root / "key"
            key_file.write_bytes(b"k" * 32)
            binding = crashmaps.context("tenant", "app", "build", artifact)
            archive = root / "map.rmap"
            archive.write_bytes(
                crashmaps.seal(b'{"_r123":"detector"}', b"k" * 32, binding)
            )
            trace = root / "trace"
            trace.write_bytes(b"_r123+0x10 \xff")
            output = io.StringIO()
            arguments = [
                "rasp-crashmap",
                "symbolize",
                "--tenant",
                "tenant",
                "--app",
                "app",
                "--build",
                "build",
                "--artifact",
                str(artifact),
                "--archive",
                str(archive),
                "--key-file",
                str(key_file),
                "--trace",
                str(trace),
            ]
            with mock.patch("sys.argv", arguments), contextlib.redirect_stdout(output):
                status = crashmaps.main()
        self.assertEqual(status, 0)
        self.assertIn("detector+0x10", output.getvalue())
        self.assertIn("\ufffd", output.getvalue())

    def testArchive_whenRoundTrip_resolvesOnlyWholeSymbols(self) -> None:
        key, binding = b"k" * 32, b"tenant/app/build/artifact"
        data = crashmaps.seal(b'{"_r123":"rasp_detector"}', key, binding)
        self.assertNotIn(b"rasp_detector", data)
        mapping = crashmaps.open_archive(data, key, binding)
        self.assertEqual(
            crashmaps.symbolize("_r123+0x10 _r123suffix", mapping),
            "rasp_detector+0x10 _r123suffix",
        )

    def testArchive_whenWrongContextKeyOrTamper_refuses(self) -> None:
        data = crashmaps.seal(b'{"a":"real"}', b"k" * 32, b"context")
        for archive, key, binding in [
            (data, b"k" * 32, b"other"),
            (data, b"z" * 32, b"context"),
            (data[:-1] + bytes([data[-1] ^ 1]), b"k" * 32, b"context"),
        ]:
            with self.assertRaises((ValueError, exceptions.InvalidTag)):
                crashmaps.open_archive(archive, key, binding)

    def testArchive_whenPersisted_privateAndImmutable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = crashmaps.archive(pathlib.Path(directory), b"encrypted", b"binding")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                crashmaps.archive(pathlib.Path(directory), b"replacement", b"binding")
            self.assertEqual(path.read_bytes(), b"encrypted")

    def testContext_whenArtifactChanges_bindingChanges(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifact = pathlib.Path(directory) / "app.so"
            artifact.write_bytes(b"original")
            first = crashmaps.context("tenant", "app", "build", artifact)
            artifact.write_bytes(b"patched")
            self.assertNotEqual(
                first, crashmaps.context("tenant", "app", "build", artifact)
            )

    def testUpload_whenCleartextUrl_rejectsBeforeSending(self) -> None:
        with self.assertRaises(ValueError):
            crashmaps.upload("http://127.0.0.1/private", b"RCM1", "secret")

    def testUpload_whenArchiveIsTruncated_rejectsBeforeConnecting(self) -> None:
        for data in (b"RCM1", b"RCM1" + b"x" * 31):
            with (
                self.subTest(length=len(data)),
                mock.patch.object(
                    crashmaps.http.client, "HTTPSConnection"
                ) as connection,
            ):
                connection.return_value.getresponse.return_value.status = 201
                with self.assertRaises(ValueError):
                    crashmaps.upload(
                        "https://artifacts.example.test/private", data, "fixture-token"
                    )
                connection.assert_not_called()
