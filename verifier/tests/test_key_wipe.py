"""Execute the native non-elidable wipe under optimizing compilers."""

import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
CPP = ROOT / "flutter_rasp/android/src/main/cpp"
JAVA = pathlib.Path("/usr/lib/jvm/java-17-openjdk-amd64/include")


@unittest.skipUnless(
    shutil.which("gcc") is not None and (JAVA / "jni.h").exists(),
    "C compiler and JNI headers required",
)
class KeyWipeTest(unittest.TestCase):
    def testWipeSecret_whenOptimized_erasesEveryByte(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / "wipe.c"
            source.write_text(
                '#include "rasp_jni.c"\nint main(void) { unsigned char secret[65]; for (unsigned i=0; i<65; ++i) secret[i]=255; wipe_secret(secret, sizeof(secret)); for (unsigned i=0; i<65; ++i) if(secret[i]!=0) return 1; return 0; }\n'
            )
            for flags in (["-O3"], ["-O3", "-flto"]):
                with self.subTest(flags=flags):
                    binary = root / "wipe"
                    subprocess.run(
                        [
                            "gcc",
                            *flags,
                            "-Werror=implicit-function-declaration",
                            "-ffunction-sections",
                            "-fdata-sections",
                            "-I",
                            str(CPP),
                            "-I",
                            str(JAVA),
                            "-I",
                            str(JAVA / "linux"),
                            str(source),
                            "-Wl,--gc-sections",
                            "-ldl",
                            "-o",
                            str(binary),
                        ],
                        check=True,
                        capture_output=True,
                    )
                    subprocess.run([str(binary)], check=True, capture_output=True)
