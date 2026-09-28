"""Compile and actually load an encrypted JVM class; compile Android API26+ integration."""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


@unittest.skipUnless(shutil.which("javac") and shutil.which("java"), "JDK required")
class ClassLoaderTest(unittest.TestCase):
    def testEncryptedClass_authenticatesBeforeDefinition(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp = pathlib.Path(directory)
            source = tmp / "Payload.java"
            source.write_text('package privateapp; public final class Payload { public static int value() { return 987654; } }')
            payload = tmp / "private"
            runtime = tmp / "runtime"
            payload.mkdir()
            runtime.mkdir()
            subprocess.run(["javac", "--release", "11", "-d", str(payload), str(source)], check=True)
            sources = list((ROOT / "hardener/java-runtime/src/main/java").rglob("*.java"))
            subprocess.run(["javac", "--release", "11", "-d", str(runtime), *map(str, sources)], check=True)
            key = tmp / "key"
            key.write_bytes(bytes(range(32)))
            package = tmp / "Payload.raj"
            subprocess.run(["java", "-cp", str(runtime), "dev.ostorlab.rasp.PackClass", str(key), "privateapp.Payload", str(payload / "privateapp/Payload.class"), str(package)], check=True)
            harness = tmp / "Harness.java"
            harness.write_text(r'''
import dev.ostorlab.rasp.*;
import java.nio.file.*;
import java.util.*;
public final class Harness {
    public static void main(String[] args) throws Exception {
        byte[] key=Files.readAllBytes(Path.of(args[0])), envelope=Files.readAllBytes(Path.of(args[1]));
        EncryptedClassLoader loader=new EncryptedClassLoader(Harness.class.getClassLoader(), name -> envelope, name -> key);
        Object result=loader.loadClass("privateapp.Payload").getMethod("value").invoke(null);
        if (!result.equals(987654)) throw new AssertionError("wrong class result");
        for (int mode=0;mode<4;mode++) {
            byte[] bad=envelope.clone(), wrongKey=key.clone();
            String name="privateapp.Payload";
            if (mode==0) bad[bad.length-1]^=1;
            if (mode==1) name="privateapp.Other";
            if (mode==2) wrongKey[0]^=1;
            if (mode==3) bad=Arrays.copyOf(bad,bad.length-1);
            final byte[] bytes=bad, secret=wrongKey;
            EncryptedClassLoader rejected=new EncryptedClassLoader(Harness.class.getClassLoader(), ignored -> bytes, ignored -> secret);
            try { rejected.loadClass(name); throw new AssertionError("unauthenticated class loaded"); }
            catch(ClassNotFoundException expected) {}
        }
        System.out.println("authenticated class executed; four invalid packages refused");
    }
}
''')
            subprocess.run(["javac", "--release", "11", "-cp", str(runtime), "-d", str(runtime), str(harness)], check=True)
            result = subprocess.run(["java", "-Xverify:all", "-cp", str(runtime), "Harness", str(key), str(package)], check=True, capture_output=True, text=True)
            self.assertIn("four invalid packages refused", result.stdout)

    def testAndroidLoader_api26Surface_compiles(self) -> None:
        android_jar = os.environ.get("ANDROID_JAR")
        if android_jar is None:
            self.skipTest("ANDROID_JAR required; JVM loader execution still runs")
        with tempfile.TemporaryDirectory() as directory:
            sources = [ROOT / "hardener/java-runtime/src/main/java/dev/ostorlab/rasp/AuthenticatedPackage.java", ROOT / "hardener/android-runtime/src/main/java/dev/ostorlab/rasp/EncryptedDexLoader.java"]
            subprocess.run(["javac", "--release", "8", "-cp", android_jar, "-d", directory, *map(str, sources)], check=True)
