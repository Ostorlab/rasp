"""Smoke the real Gradle plugin and execute its artifact with JVM bytecode verification."""
from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
GRADLE = pathlib.Path(os.environ.get("GRADLE_HOME", "/nonexistent")) / "bin/gradle"


@unittest.skipUnless(GRADLE.is_file(), "GRADLE_HOME required for JVM integration")
class GradlePluginTest(unittest.TestCase):
    def testPlugin_hardenedArtifact_reproducibleAndExecutable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            plugin = ROOT / "hardener/gradle-plugin"
            (root / "settings.gradle").write_text(f"pluginManagement {{ repositories {{ mavenCentral(); gradlePluginPortal() }}; includeBuild('{plugin.as_posix()}') }}\nrootProject.name = 'fixture'\n")
            (root / "build.gradle").write_text('''plugins { id 'dev.ostorlab.rasp.hardening' }
java { sourceCompatibility = JavaVersion.VERSION_11; targetCompatibility = JavaVersion.VERSION_11 }
tasks.named('hardenClasses') {
    seed = providers.gradleProperty('raspSeed').map { Long.parseLong(it) }
    methods = [providers.gradleProperty('raspMethod').getOrElse('demo/Example#compute(II)I')]
    probeOwner = 'demo/Guard'
}
''')
            source = root / "src/main/java/demo"
            source.mkdir(parents=True)
            (source / "Guard.java").write_text('''package demo;
public final class Guard { public static int probe(int site) { return Boolean.getBoolean("rasp.test.tamper") ? 1 : 0; } }
''')
            (source / "Example.java").write_text('''package demo;
public final class Example {
    public static int compute(int x, int y) { int a = x + 123456; if ((x & 1) == 0) a ^= y; else a -= 7; return a; }
    public static void main(String[] args) { for(int x=0;x<100;x++) System.out.println(compute(x, x*17)); }
}
''')
            command = [str(GRADLE), "-p", str(root), "--no-daemon", "--offline", "hardenedJar"]
            environment = dict(os.environ)
            built = subprocess.run(command + ["-PraspSeed=123"], capture_output=True, text=True, env=environment)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            jar = root / "build/libs/fixture-hardened.jar"
            first = jar.read_bytes()
            java = pathlib.Path(os.environ["JAVA_HOME"]) / "bin/java"
            plain = subprocess.run([str(java), "-Xverify:all", "-cp", str(root / "build/classes/java/main"), "demo.Example"], check=True, capture_output=True).stdout
            hardened = subprocess.run([str(java), "-Xverify:all", "-cp", str(jar), "demo.Example"], check=True, capture_output=True).stdout
            self.assertEqual(plain, hardened)
            tampered = subprocess.run([str(java), "-Xverify:all", "-Drasp.test.tamper=true", "-cp", str(jar), "demo.Example"], check=True, capture_output=True).stdout
            self.assertNotEqual(tampered, hardened)
            subprocess.run(command + ["-PraspSeed=123", "--rerun-tasks"], check=True, capture_output=True, env=environment)
            self.assertEqual(first, jar.read_bytes())
            subprocess.run(command + ["-PraspSeed=456"], check=True, capture_output=True, env=environment)
            self.assertNotEqual(first, jar.read_bytes())
            missing = subprocess.run(command + ["-PraspSeed=456", "-PraspMethod=demo/Example#missing()I"], capture_output=True, text=True, env=environment)
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn("Selected methods not found", missing.stderr)
