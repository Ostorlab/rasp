# Harmless ART fixture

This source fixture uses real SDK35 D8/R8 output, package-private calls, interface dispatch, arrays, a switch, an exception handler, annotations, debug information and independent secondary DEX compilation. R8 relocates business and library classes into `x`. The compile-only RuntimeBridge is never bundled in the input.

Build with JDK17+ and Android SDK platform 35/build-tools 35.0.1:

```sh
python tests/dexsplit/fixtures/app/build.py /tmp/pk02-app --bridge /path/to/runtime-bridge-compile-only.jar
rasp pack /tmp/pk02-app/r8.apk --platform android --build-id pk02-r8 --mapping /tmp/pk02-app/mapping.txt --output /tmp/pk02-app/protected.apk
```

`fixture.json` records source/tool/input/output hashes. Baseline and protected APKs are unsigned. Root's device owner can sign both with a disposable lab key, install baseline then protected APK, and run:

```sh
adb logcat -c
adb shell am start -W -n fixture.protectedapp/.MainActivity
adb logcat -d -s PK02 AndroidRuntime
```

Both executions must log `PK02_RESULT=42 PACKAGE_PRIVATE_OK`, with no VerifyError, IllegalAccessError or ClassNotFoundException. The unprotected baseline logs `BRIDGE=unprotected-baseline`; the protected app must use the actual supplied bridge. Signing, emulator/physical ART execution and AAB-to-split-APK/bundletool installation are separate root-owned gates. Generated AABs test the base-container packer and preserve an unrelated feature asset; they do not establish store/split delivery validity. No device execution is implied by building or parsing these fixtures.
