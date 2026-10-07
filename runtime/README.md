# Runtime

The C++ runtime libraries that the packer adds to a protected app. They run the checks inside the app and report what they observe to the ADR server.

## Layout

- `core/`: code shared by every platform. It uses no platform API.
- `ios/`: `RaspRuntime.framework`, the runtime for iOS, and its entry point.
- `tests/`: tests that run on a development machine, with GoogleTest.

## Build

CMake 3.28 or newer. The presets are in `CMakePresets.json`.

On a development machine, with the tests:

```
cd runtime
cmake --preset host
cmake --build --preset host
ctest --preset host
```

For an iOS device (arm64), on a Mac with Xcode:

```
cd runtime
cmake --preset ios
cmake --build --preset ios
```

The framework is written to `build/ios/ios/RaspRuntime.framework`. Its install name is `@rpath/RaspRuntime.framework/RaspRuntime`, which the packer adds to the app's load commands. The framework exports no symbols: the code runs from a constructor when the app loads it.

CI runs both builds (`.github/workflows/runtime.yml`).
