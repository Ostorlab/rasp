/// Test-only declaration for the Android API-level boundary, backed by the JVM fixture's simulated SDK_INT.
#pragma once

/// Reads the simulated SDK level for compiled production identity dispatch; never linked into shipped artifacts.
/// @return The fixture SDK value, or -1 on JNI failure.
extern "C" int android_get_device_api_level();
