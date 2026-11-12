-include ../../../../entrypoint_validation/android/consumer-rules.pro
# Manifest component names and the public source API stay inspectable in this reference fixture.
-keep class fixture.entrypoints.** { *; }
-keep public class co.ostorlab.rasp.entry.EntryPointValidation { public *; }
