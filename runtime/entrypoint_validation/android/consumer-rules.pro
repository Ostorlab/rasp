# Preserve the existing sole injected bridge API; this source package defines no native methods.
-keep class co.ostorlab.rasp.RuntimeBridge { *; }
-keep class co.ostorlab.rasp.RuntimeBridge$* { *; }
-keep class co.ostorlab.rasp.RaspStub { *; }
# Keep the API35-only body isolated from API31 class verification and optimizer inlining.
-keep class co.ostorlab.rasp.entry.EntryPointValidation$Api35 { *; }
