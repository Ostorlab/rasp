# iOS runtime artifact

The packer embeds one prebuilt artifact into every app. It comes from the
runtime build, not from the packer, and is placed here:

- `RaspRuntime.framework` — the iOS runtime framework. The packer makes the
  app's main executable load it (`@rpath/RaspRuntime.framework/RaspRuntime`),
  embeds it under the app's `Frameworks/`, and writes the build identity
  (`RaspAppId`, `RaspBuildId`) into its `Info.plist`.

Until the runtime build writes it here, `resources.framework()` raises
`InvalidRuntimeError`.
