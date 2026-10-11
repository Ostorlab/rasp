# iOS runtime artifact

The packer embeds one prebuilt artifact into every app. It comes from the
runtime build, not from the packer. The release workflow
(`.github/workflows/release.yml`) builds it and commits it here, on the release
tag only:

- `RaspRuntime.framework` — the iOS runtime framework. The packer makes the
  app's main executable load it (`@rpath/RaspRuntime.framework/RaspRuntime`),
  embeds it under the app's `Frameworks/`, and writes the build id
  (`RaspBuildId`) into its `Info.plist`.

`main` doesn't have it, so outside a release `resources.framework()` raises
`InvalidRuntimeError`.
