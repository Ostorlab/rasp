# iOS runtime artifact

The packer embeds one prebuilt artifact into every app. It comes from the
runtime build (see `runtime/README.md`), not from the packer, and it is not in
the repository. The packer looks for it in this folder:

- `RaspRuntime.framework` — the iOS runtime framework. The packer makes the
  app's main executable load it (`@rpath/RaspRuntime.framework/RaspRuntime`),
  embeds it under the app's `Frameworks/`, and writes the runtime config, which
  holds the build id, into the `__DATA,__rasp_config` section of its
  `RaspRuntime` binary.

Without it, `resources.framework()` raises `InvalidRuntimeError`.

Ship `RaspRuntime.framework/RaspRuntime.capabilities.json` with the pristine framework, as
staged by `cmake --install ... --component runtime`. The packer validates its byte digest
before inserting config. It removes the pristine sidecar from the copied, modified framework
and returns source-artifact provenance to the caller. Invalid present metadata raises
`InvalidRuntimeError`; missing metadata permits legacy packing with unknown capabilities.
