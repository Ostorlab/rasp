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
