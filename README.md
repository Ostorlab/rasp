# rasp

Production source of Ostorlab Mobile RASP: the **packer**, and the **runtime libraries** it puts inside a customer's app.

- **The packer** (Python) takes a customer's built app, an APK or an IPA, and adds the runtime to it. It returns the protected app unsigned, and the customer signs it before shipping it.
- **The runtime libraries** (C++) run inside the protected app, on Android and on iOS. They run the checks (debugger, hooking, jailbreak and root, tampering, and others) and report what they observe to the ADR server.

The ADR server, which receives the reports and decides, is not in this repository.

## Layout

```
packer/                 Python packer: a library, with the `rasp` command line as its client
  src/rasp_packer/
    android/            APK: add the runtime library
    ios/                IPA: add the runtime framework
  tests/
runtime/                C++ runtime libraries, built with CMake
  core/                 code shared by both platforms: observations, batches, sending them to the ADR server
  checks/               the checks: shared code, plus platform-specific files where a check needs them
  android/              Android entry point (JNI) and the .so build
  ios/                  iOS entry point and the RaspRuntime.framework build
  tests/                tests that run on a development machine, without a device
docs/                   notes about this repository
poc/                    the proof of concept, kept for reference
```

Each folder is created by the first pull request that adds code to it.

## The `poc/` folder

`poc/` holds the proof of concept that came before this production code: the Flutter plugin and its demo bank app, the reference trust service (`verifier/`), the build-time hardener, the Linux ELF packer, and the assurance and server-agent tools. See [`poc/README.md`](poc/README.md).

It is kept for reference only:

- Production code never imports from `poc/`.
- Ideas from the proof of concept are reviewed and rewritten for production, not copied as they are.
- The proof of concept's CI still runs, so it keeps working as a reference.

## Design

The design is described in the `Ostorlab/design-docs` repository:

- *Mobile RASP*: the packer and the protection it adds.
- *RASP Runtime — Checks and Event Contract*: what the runtime observes, and the message it sends to the ADR server.
- *Mobile ADR*: the ADR server.

## Contributing

Every change goes through a pull request.
