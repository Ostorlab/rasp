# Third-party notices

This repository includes, or ships in its build output, the following third-party software. Each is used under the
licence named here; the full licence texts are at the links.

| Component | Where | Used for | Licence |
|---|---|---|---|
| [TF-PSA-Crypto](https://github.com/Mbed-TLS/TF-PSA-Crypto) 1.1.1 | `runtime/third_party/tf-psa-crypto/` | The cryptography of the runtime, linked into `librasp.so` and `RaspRuntime` | [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0) (dual-licensed Apache-2.0 OR GPL-2.0-or-later; used under Apache-2.0) |
| [LLVM libc++ and libc++abi](https://libcxx.llvm.org/) 23.1.3 | `runtime/third_party/libcxx/` | The C++ standard library of the iOS runtime, linked into `RaspRuntime` | [Apache-2.0 WITH LLVM-exception](https://llvm.org/LICENSE.txt) |
| [O-MVLL](https://github.com/open-obfuscator/o-mvll) 1.11.0 | `runtime/third_party/omvll/` | A clang plugin that obfuscates the Android runtime at build time; it is a build tool and is not shipped | [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0) |
| [CPython](https://www.python.org/) 3.10 standard library | inside the O-MVLL archive, `runtime/third_party/omvll/` | The Python library the O-MVLL plugin runs its configuration with, at build time; it is not shipped | [PSF License Agreement](https://docs.python.org/3.10/license.html) |
