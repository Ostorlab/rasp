# Reproduction and disclosure evidence

This index links methodology and source protocols. It contains no measured device
population, numerical benchmark, market ranking or efficacy certification.

| Evidence | Reproduction scope | Missing evidence |
|---|---|---|
| [Validation protocol](../validation.md) | Bounded result/runner and harmless host/Android fixture procedures | Physical/emulator/Apple execution, attack outcomes, population rates |
| [Host source](../../validation/fixtures/host.c) | Actual production C API startup NOT_READY; no receipt admission | Initialized device detection/denial and effectiveness |
| [Android source](../../validation/fixtures/android/MainActivity.java) | Real bridge API, clean receipt and request-hash rejection protocol | Signed preinstalled owned-lab ALLOW/DENY and verified cleanup |
| [Local-policy contract](../local-policy-contract.md) | Client operation-gate semantics and limitations | Server authorization, authenticated attestation |

A release evidence entry must pin Git head/tree, source archive/map, tool/build
receipt, exact artifacts/policy/suite, all planned device cells, failed controls,
and private reproduction bundle references. Declare redactions without silently
removing failures or changing the denominator. Host/transport tests are not device
measurements. External commercial-shield research does not benchmark this runtime.

Review evidence and customer/secret redactions before any future publication.
Report vulnerabilities privately using [SECURITY.md](../../SECURITY.md); this
runner does not publish or send disclosures.
