# Executable module and public loader observations

Revision 10 appends six Android and two physical-iOS identities to the existing
opt-in `hooks` group. It preserves all prior observations and policy predicates.
`hook.exec_modules` / `hook.exec_modules_meta` use independent Android
`proc_maps_v1` and `dl_iterate_phdr_v1` sources, or physical-iOS `dyld_v1`.
Android `hook.loader_chain` / `hook.loader_chain_meta` use
`application_classloader_v1`. Each identity appears once per selected invocation.

These are bounded own-process diagnostics. App/OS/other labels describe lexical
locations, not trusted ownership, code authenticity, malware or attestation.
Legitimate ART/JIT/memfd/in-memory DEX, custom plugins and dyld shared-cache images
can have incomplete loader correlation. No signing-status/csops API, new policy
selector, capture change, host export or enforcement action is added.

Data is a list of at most 32 module records (192 ASCII bytes each), or 16 public
loader-parent records (96 bytes each). Failed, denied, malformed, limited or timed
out collection carries no value; absent platform/context is unsupported. Empty
successful data differs from unavailable. Parsing validates complete bounded
input even after the output sample fills. Android uses the actual permission
field, not letters in a path. Native names are copied in bounded page-aware
chunks, stopping at NUL without reading into an unreadable following page.

Metadata is one fixed ASCII diagnostic of at most 256 bytes, with status `ok` even
when data is unsupported/error/timeout. That status means the diagnostic was
produced. Its fixed ordered fields are `v=1;outcome;reason;seen;eligible;emitted;
sample_truncated;scope;correlation;stability`. Unavailable counts are `na`, and
non-ok data emits zero records. Unknown/missing versions or a lost pair member
must never be interpreted as clean source evidence. Counts and metadata are not
an atomic transport pair. Module records contain only ordinal, location,
backing/permissions/loader relation/deleted-label or executable segment/declared
flag labels; loader records contain depth, reduced kind and parent ordinal.
No raw path, filename, class name, address, path hash or stable module ID is sent
by these new identities. Existing historical hooks retain their own raw evidence.

| Source | Complete-input limits |
| --- | --- |
| Android maps | Two 4 MiB reads plus EOF probe; 8192 records/8192 bytes per line; 2048 attempts/read/eight consecutive EINTR |
| Android native | 4096 images/1024 headers per image/2 MiB headers/4 MiB names/16384 executable intervals |
| Public Application | Base+64 split APK paths; 4096 bytes per path/256 KiB aggregate; paths are transient scope inputs |
| Public topology | Two 16-node passes/256 UTF-16 units per class/64 local refs/≤2048 JNI calls including cleanup |
| dyld | Two 4096-image copied passes/4096 commands/64 KiB commands per image/8 MiB headers and 4 MiB names per pass |

A source has a cooperative 100 ms elapsed-work bound; an entered OS/JNI operation
can block beyond it. No signal handler, cancellation of arbitrary native calls,
unchecked pointer dereference, other-process inventory or exhaustive VM scan is
used. Bracket equality cannot exclude ABA races. iOS reports declarations, not
live VM permissions or every executable mapping. Native APIs remain hookable.

Existing selected reporting plugins automatically serialize/store delivered
observations. Path-free does not mean no upload/persistence or per-signal consent.
PL05 requires the existing explicit HTTPS profile/authority; security refusals do
not select plaintext DNS. Independently selected authorized DNS remains plaintext
and never acknowledges HTTPS storage. The native outbox has 32 slots/4 MiB and
bounded retries/work, but **no finite age TTL, legal-hold/erase API or restored
record suppression**. An old matched record can retry until acknowledged; profile
expiry/authority holds retain it rather than erase it. Strict PL05 transport is
unavailable on iOS 12 despite the preserved native deployment floor; data is held.

Server tenant/build admission, scoped retention/holds/erasure and restore controls
are separate. Native publication acknowledgement is not database retention or
trusted coverage. New backend catalogue adoption is separately reviewed against
the frozen native manifest; older consumers must keep unknown/unregistered state.
No customer deployment/collection or compliance/physical-erasure result follows
from these software fixtures. The [fixture](fixtures/module-provenance-v1.json)
contains exact allocated native shapes and bounds; all historical catalogue blocks
remain unchanged. Apple SDK/device and genuine installed-artifact acceptance must
be recorded on the exact final producer; host fixtures are not device evidence.
