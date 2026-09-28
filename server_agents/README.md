# Scoped Python and Node server protection agents

**Server protection agents** are request-scoped runtime controls that refuse
unapproved process, file, and private network operations and suspicious SQL
source interpolation. Denials raise `Blocked` and emit a bounded event containing
tenant, request, sink, and reason, never raw SQL, command arguments, request
values, or file contents.

Install hooks at process startup, then enter a trusted application-defined request
scope. Scopes isolate tenants and concurrent async requests.

Supported sinks in this release:

| Runtime | Process | Files | Network | SQL | Deserialization |
| --- | --- | --- | --- | --- | --- |
| CPython 3.10+ | Audit events, executable allowlist; shell denied | Audited opens, deletes, renames, links, copies and directory listing restricted to roots | Socket-connect address checks | SQLite connections/cursors, plus `check_sql` for other drivers | Pickle global resolution |
| Node 22+ | Builtin child-process hooks | Builtin callback/sync/promise file methods | Socket-connect and resolved DNS address checks | `protectSqlClient` for query-style drivers | Not intercepted |

These are instrumentation controls, not an in-process sandbox against arbitrary
code already executing in the service. Install before application imports or
connections capture sink references. Native extensions, direct syscalls, and
other uninstrumented APIs need their own adapters. File checks resolve existing
symlinks but do not replace OS permissions or eliminate concurrent symlink races.
Existing file descriptors are capabilities opened by the application.
Python protected file operations require absolute paths, including calls using
`dir_fd`, because an open audit event does not expose its directory descriptor.
Relative symlink targets are resolved against the link's parent and both link
and target must stay within allowed roots. Node checks callback, sync, and promise
forms of deletion, rename, copy, linking, directory listing, opens and streams.
Python import discovery can list the current module directory, and actual module
loading can read only its source and derived bytecode paths. These exceptions are
active only inside the import machinery; direct loader/resource reads and normal
directory listing still require an allowed root. Protected imports skip bytecode
cache writes. Import hooks use CPython's import machinery and are instrumentation,
not a sandbox against code that replaces runtime hooks.

SQL checks use token boundaries to correlate decoded request values with statement
structure. Values shorter than three characters, identifier substrings, and
contents contained entirely in a quoted literal or comment are ignored. Values
spanning tokens or occupying a whole unquoted token are denied; separately bound
parameters remain allowed. This is **bounded source-value correlation**, matching
decoded request values against statement text, not complete taint propagation
through arbitrary transformations or a complete SQL parser. Pass the actual decoded
values used by the sink. Parameterized queries remain the primary defense.

The packages are unpublished. For local Python use, run
`pip install -e server_agents/python` from the repository root. For Node, run
`npm install /path/to/rasp/server_agents/node`
from your application's directory so `require('@ostorlab/rasp-agent')` resolves.

## Python

```python
from rasp_agent import agent

agent.install()  # before application imports
policy = agent.Policy(allowed_roots=("/srv/application/uploads",))

try:
    with agent.request_scope("trusted-tenant-id", "request-id", (decoded_name,), policy) as scope:
        cursor.execute("select * from users where name=?", (decoded_name,))
except agent.Blocked as denied:
    log_and_return_403(denied.event)  # application-owned request boundary handler
```

An empty executable/root allowlist denies those sinks during protected requests.
Private network destinations are denied unless explicitly allowlisted by CIDR.
Resolve names first; connect checks apply to actual IP addresses. Async context
propagates through tasks; explicitly propagate context when using worker threads.
Applications define tenant identity from verified authentication, not a caller's
tenant header, and handle `agent.Blocked` as a denial at the request boundary.

## Node

```javascript
const rasp = require('@ostorlab/rasp-agent');
rasp.install();
rasp.protectSqlClient(database);
const policy = {
  allowedRoots: ['/srv/application/uploads'],
  allowedExecutables: [], allowedAddresses: [], deniedSinks: []
};
rasp.withRequest({tenantId, requestId, sources: [decodedName]}, policy, () =>
  database.query('select * from users where name=$1', [decodedName]));
```

Use `allowedRoots`, `allowedExecutables`, and exact `allowedAddresses` for trusted
capabilities. Network hooks validate resolver output immediately before connect,
including custom resolver callbacks. Unix sockets are denied in protected scopes.
The adapter checks SQL text, preserving values/callbacks passed separately.

## How do virtual patches block vulnerable components?

**Virtual patches** disable a vulnerable sink in protected requests for an exact
affected component PURL until the component is upgraded. An administrator supplies
trusted, versioned SCA component PURLs and reviewed rules mapping the exact
affected PURL to a vulnerability identifier and sink. This intentionally blocks
the affected feature rather than claiming
to recognize every exploit payload. Rules and SCA data must not come from the
requesting client. Test identifiers such as CVE-2099-0001 are fictional fixtures,
not vulnerability claims.

Java, .NET, Go, PHP and eBPF integrations are separate deliverables; this release
does not mark those runtime agents complete.
