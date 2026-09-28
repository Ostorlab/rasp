# Private server protection agents

The Python and Node integrations attach to actual runtime sinks. Install hooks
at process startup, then enter a trusted application-defined request scope.
Scopes isolate tenants and concurrent async requests. Denials carry bounded
structured events containing tenant/request/sink/reason, never raw SQL, command
arguments, request values, or file contents.

Supported sinks in this slice:

| Runtime | Process | Files | Network | SQL | Deserialization |
| --- | --- | --- | --- | --- | --- |
| CPython 3.10+ | Audit events, executable allowlist; shell denied | Audited opens restricted to roots | Socket-connect address checks | SQLite connections/cursors, plus `check_sql` for other drivers | Pickle global resolution |
| Node 22+ | Builtin child-process hooks | Builtin callback/sync/promise file methods | Socket-connect and resolved DNS address checks | `protectSqlClient` for query-style drivers | Not intercepted |

These are instrumentation controls, not an in-process sandbox against arbitrary
code already executing in the service. Install before application imports or
connections capture sink references. Native extensions, direct syscalls, and
other uninstrumented APIs need their own adapters. File checks resolve existing
symlinks but do not replace OS permissions or eliminate concurrent symlink races.
Existing file descriptors are capabilities opened by the application.
Python protected file opens require absolute paths because CPython's audit event
does not expose a relative open's `dir_fd`.

SQL checks reject decoded request values interpolated into statement text and
allow parameter binding. This is bounded source-value correlation, not complete
taint propagation through arbitrary transformations. Pass the actual decoded
values used by the sink. Parameterized queries remain the primary defense.

## Python

```python
from rasp_agent import agent

agent.install()  # before application imports
policy = agent.Policy(allowed_roots=("/srv/application/uploads",))

with agent.request_scope("trusted-tenant-id", "request-id", (decoded_name,), policy) as scope:
    cursor.execute("select * from users where name=?", (decoded_name,))
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
rasp.withRequest({tenantId, requestId, sources: [decodedName]}, policy, () =>
  database.query('select * from users where name=$1', [decodedName]));
```

Use `allowedRoots`, `allowedExecutables`, and exact `allowedAddresses` for trusted
capabilities. Network hooks validate resolver output immediately before connect,
including custom resolver callbacks. Unix sockets are denied in protected scopes.
The adapter checks SQL text, preserving values/callbacks passed separately.

## Virtual patches

An administrator supplies trusted, versioned SCA component PURLs and reviewed
rules mapping an exact affected PURL to a vulnerability identifier and sink.
Selected rules disable that sink in protected requests until the component is
upgraded. This intentionally blocks the affected feature rather than claiming
to recognize every exploit payload. Rules and SCA data must not come from the
requesting client. Test identifiers such as CVE-2099-0001 are fictional fixtures,
not vulnerability claims.

Java, .NET, Go, PHP and eBPF integrations are separate deliverables; this slice
does not mark those runtime agents complete.
