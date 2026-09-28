# Scoped Python and Node server protection agents

**Server protection agents** are request-scoped runtime controls for process,
file, private-network, SQL, and deserialization sinks, including suspicious SQL
source interpolation. Coverage differs by runtime as shown below. Denials raise
`Blocked` and emit a bounded event containing tenant, request, sink, and reason,
never raw SQL, command arguments, request values, or file contents.

Install hooks at process startup, then enter a trusted application-defined request
scope. Scopes isolate tenants and concurrent async requests.

Supported sinks in this release:

| Runtime | Process | Files | Network | SQL | Deserialization |
| --- | --- | --- | --- | --- | --- |
| CPython 3.10+ | Audit events, executable allowlist; shell denied | Allowed roots restrict audited opens, deletes, renames, links, copies, and directory listing | Socket-connect address checks | SQLite connections/cursors, plus `check_sql` for other drivers | Pickle global resolution |
| Node 22+ | Builtin child-process hooks | Allowed roots restrict hooked opens, deletes, renames, links, copies, directory listing, and streams (callback/sync/promise where available) | Socket-connect and resolved DNS address checks | `protectSqlClient` for query-style drivers | Not intercepted |

Java, .NET, Go, PHP, and eBPF integrations are separate deliverables and are not
implemented by these packages.

## What can these controls not do?

These controls check instrumented runtime sinks and do not provide complete process isolation.

- Instrumentation is not an in-process sandbox against arbitrary code already
  executing in the service. Install before application imports or connections
  capture sink references; code that replaces runtime hooks can bypass them.
- Native extensions, direct syscalls, and other uninstrumented APIs need their
  own controls or adapters.
- File checks resolve existing and dangling symlinks, but do not replace OS
  permissions or eliminate concurrent symlink races. Existing file descriptors
  are capabilities opened by the application. Relative symlink targets are
  resolved against the link's parent. Creating links requires both the link and
  its target to stay within allowed roots.
- Python protected file operations require absolute paths, including calls using
  `dir_fd`, because an open audit event does not expose its directory descriptor.
- Python import discovery can list the current module directory; actual module
  loading can read only its source and derived bytecode paths. These exceptions
  operate inside import machinery. Direct loader/resource reads and normal
  directory listing still require an allowed root. Protected imports skip bytecode
  cache writes.
- SQLite interception supports the default connection factory, exact
  `sqlite3.Connection` (replaced with `agent.Connection`), and exact
  `agent.Connection`. Custom connection subclasses/factories are rejected.
  Cursors use exact `agent.Cursor`; custom cursor factories/subclasses are rejected
  because overriding execution could bypass SQL checks.

## How are SQL source values checked?

SQL checks use **bounded source-value correlation** to match decoded request
values against statement text at token boundaries. Values shorter than three
characters, identifier substrings, and contents contained entirely in a quoted
literal or comment are ignored. Values spanning tokens or occupying a whole
unquoted token are denied. This does not track arbitrary transformations and is
not a complete SQL parser; pass the actual decoded values used by the sink.

Parameterized queries remain the primary SQL injection defense. Values bound
separately from the statement stay allowed, including values that would be denied
if interpolated into SQL structure.

## How do I install the unpublished packages locally?

Both packages are unpublished; install from a checkout of this repository.

For Python, run from the repository root:

```sh
python3 -m pip install -e server_agents/python
```

For Node, run from your application's directory, replacing the checkout path:

```sh
npm install /path/to/rasp/server_agents/node
```

## How do I protect a Python request?

Install hooks at startup, enter a scope with trusted identity and decoded values,
then handle `agent.Blocked` at the request boundary.

This self-contained SQLite example returns a status and body for an HTTP handler
to send. The fixed tenant identifier stands in for verified application authentication.

```python
import logging
import sqlite3

from rasp_agent import agent

agent.install()  # before application code captures sink references
policy = agent.Policy(allowed_roots=("/srv/application/uploads",))
database = sqlite3.connect(":memory:")
database.execute("create table users (name text)")
cursor = database.cursor()
decoded_name = "alice"

def handle_request() -> tuple[int, str]:
    try:
        with agent.request_scope("trusted-tenant-id", "request-id", (decoded_name,), policy):
            cursor.execute("select * from users where name=?", (decoded_name,))
            return 200, str(cursor.fetchall())
    except agent.Blocked as denied:
        logging.warning("RASP denial: %s", denied.event)
        return 403, "Forbidden"

try:
    status, body = handle_request()
    print(status, body)
finally:
    database.close()
```

Python operational rules:

- Empty executable and root allowlists deny those path/process sinks during protected requests.
- Private network destinations are denied unless explicitly allowed by trusted CIDRs.
- Resolve names first; socket-connect checks apply to the actual IP addresses.
- Async context propagates through tasks. Explicitly propagate context when using worker threads.
- Obtain tenant identity from verified authentication, not a caller's tenant header.
  Handle `agent.Blocked` as a denial at the application request boundary.

## How do I protect a Node request?

Install hooks at startup, wrap the SQL client, then run each request in
`withRequest` and handle `rasp.Blocked` at its boundary.

This standalone HTTP example uses Node's SQLite module (Node 22.13+). The fixed
tenant identifier stands in for verified application authentication.

```javascript
const rasp = require('@ostorlab/rasp-agent');
rasp.install();
const http = require('node:http');
const { DatabaseSync } = require('node:sqlite');
const sqlite = new DatabaseSync(':memory:');
sqlite.exec('create table users (name text)');
const database = rasp.protectSqlClient({
  query(statement, values) { return sqlite.prepare(statement).all(...values); }
});
const policy = {
  allowedRoots: ['/srv/application/uploads'],
  allowedExecutables: [], allowedAddresses: [], deniedSinks: []
};
const tenantId = 'trusted-tenant-id';
let requestSequence = 0;
http.createServer((request, response) => {
  const requestId = String(++requestSequence);
  const decodedName = new URL(request.url, 'http://localhost').searchParams.get('name') || '';
  try {
    const rows = rasp.withRequest({ tenantId, requestId, sources: [decodedName] }, policy,
      () => database.query('select * from users where name=?', [decodedName]));
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify(rows));
  } catch (error) {
    if (!(error instanceof rasp.Blocked)) throw error;
    console.warn('RASP denial:', error.event);
    response.writeHead(403, { 'Content-Type': 'text/plain' });
    response.end('Forbidden');
  }
}).listen(8080);
```

Node operational rules:

- Use `protectSqlClient` for query-style database drivers; SQL is not automatically intercepted.
- `allowedRoots`, `allowedExecutables`, and exact `allowedAddresses` grant trusted
  capabilities. Empty root/executable allowlists deny those path/process sinks.
- Network hooks validate resolver output immediately before connection. Custom
  resolvers receive `(hostname, options, callback)` and may call the callback or
  return a Promise with an address/family object or an `all` array. Default/rest
  parameters are supported. Callback resolvers can return `undefined`; other
  non-Promise custom return values fail closed. Only the first completion is
  checked and delivered. A resolver that never completes cannot establish a
  connection; applications still need connection timeouts and cancellation.
- Unix sockets are denied in protected scopes.
- `protectSqlClient` checks SQL text and preserves separately passed values,
  callbacks, and the underlying client's return value.

## How do virtual patches block vulnerable components?

**Virtual patches** disable a vulnerable sink in protected requests for an exact
affected component Package URL (PURL) until the component is upgraded. Supply a
trusted Software Bill of Materials (SBOM) and reviewed rules mapping the exact
affected PURL to a vulnerability identifier and sink. This blocks the affected
feature rather than claiming to recognize every exploit payload. Rules and SBOM
data must not come from the requesting client.

The Python on-ramp is SBOM and rules, then `patches.select`, then `agent.Policy`:

```python
from rasp_agent import agent
from rasp_agent import patches

sbom = {"components": [{"purl": "pkg:pypi/example@1.0"}]}
rules = [{
    "vulnerabilityId": "CVE-2099-0001",
    "purl": "pkg:pypi/example@1.0",
    "sink": "deserialization",
}]
selected = patches.select(sbom, rules)
policy = agent.Policy(denied_sinks=selected.denied_sinks)
```

`patches.select` is currently Python-only. Node accepts the equivalent reviewed
sink array in `deniedSinks`, for example `{ deniedSinks: ['sql'] }`, for its
implemented sinks. Test identifiers such as CVE-2099-0001 are fictional fixtures,
not vulnerability claims.
