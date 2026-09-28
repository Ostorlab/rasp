# Private protection console

The self-hosted console lets operators publish signed protection policies, watch
rollouts, restore policies, rotate secrets and signing keys, and inspect scoped
installs, events, delivery records, and audit history. It ships as static files
with no external assets. No SDK or console package is published.

The backend contract and local deployment instructions are in
[backend-control-plane.md](../docs/backend-control-plane.md). All reads and
mutations require a server-configured principal with an application grant.

## How do I serve and proxy the console?

Serve the files and proxy `/v1/console/` to the control-plane API on the same
origin. `Dockerfile` provides nginx on port 8080. Its `trust:8080` upstream names
the control-plane service's Docker hostname; change `nginx.conf` if your backend
uses another hostname. Configure TLS at ingress and bind demo ports to loopback.
The UI does not accept a tenant override; the server binds tenant and role grants.

## How are credentials handled?

Credentials stay in tab memory, travel as bearer headers, and clear on disconnect
or rejected authentication. The UI uses no browser persistence, credential URLs,
analytics, or remote scripts. Mutation confirmations precede policy publication,
rollout, restoration, secret changes, and key rotation. Authorization is enforced
by the backend for every request. No sample metrics are bundled.

## How do I run the browser contract tests?

Run from `console/`:

```sh
npm ci
npx playwright install chromium
npm test
```

Contract tests use controlled HTTP responses, including empty/error states,
pagination, mutation confirmation, session isolation, and malformed navigation.
Screenshots are test artifacts. A plain `python3 -m http.server 4173 --bind
127.0.0.1` serves assets but does not proxy the backend.

## How do I run the live integration test?

Set `RASP_CONSOLE_LIVE_URL` to the loopback backend URL,
`RASP_CONSOLE_LIVE_APP` to a dedicated test application, and
`RASP_CONSOLE_LIVE_TOKEN` to its administrator credential, then run `npm test`.
The test publishes a policy, creates a secret version, and reads audit records
through real backend requests. It mutates that dedicated application's state.
Without these settings, only the live case is skipped. CI provisions an isolated
backend and runs this case alongside the contract suite.
