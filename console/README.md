# Private protection console

A dependency-free browser application for the scoped control-plane API in
`docs/backend-control-plane.md`. Requires the control-plane backend PR. No SDK or
console package is published.

Serve these static files and proxy `/v1/console/` to the backend on the **same
origin**. `Dockerfile` provides nginx on port 8080 with a `trust:8080` upstream.
Use TLS at the deployment ingress; bind local demonstration ports to loopback.
Configure server-side console principals and their application/role grants in
the backend. The UI never accepts a tenant override.

Credentials live only in tab memory, are sent as a bearer header, and are cleared
on disconnect or rejected authentication. No browser persistence, query-string
credential, analytics, third-party assets, or remote scripts are used. The UI
shows only API responses, including empty/error states; no sample metrics are
bundled. Policy publication, rollout, rollback, secret changes and key rotation
have explicit confirmation. Authorization remains enforced on the server.

`npm ci`, `npx playwright install chromium`, then `npm test` run browser contract
tests against controlled HTTP responses. Screenshots are test artifacts, not
live fleet evidence. Backend integration is validated separately against the
configured local trust service. `python3 -m http.server 4173 --bind 127.0.0.1`
alone serves static assets but does not proxy a backend.
