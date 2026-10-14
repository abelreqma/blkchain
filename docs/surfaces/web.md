# Web surface

The web surface assesses web applications and APIs. Beyond the engagement
executor it includes a static-analysis engine that reconstructs an application's
API surface from its own JavaScript, a collection pipeline for traffic and
source, an acquisition layer that characterizes an origin, an isolated browser
with authenticated role support, and scoped replay.

Executor: `cli/webexec.go`. Analysis engines: `cli/internal/webanalysis`,
`cli/internal/webcollect`, `cli/internal/webacquire`. Persona: `web` in
`cli/domains.go`.

## Capabilities

Reconnaissance and testing:

- Confirm liveness, identify the server, and read TLS; discover routes and paths;
  discover parameters and endpoints; run finding-driven probes.
- Test to the OWASP WSTG method: map the application, virtual hosts, routes,
  methods, parameters, forms, roles, and trust boundaries; establish a baseline
  request and response per important flow; test authentication, session handling,
  access control and IDOR, injection, SSRF, file handling, deserialization,
  request smuggling, CORS, GraphQL, and client-side execution; compare behavior
  across roles and object identifiers, testing both the denial and the
  successful-access path; prove impact with the minimum representative data.
- Run `nmap` for bounded service fingerprinting, `ffuf` for discovery, `curl` for
  request-level tests, and `sslscan` or `openssl s_client` for TLS.

Static analysis of application source (`cli/internal/webanalysis`):

- Parse JavaScript, TypeScript, and TSX (tree-sitter plus BishopFox `jsluice`)
  and run a lexical-scope data-flow analysis over the result.
- Reconstruct API operations, the `fetch`, XHR, and axios calls an application
  makes, into method, path, and parameters, merging operations seen more than
  once, and refuse to fabricate an operation that cannot be resolved from the
  source.
- Extract credentials, identify libraries and versions, derive subdomains, and
  serialize the syntax tree on request.

Collection and acquisition:

- Capture traffic archives, recover source maps so analysis runs on the original
  source, parse HTML, and perform bounded imports (`cli/internal/webcollect`).
- Characterize an origin's headers, cookies, CORS policy, methods, and a fixed
  set of well-known metadata paths (robots, sitemap, security.txt,
  openid-configuration, oauth-authorization-server, openapi.json, swagger.json,
  graphql, service-worker, and others), each census run alongside random
  same-host controls; analyze TLS and WebSocket surfaces
  (`cli/internal/webacquire`).

Browser, roles, and replay:

- Drive an isolated browser (Playwright) to navigate, inspect, and capture through
  the same destination and redirect broker as the command path.
- Run authenticated collection under a named role from a loopback Chrome CDP
  import: only cookies for the selected host and local storage for that exact
  origin enter a new isolated context, parent-domain cookies are narrowed to the
  selected host, other origins and WebAuthn credentials are not copied, and the
  source Chrome never performs target traffic; a request to another in-scope
  origin strips the imported credentials and records an anonymous role.
- Replay requests within scope, preserving the body representation, through the
  broker checks.

External-surface sweep:

- From a recon task naming an HTTP origin, run the code-owned sweep and store each
  result as a provenance-bound surface record: TLS, headers, cookies, CORS,
  methods, metadata paths, and subdomains, TLS first because its certificate names
  feed subdomain derivation.

Burp, where the operator runs one:

- A direct surface's brokered HTTP and WebSocket requests traverse a loopback
  intercepting proxy when the operator names one in `BLKCHAIN_WEB_PROXY` and its
  CA certificate in `BLKCHAIN_WEB_PROXY_CA`, so Burp sees the requests the stack
  makes. There is no default address. The isolated browser's own page loads
  are not proxied. A pivoted surface takes no upstream proxy, because the foothold
  carrier it dials through is what an upstream proxy would replace.
- A web-surface task is additionally offered the tools of a configured Burp MCP
  server, and only a web-surface task is. Its three request tools go through the
  same gate as a native web request, so an out-of-scope host, an unarmed
  state-changing method, an action class the RoE does not list, and a port recon
  has not observed are each refused. `send_http2_request` is read in Burp's own
  schema, with its method and path taken from `pseudoHeaders`. All three are
  refused while a foothold carries the web surface, because Burp sends from the
  operator's host rather than through the foothold. A request that names a host
  other than its connection target, in its `Host` header, request target or
  `:authority`, is refused unless that host is in scope. Its reads of proxy history, scanner issues
  and Collaborator interactions are available and are not filtered by engagement
  scope. Its instrument-state and configuration-dump tools are not registered.
- `send_to_intruder` stages a request in an Intruder tab; the fuzzing traffic
  leaves when an operator starts the attack in Burp, outside the gate and the
  engagement's caps.

Recon and the collection above are read-only. Actions that need credentials,
state change, or deeper validation move to an exploit or post-exploitation task,
which is arm-gated. The surface is carried from a foothold over SSH and command
carriers, which forward the binary TCP stream the web broker needs.

## Future expansion

- Own-parser coverage for web findings, so they derive from dedicated parsers
  rather than a single tool's output shape, matching the provenance-bound surface
  records the sweep already produces.
- Access-control and IDOR comparison across roles driven automatically by the
  reconstructed API operation set rather than by prompt.
- Client-side coverage (postMessage, WebSocket message injection, browser storage)
  as explicit recon steps rather than finding-driven probes.
- GraphQL introspection and operation reconstruction as a first-class step, given
  the metadata sweep already probes the `/graphql` path.
- Scope-filtered Burp reads, so proxy history returned to a task carries only the
  engagement's own traffic. The wrapper passes Burp's text through unaltered
  today, because the shape it would have to parse changes with Burp.

The shared engagement model (the command gate, the Auto and Safe arming modes,
vantage reachability, the isolated runner, foothold carriers, and evidence
recording) is described in [the index](README.md).
