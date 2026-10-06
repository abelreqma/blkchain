# Web JavaScript and API analysis

`blk engage web` and `/engage web` run web assessment through the same Go service. The CLI prints
plain text or structured JSON with exact operation records. The REPL and TUI use the approved icon headings,
terminal theme, and width-aware wrapping. `inspect` reads stored evidence without
visiting the target. Supply an existing workspace or use the latest engagement.

```sh
blk engage web collect engagement.md --workspace ./assessment --browser --auto
blk engage web inspect domain.com --workspace ./assessment --view apis
blk engage web inspect domains.txt --workspace ./assessment --view artifacts
blk engage web inspect 192.0.2.1 --workspace ./assessment --view all
blk engage web analyze --workspace ./assessment
blk engage web import --workspace ./assessment --roe ROE.md --file traffic.har
blk engage web archive domain.com --workspace ./assessment --roe ROE.md
blk engage web export --workspace ./assessment
```

The interactive equivalents include:

```text
/engage web inspect domain.com --view apis
/engage web inspect domains.txt --view features
/engage web inspect engagement.md --view all
/engage web inspect 192.0.2.1 --view artifacts
/engage web collect engagement.md --workspace ./assessment --browser --auto
/engage web export --workspace ./assessment
```

Views are `summary`, `apis`, `artifacts`, `functions`, `features`, `findings`,
`coverage`, `exports`, and `all`. `--json` returns the same structured
records on every surface. Files and workspaces containing spaces accept quotes.
Domain lists accept one domain, URL, or IP per line, with blank lines and `#`
comments. Comma-separated targets and `@domains.txt` are supported. Targets
without a scheme default to HTTPS. `--file` also supplies a target list.

IP inputs retain the IP target and add up to ten reverse-DNS names per IP.
`--no-rdns` disables these lookups. A PTR record never expands scope. CIDRs define
scope and require an explicit bounded list of web hosts for collection.

An engagement Markdown file uses the existing RoE format:

```markdown
# Engagement
## Targets
- https://staging.example.test
## In Scope
- staging.example.test
- 192.0.2.10
## Out of Scope
- production.example.test
## Rate
2/s
```

Collection, archive, replay, and import require the operator RoE. Supply
`--roe`, an engagement Markdown target, or the project's `ROE.md`. The policy
checks hostnames and pins resolved addresses. Authorized private targets work
when the RoE includes them. Auto is the default. Active browser and API actions
require `browser-write` or `api-write` in the RoE; outbound WebSocket messages
use `api-write`, while handshakes use `api-read`. `--task` attributes actions
and evidence to an existing engagement task. The legacy `--scope` flag applies
only to read-only workspace views.

# Collection and evidence

The bounded frontier follows links, frames, executable inline scripts, event
handlers, external responses, imports, import maps, module preloads, manifests,
and supported Webpack/Vite chunk tables. Browser collection additionally captures
runtime DOM and CDP script sources, observed API requests, initiators, frames,
popups, and generated scripts. JSON data scripts remain separate from code.

`--interaction scroll` and `--interaction 'click:#tab'` exercise supplied controls.
Clicks use active-action policy. Unknown dynamic dependencies remain unresolved.
The collector does not treat network idle as complete coverage. Dedicated,
shared, blob, and service workers use the isolated proxy and the Go request
broker. CDP captures worker sources and available initiator/context information.
Cached responses carry separate discovery and validation fields. WebSocket
handshakes and text/binary messages retain connection ids, direction, sequence,
opcode, encoding, and exact artifact bytes. Duplicate messages remain distinct.
The page dwell window is bounded to two seconds; streams close at job completion.
Unavailable source/body metadata and exhausted limits appear in coverage. Detected challenges, denied traffic, omitted HAR bodies,
parser failures, and exhausted limits also appear in coverage.

Use an operator-provisioned isolated headed container for assisted challenges.
The assistance window is consumed once per role job, capped at 120 seconds, and
captures DOM state after the window. Cancellation closes the isolated context.
An elapsed window never proves a challenge was solved.
Set `BLKCHAIN_PLAYWRIGHT_HEADED=1`, then supply `--headed --assist-seconds 60`.
The assistance window defaults to 30 seconds and cannot exceed 120 seconds per
role job. Request policy remains active throughout the window. Provisioning
uses the same verified driver, image, restricted mounts, and network boundary as
headless collection. See [webbrowser-provisioning.md](webbrowser-provisioning.md).

Raw blobs live under `evidence/web/blobs/<sha256>` in the engagement workspace.
Directories use mode 0700 and files use mode 0600. Identical content shares one
blob while capture records preserve each URL, role, and version. Metadata and
relationships use additive tables in the existing `engagement.db`. Source-map
names never become output paths. Web evidence is not added to the trusted RAG
corpus. Operation views, request examples, model job results, and JSON exports preserve
exact operation values, including headers, cookies, and request bodies. Artifact
and finding previews still mask detected secrets. Storage remains restricted.

| Limit | Bound |
|---|---|
| Supplied targets | 100 |
| Discovery frontier and broker requests | 500 each |
| Downloaded frontier assets | 200 per role/job |
| Depth, page states, interactions | 3, 30, 20 by default; depth up to 8, states up to 100 |
| Collection time | 3 minutes per role/job; 6 minutes per command |
| Request body | 1 MiB |
| WebSocket messages | 256 KiB per message, 250 messages per connection, 16 connections per proxy |
| Wire response and decoded body | 4 MiB each |
| Aggregate wire and accepted response bytes | 64 MiB each per broker |
| Workspace blobs and metadata | 256 MiB and 32 MiB |
| Metadata record and record count | 1 MiB and 20,000 |
| Parser | one process at a time, 6 second deadline, CPU limit, 16 MiB result |
| AST traversal | 100,000 nodes, depth 128 |
| Source maps | depth 8, 1,000 sources, 16 MiB recovered source bytes, 5 seconds |
| HAR import | 16 MiB, 500 entries, 64 MiB decoded bodies |

# Sessions, analysis, and history

Supply `--session sessions.json` to collect roles independently. Values refer to
environment variable names; the file contains no credentials. An example is:

```json
{
  "roles": [
    {
      "name": "reader",
      "origin": "https://staging.example.test",
      "headers_env": {"Authorization": "STAGING_AUTHORIZATION"},
      "cookies_env": {"session": "STAGING_SESSION"},
      "storage_env": {"selectedAccount": "STAGING_ACCOUNT"}
    }
  ]
}
```

Optional `login` contains a structured browser `submit` action with `url`,
`form_selector`, and `fields` whose values use `${ENV_NAME}` references. Login
requires an armed task and gate permission. `--role reader` selects one supplied
role. Credentials stay bound to that HTTP origin. API replay uses the same
session adapter and current policy; no generated shell command executes.

JSluice and pinned Tree-sitter grammars provide JavaScript, TypeScript, and JSX
analysis. Bounded passes map direct calls, wrappers, function parameters,
destructuring, defaults, XHR, Axios clients, static interceptors, URL expressions,
GraphQL operations/variables, observed WebSocket operations/messages, and EventSource leads. Unknown spreads,
computed origins, conditional interceptors, and unsupported decoder patterns
remain unresolved. Formatting and static transformations preserve original blobs
and record source locations. A sink or secret match is an analysis lead.
Discovered credential values remain exact in finding records and operator output.

Technology findings report source or header signals and unknown versions when
version evidence is absent. Provider patterns and entropy/context candidates use
separate detectors and evidence grades. Discovered passwords and secret values are retained in the finding's `value`
field, with credential type, source URL, artifact, location and role. A password
literal does not need high entropy to become a finding. JSON response fields, embedded JSON state and nonempty HTML password inputs
also produce credential findings. A fingerprint supports correlation; it does
not replace the value. Detection does not establish that a credential works.

During `blk engage`, the CLI and REPL/TUI emit each discovered credential as a
structured JSON event. The same event is appended to
`evidence/web/findings.jsonl`. Reports retain the exact value in `report.json`
and in a JSON block in `report.md`, even when the originating task is unfinished.
The report refreshes when a credential is stored. Control and Unicode characters
use reversible JSON escapes in live output. Passwords are not replaced with masks.
The same output contract covers named API keys, access/client secrets, tokens,
authorization and cookie headers, signing/encryption/private keys, connection
strings, exposed environment assignments and JSON environment objects. Known
provider patterns and entropy/context matches remain additional detectors.
Captured environment documents retain all supplied assignment values, including
ordinary configuration settings, with `environment_variable: true`. Their grade
is `configuration-observed`; sensitivity and runtime use remain unverified.
Assignment records also retain their expression. Variable references that require
runtime resolution remain coverage gaps. The analyzer does not resolve a target's
`process.env` reference using the runner's environment.

The finding log uses mode 0600 and a 32 MiB limit. Individual credential values
are capped at 64 KiB, with larger values retained as a coverage gap and in their
source artifact. `blk engage web collect --json` keeps one final JSON document on stdout;
its findings retain values, and its credential events still go to the JSONL log.

Known-library scanning reads a local Retire-compatible advisory repository.
Set `BLKCHAIN_RETIRE_MANIFEST` to a JSON file containing `path`, `sha256`, `date`
(`YYYY-MM-DD`), and `revision` (40 hexadecimal characters). The repository must
match its SHA256 and remains bounded to 4 MiB. Unsupported extractors and missing
snapshots produce coverage gaps. Advisory findings retain snapshot date, revision,
and hash. Outdated-library findings remain separate from vulnerability findings.
No scanner, runtime, or advisory data downloads during an engagement.

`archive` queries the bounded Wayback CDX adapter, saves distinct content versions,
and selects dependency captures at or before the parent capture time. Capture
and retrieval times remain distinct. Archived source is never executed. Provider
requests contain no target credentials, and private session URLs are excluded.
Use `--resume` with a recorded continuation key when pagination exceeds the job
budget. Missing captures or provider failures preserve existing live evidence.
The adapter accepts the CDX JSON resume rows documented by the
[Wayback CDX API](https://github.com/internetarchive/wayback/blob/master/wayback-cdx-server/README.md).
Archive requests identify themselves as `blkChain/1.0 (Wayback archive collection)`.
The infrastructure policy allows only that fixed User-Agent and rejects target
credentials and other headers.
Every archive index query, capture fetch and retry passes through one shared
process-wide limiter. Requests are serialized, and the next request starts at
least one second after the previous request completes. Concurrent archive jobs
and roles share this limit; there is no burst allowance. Rate waits honor
cancellation and remain inside the request timeout.
It stops on a repeated key, caps jobs at three pages, and retries 429 or 503 once.
It honors Retry-After only within a five-second wait budget; longer waits remain
throttling gaps. Archive responses do not follow redirects to live targets.

Run the opt-in public-service check serially:

```sh
cd cli
BLKCHAIN_WAYBACK_E2E=1 go test ./internal/webcollect -run '^TestWaybackPublicServiceE2E$' -v -count=1
```

It uses public example.com captures to check index access, resume pagination,
an indexed body and a missing capture. Provider outages fail this check and
leave live validation incomplete. Controlled fixtures test throttling; the live
check does not induce rate limits.
Source maps support embedded content, HTTP references, and bounded indexed maps;
logical `webpack://` sources never trigger local-file reads.

# Exports and structured replay

Exports contain JSON with exact operation records and cURL text templates under `evidence/web/exports`.
The command prints the directory. Each template states whether it is replayable
and lists unresolved fields. Credentials use environment references; URL tokens
and body fields use explicit placeholders. Body files have content-addressed
names. Run an exported template from its export directory after filling values.
Shell metacharacters are quoted and control characters are rejected.

```sh
blk engage web export --workspace ./assessment --operation OPERATION_ID
blk engage web replay --workspace ./assessment --roe ROE.md \
  --operation OPERATION_ID --values values.json --session sessions.json \
  --role reader --task EXISTING_TASK --auto
```

`values.json` maps parameter names to strings. Numeric, boolean, object, and array
parameters accept JSON encoded in those strings. Path/query values are encoded
for their URL context. GraphQL variable names are independent parameters.
Unsupported signatures and missing values remain gaps. Select an observed HTTP
request with `--example N` to replay its original body bytes:

```sh
blk engage web replay --workspace ./assessment --roe ROE.md \
  --operation OPERATION_ID --example 1 --session sessions.json \
  --role writer --task EXISTING_TASK --auto
```

Example numbers refer to the operation's stored `examples` array, starting at 1.
Inspect the array with `--view apis --json`. Exact replay accepts text, JSON objects, arrays and scalars,
form bodies, multipart uploads with their captured boundary, and octet-stream
bodies. Other valid media types use an opaque adapter without interpreting or
changing their body bytes. It preserves the captured URL and body bytes. Binary HTTP bodies use
`body_encoding: base64` in records. The adapter decodes them before sending.
`--example` and `--values` cannot be combined. Stored session headers are replaced
with supplied credentials for the selected role and origin. A role absent from
supplied sessions remains a coverage gap. Missing HAR wire bytes, unsupported
encodings, malformed bodies and oversized bodies cannot replay. HAR `_encoding`
may supply `base64` for an exact binary request body. Multipart `params` without
`postData.text` cannot reconstruct the original boundary or file bytes.

Structured cURL export still uses placeholders. For bodies it cannot represent,
it directs the operator to exact example replay instead of emitting an empty
request. HTTP replay uses the scoped broker directly for header/cookie sessions;
login or local-storage sessions require the isolated browser.

WebSocket replay requires an operator-supplied application transcript in
`--values`. The `exact-message` adapter sends and expects bounded text or binary
messages on a negotiated connection. Every expect step compares opcode and exact
bytes. It does not infer application messages, subscription ids or authentication
values. A subscription transcript can supply initialization, acknowledgement,
subscribe and data steps:

```json
{
  "adapter": "exact-message",
  "protocols": ["graphql-transport-ws"],
  "steps": [
    {"send": {"opcode": 1, "body": "{\"type\":\"connection_init\"}"}},
    {"expect": {"opcode": 1, "body": "{\"type\":\"connection_ack\"}"}},
    {"send": {"opcode": 1, "body": "{\"id\":\"one\",\"type\":\"subscribe\",\"payload\":{\"query\":\"subscription { event }\"}}"}},
    {"expect": {"opcode": 1, "body": "{\"id\":\"one\",\"type\":\"next\",\"payload\":{\"data\":{\"event\":\"fixture\"}}}"}}
  ]
}
```

This example follows the [GraphQL WebSocket protocol](https://github.com/enisdenjo/graphql-ws/blob/master/PROTOCOL.md).
It validates only the supplied exchange for its recorded role and time. Variable
response fields require a newly supplied expectation. Binary frames use opcode 2
and `encoding: base64`. Plans allow 20 steps, 256 KiB per frame, 1 MiB total body
bytes, 10 seconds per receive and 30 seconds total. Sends retain armed-task and
scope authorization. Browser-only state requires refreshed header or cookie
credentials for this replay adapter. Failure retains messages and a coverage gap.
HTTP cURL templates never claim WebSocket application validation.

Operation and finding records carry `evidence_grade` with `grade` and
`explanation`. JSON inspection exposes both on CLI and REPL/TUI surfaces. Text-view additions
require approval of the terminal preview.
Grades distinguish discovered, historical, attempted, access, cached response,
HTTP response, WebSocket handshake, message and validated exchange evidence.
Detector findings remain leads, signature detections or advisory matches.
The older finding `confidence` field remains for compatibility and is not a
calibrated probability. No grade represents a percentage. Numerical confidence
requires measurement against a labeled validation dataset.
Historical discovery alone never marks an operation validated. A 401 or 403
records an access response rather than declaring the operation dead.

Engagement reports include web records as an additive section and JSON field.
Model tools expose bounded `web_collect`, `web_analyze`, `web_inspect`, and
`web_export` jobs. Code owns acquisition, parsing, persistence, and cancellation;
the model interprets stored summaries without extending scope or authority.
