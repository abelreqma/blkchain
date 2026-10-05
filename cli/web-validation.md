# Web engagement validation

Validation date: 2026-10-05, America/Los_Angeles.
Branch: `fix/web-engagement-limitations`, rebased onto local main at `d88eb0f`.

| Area | Implemented behavior | Validation status |
| --- | --- | --- |
| Wayback pagination | Parse embedded CDX resume rows, reject malformed keys, stop repeated keys and cap three pages | Controlled fixtures pass. Public example.com index and second resume page pass. |
| Wayback throttling | Shared process-wide one-request-per-second pacing covers queries, captures and retries; retry 429/503 once and respect bounded Retry-After | Concurrent timing, cancellation and identity tests pass. The default Go User-Agent receives HTTP 429; the fixed blkChain identity receives HTTP 200. |
| Missing captures | Preserve unavailable index/body responses as coverage gaps | Controlled fixtures and live indexed HTTP 200 body, empty missing-capture index and missing HTTP 404 body checks pass. |
| HTTP replay | Explicit stored-example adapters preserve text, JSON, form, multipart and binary body bytes | Local HTTP fixture verifies byte equality through the shared command handler. Missing HAR wire bytes remain gaps. |
| WebSocket exchanges | Match an operator-supplied send/expect transcript with negotiated subprotocol, opcode and exact bytes | Controlled GraphQL subscription exchange passes. Mismatch, denied sends, cancellation and limits fail closed. No remote application subscription was tested. |
| Roles and state | Require supplied roles and credentials; persist unavailable roles and browser-only state as gaps | Missing-role persistence and target-filtered gap tests pass. Unknown roles and application states remain unavailable. |
| Assisted browser | Consume one assistance window per role job, cap 120 seconds, capture DOM after assistance | Limit rejection is tested. Live headed interaction, challenge completion and post-assistance DOM capture remain unverified. |
| Evidence grades | Supply grades with explanations in JSON; distinguish HTTP responses, cached responses, WebSocket handshakes, messages and validated exchanges | Record and TUI-dispatch tests pass. No probability calibration was performed. Text rendering awaits approval of the terminal preview. |

The full Go suite and vet pass. Race-enabled tests cover the CLI and the web
analysis, collection and broker packages. The Python suite passes 277 tests.
The archive-specific live LLM acceptance passes with the local retrieval stack.
These checks do not establish browser isolation or headed assistance.

Browser provisioning variables were unset in this session. No shared service was
restarted or reconfigured. Provisioned browser and headed-assistance checks remain outstanding.

The public-service attempt used:

```sh
BLKCHAIN_WAYBACK_E2E=1 go test ./internal/webcollect -run '^TestWaybackPublicServiceE2E$' -v -count=1
```

It now passes both index pages, the indexed body and the missing-capture checks.
The test remains opt-in and fails if any required provider check is unavailable.
A 429 or transfer error cannot satisfy the missing-body HTTP 404 check.

## Discovered credential output

Discovered passwords and secret values are retained in structured finding records,
live engagement JSON events, `evidence/web/findings.jsonl`, and both report formats.
The evidence value is separate from the detector's unvalidated credential status.
Control characters are escaped reversibly rather than redacted. Tests cover short
passwords, spaces, quotes, backticks, newlines, source/role provenance, stdout/log
agreement, report refresh without a plan mutation, concurrent finding events and
TUI output without ending the running engagement.

API keys, tokens, client secrets, private-key blocks, connection strings, cookie
headers and exposed environment/configuration values use the same unredacted
finding pipeline. Controlled-target tests verify these values across live stdout,
the JSONL log and both report formats. Unresolved environment references remain
gaps and do not read values from the runner's environment.

## Wayback rate verification

All archive requests in one blk process share a serialized request gate. The next
request starts at least one second after the preceding request finishes, including
requests from different Archive instances and retries. Queued requests cancel
without reaching the provider. Separate blk processes have independent gates.

A controlled server measured three concurrent query/capture/retry requests with
at least one second between arrivals. Archive regression tests cover resume rows,
malformed indices, version preservation, redirects, unavailable captures and
bounded provider backoff. The earlier public failure persisted because archive requests used Go's default
`Go-http-client/1.1` identity. A matched HTTP/1.1 request to the same CDX URL
returned an immediate nginx HTTP 429 with that identity and no Retry-After. An
honest `blkChain/1.0 (Wayback archive collection)` identity returned HTTP 200.
The adapter now supplies that fixed identity to queries, captures and retries.
Its infrastructure policy permits only this exact header; target cookies,
authorization and caller-supplied identities remain denied. No rate limit was
relaxed. The matched response files are local diagnostic evidence, not a claim
about Wayback's internal configuration.

## Local stack acceptance

The opt-in `TestWaybackLocalLLMStack` verifies live dense/sparse retrieval and
reranking from `blkchain_dwq`, two public CDX pages, an indexed capture, exact
stored body bytes, capture timestamps in CLI and TUI inspection, native
`web_inspect` tool calling, and report generation. The local model
`supergemma4-26b-uncensored-mlx-4bit-v2` called the tool once in two rounds and
reported timestamp `20020120142510` as historical evidence with current
availability unvalidated. The body contained 6,814 bytes. Thinking was disabled.

```sh
BLKCHAIN_COLLECTION=blkchain_dwq OMLX_MODEL=supergemma4-26b-uncensored-mlx-4bit-v2 BLKCHAIN_WAYBACK_LLM_E2E=1 go test . -run '^TestWaybackLocalLLMStack$' -v -count=1
```

This acceptance checks archive acquisition, stored inspection and model
interpretation. It does not establish browser collection, challenge completion,
remote WebSocket application behavior or current behavior of archived targets.
MCP engagement snapshot/persistence and formatted evidence-grade display remain
separate outstanding items from the earlier web engagement audit.
