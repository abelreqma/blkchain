# blkChain

blkChain is a security research and authorized assessment framework. It combines a searchable security knowledge base, model-assisted task orchestration, isolated command execution, browser and API analysis, and a persistent engagement evidence store. Its assessment core, `blk engage`, coordinates bounded tasks under operator-defined rules of engagement. The `blk` terminal client provides one-shot commands, an interactive session, an MCP server, and an HTTP API.

Use it to research techniques, understand an application's exposed sources and traffic, run scoped assessment tasks, and inspect the evidence behind a conclusion.

Start with the [complete setup guide](#complete-setup-guide). For an existing installation, see [answer modes](#research-and-answer-modes), [external surface and advisory scans](#external-surface-and-advisory-scans), [web analysis](#web-application-analysis), and the [engagement store](#engagement-store-and-findings).

## Capabilities

| Area | Current implementation |
| --- | --- |
| Security research | Local dense and BM25 retrieval, RRF fusion, cross-encoder reranking, source filters, bounded answers, specialist prompts, and optional public web research. |
| Assessment orchestration | Task dependencies, specialized executors, Auto and Safe modes, operator-defined rules of engagement, isolated runners, external-surface sweeps, offline dependency scans, action capture, stop, and resume. |
| Web application analysis | Source and traffic collection, JavaScript and source-map analysis, API operation reconstruction, role sessions, workers, cached responses, WebSockets, and scoped replay. |
| Engagement evidence | SQLite tasks, exact quotes, action records, surface observations, scanner advisories, coverage records, finding review states, provenance relationships, and local answers citing selected records. |
| Operator interfaces | Keyboard-driven terminal UI, plain REPL, history, draft editing, context attachments, queued questions, source inspection, model controls, and service diagnostics. |
| Integration | Native MCP tools, an HTTP API, and schema-validated JSON generation through the same Go implementation. |

## Research and answer modes

The research index combines dense embeddings and BM25 sparse vectors in Qdrant. Go queries both vectors, fuses their results with Qdrant RRF, and optionally reranks the candidate pool with a local cross-encoder. Source, type, and payload filters constrain retrieval.

The native answer loop grades source sufficiency, can rewrite the query, and synthesizes an answer from bounded source passages. It supports conversation context, specialist prompts, streaming, per-call usage metrics, and an explicit no-results response. Exact-CVE research can add NVD details and public research when web permission is enabled.

Bare `blk` starts the REPL or TUI in native auto mode. `blk ask QUESTION` also uses native auto by default. Native auto selects a research specialist from the question, then retrieved metadata when the question is ambiguous. Interactive public research turns search live sources before answering when web is enabled:

| Entry point | Behavior |
| --- | --- |
| `blk ask QUESTION` | Uses native answer routing and selects a research specialist dynamically. |
| `blk ask --session ID QUESTION` | Continues a saved conversation. `ID` is a session id, `new` to start one, or `last` for the most recent. Without `--session`, `ask` is stateless and writes no transcript. |
| `blk ask --hermes QUESTION` | Runs one legacy Hermes turn using the external Hermes configuration. It writes no session. |
| `blk ask --agent web QUESTION` | Uses the native web specialist prompt. The specialist name does not itself enable internet access. |
| `blk ask --rag QUESTION` | Forces the native knowledge-base answer path. |
| `blk search QUERY` | Synthesizes a native answer grounded in the search results. |
| `blk search --json QUERY` | Returns ranked chunks without answer synthesis. |
| `blk ask --json QUESTION` | Returns structured native answer output, citations, results, and available call metrics. |

`--json` and `--sources` work with the default native `ask` path. In the interactive session, `/agent NAME` selects a native specialist and `/agent auto` restores dynamic selection. `/hermes PROMPT` runs one legacy Hermes turn. Research specialists change answer guidance. Engagement executors are selected separately from task kind and surface.

`blk ask`, the plain REPL, the TUI, the `chat` tool of `blk mcp`, and the turn endpoints of `blk serve` run the same native turn. One function resolves the session, loads its history, assembles the answer options, routes the question, records tool actions, and saves the turn, so every surface gets the same routing, tools, and persistence. `--hermes` cannot be combined with `--session`, `--agent`, `--rag`, `--web`, `--json`, or `--sources`.

Each session is one append-only JSONL transcript plus a row in the local history database. Every blk process shares them, and a transcript is reconciled with the database when a session is reopened. A session started over MCP or `blk serve` is an ordinary session, so `blk ask --session ID` continues it.

Native chat shares a bounded tool registry across those surfaces. It offers knowledge-base search, playbook routing, file operations, terminal and process control, public web search and extraction, browser control, screenshot analysis, and allowlisted MCP client tools.

File and terminal tools use an empty, persistent Docker sandbox for the current project by default. Use `--tool-host local` for an explicit one-shot local workspace or `/tool-host local` for the interactive session. `file_import` and `file_export` copy only paths named in the current request and never overwrite an existing destination. Text reads are paginated and convert UTF-16, Jupyter notebooks, DOCX, and XLSX to text. Document formats are read-only through the file tools; transfers can carry binary files. Shell processes can continue across chat turns. The sandbox has no network access, so public research and browsing use separate bounded web tools.

`browser_control` keeps an isolated browser across interactive turns. It can navigate, inspect, click, type, scroll, press keys, go back, read console messages, list images, and save screenshots. It requires the provisioned Playwright driver. `browser_vision` requires `BLKCHAIN_VISION_MODEL` to name a vision-capable model on the local LLM endpoint; without one, it returns a clear error. `--browser-cdp` or `/browser-cdp` explicitly copies signed-in state from a loopback Chrome or Brave CDP endpoint into the isolated browser. That path also requires a pinned host Node executable through `BLKCHAIN_BROWSER_NODE_PATH` and `BLKCHAIN_BROWSER_NODE_SHA256`.

Native `file_read` does not extract PDF text or preview SQLite databases. The signed-in browser path copies storage state into an isolated context; it does not control the source browser tabs. Raw CDP commands and JavaScript dialog control are not exposed.

When the user names an IP, host, network, or HTTP URL in the current turn, or refers to a target from the immediately preceding user turn, native chat can run isolated security commands and target-bound API or browser actions. It can choose these tools when the user asks for an action or clearly implies one. Target commands use the audited binary catalog and isolated runner; API and browser requests recheck destinations and redirects. The project `denied_binaries` list still applies. Native chat uses a temporary target scope from the user's own words and does not require `ROE.md`. `blk engage` continues to require its sealed RoE and approvals.

A named target supplies scope for the turn, not service evidence. Before a service-specific action, native chat makes a bounded port-discovery probe and admits the requested action only when that host, transport, and port qualify. The observation lasts for the turn. Explicit local terminal access and configured MCP servers execute outside the built-in target tool gate.

Native chat classifies the user's intent without matching fixed request phrases. A requested tool action gets one retry if the model answers without calling the relevant tool. If it still makes no such call, the turn returns an error instead of reporting an unperformed action as complete. A target action without a user-named target fails before execution.

A fresh REPL/TUI profile enables public web research on first launch. Native one-shot CLI and MCP calls do not enable it automatically. An existing saved `web off` remains off until `blk web on` enables it. `blk web off` disables public research searches, not target-bound chat API or browser actions. Providers include DuckDuckGo and Tavily; Tavily reads `TAVILY_API_KEY` or `TAVILY_SETUP_TOKEN`. Use `blk web provider duckduckgo`, `blk web provider tavily`, or `blk web provider auto` to choose a provider. Permission and provider settings persist locally. Interactive public research turns fail clearly when a required live search is unavailable rather than present local or model knowledge as current. Web-first answer search sends the current question, never attachments or conversation history. The `web_search` tool can send a model-generated query after filtering recognized target identifiers and secret-shaped data. Target-specific advisor turns stay local; explicit `/web search` sends the query the operator enters.

When a native chat turn explicitly calls `web_search` or `web_extract`, blkChain returns the bounded source results as the final answer. It does not substitute an unsupported model summary for those results.

MCP client servers are configured in `~/.config/blkchain/mcp-clients.json`, or the path named by `BLKCHAIN_MCP_CLIENT_CONFIG`. Each server must list `allow_tools`. Stdio servers run in the chat sandbox unless `host` is set to `local` with an absolute command. HTTP servers require HTTPS or a loopback HTTP URL. `env` maps child environment names to existing environment variable names, and `token_env` names an environment variable for HTTP bearer authentication. For example:

```json
{"servers":[{"name":"notes","transport":"stdio","command":"/work/notes-server","allow_tools":["search_notes"]}]}
```

Import the executable into the sandbox before using this stdio example. MCP tool results are treated as untrusted data. The MCP client configuration is separate from the `blk mcp` server.

`cli/mcp-clients.example.json` is a fuller template: a Burp Suite Pro entry reached over the stdio proxy jar Burp ships, with `host` set to `local` because a sandboxed stdio server has no network and could never reach Burp on loopback. Its `allow_tools` lists every tool that server advertises. Seven of them are hazardous and listed deliberately. `send_http1_request` and `send_http2_request` carry the largest consequence: they send requests out through Burp and reach no code-side gate at all. They do not pass the engagement web scope check, the RoE, or Safe-mode approval, so the `allow_tools` list is the only authorization boundary for them, and leaving them in grants a chat turn the ability to reach any host Burp can reach. The injection chain is direct: `get_proxy_http_history_regex` and `get_proxy_websocket_history_regex` return target-controlled bytes into the same turn that can call those two send tools. The remaining five: `output_project_options` and `output_user_options` dump configuration that can carry credentials into model context, `set_project_options` and `set_user_options` rewrite it, and `set_task_execution_engine_state` pauses or resumes the scanner. Remove all seven for a read-mostly setup. Registration fails if a listed tool is absent, so the list has to match the server's version.

The same hazard note belongs in the operator's own `~/.config/blkchain/mcp-clients.json`, since that is the file whose list gets trimmed. The loader ignores unknown top-level keys, so a `_README` string alongside `servers` is carried without affecting configuration.

Hermes is a legacy one-shot, reached through `blk hermes`, `/hermes`, and `blk ask --hermes`. It has its own provider, tools, and permissions, and it writes no blk session. Native web settings and engagement Safe/Auto settings do not control Hermes's own tool execution.

## Engagement harness

`blk engage` plans and executes tasks under an operator-owned rules of engagement (RoE) policy. The model proposes tasks and structured tool arguments. Code applies scope checks, action permissions, command denials, resource limits, and execution routing. Retrieved techniques and citations supply advisory context; they do not grant authority.

Auto is the default and runs actions permitted by the RoE without per-action prompts. Safe requires an interactive approval channel. The RoE names in-scope and excluded targets, permitted action classes, command denials, resource caps, and runner settings. A goal such as "recon only" does not replace those policy permissions. Use explicit action and command restrictions for the intended assessment.

If no policy is found, `blk engage` writes a commented `ROE.md` template in the current directory and stops. Configure its targets and allowed actions before starting a run. Existing policies are not overwritten. `--roe PATH` selects a policy kept elsewhere.

The harness stores tasks, dependencies, provenance, exact evidence quotes, action transcripts, policy decisions, and coverage records in a workspace. Command workers have destination filtering, a read-only root filesystem, bounded writable scratch space, a restricted environment, and CPU, memory, process, output, and time limits. Commands needing raw sockets use a separate worker with that capability. Resume retains the sealed policy, original deadline, and recorded usage. `blk engage --resume WORKSPACE` resumes a run; `blk engage stop --workspace PATH` stops one.

Service-specific commands and web requests require a host, transport, and port observed from the same execution vantage within the past hour. Naming a URL is not evidence. When needed, blkChain runs a bounded discovery probe through the same gate. Scope and RoE checks apply to every action.

A completed Nmap TCP `open` result permits protocol checks. UDP `open|filtered` permits a protocol-correct probe but does not prove a response; a completed version scan, IKEv2 response, or HTTP/3 response can promote the matching candidate to `open`. ACK, FIN, NULL, Xmas, idle, fragmented, and source-port scans remain diagnostic. Firewall diagnostic scans require a completed ordinary scan of the same port from the same vantage. Masscan is unavailable because its raw Ethernet packets bypassed the worker destination firewall in a local fixture. Decoys, source-address spoofing, raw Ethernet, and MAC spoofing are denied for the same scope reason.

A source-port SYN result creates only a candidate for that exact route. One bounded, direct curl GET from the same source port can confirm an HTTP response and store that route separately. Nping UDP hex payloads require prior UDP port evidence. A packet reply or TCP handshake alone is not an application response.

An explicit DNS server requires UDP and TCP evidence when the client can retry over TCP. `dig +ignore` stays on UDP; `+tls` and `+https` use TCP/853 and TCP/443. A single scoped `curl --resolve host:port:IP` retains Host and SNI while pinning the connected address. A loopback proxy CONNECT is logged as another view and cannot authorize the worker or web broker path. The pinned runner builds HTTP/3-capable curl with ngtcp2 and nghttp3. `--http3-only` requires UDP evidence; `--http3` also requires TCP evidence because it can fall back. A completed `--http3-only --include` response promotes only the observed UDP route.

Engagement scanner observations retain exact output and source identity across resume. Native chat keeps observations for one turn. Completed Nmap, Nping, and IKE scan forms are recorded by their full command and vantage; an exact repeat within one hour is denied. Changing the port set or technique remains available when it answers a new question. Incomplete Nmap output does not count as a completed pass. A later closed result revokes earlier port evidence.

The runner supports bounded Nmap TCP, UDP, SCTP, IP-protocol, and diagnostic scans, but only validated TCP and UDP states can unlock its current service clients. SCTP and IP protocol results stay in their own namespaces. The pinned runner includes bounded Nping TCP, TCP-connect, UDP, and ICMP diagnostics for one literal IP. Nping raw modes use only `NET_RAW`; native chat and `blk engage` keep their destination guards. The source-built `ike-scan` sends bounded IKEv2 probes to one observed IPv4 UDP/500 endpoint, or UDP/4500 with `--nat-t` and its non-ESP marker. A returned handshake or notify confirms that exact UDP service; silence remains inconclusive. Split large ranges into scans that fit the command timeout; a partial run does not establish a complete inventory.

The network recon ladder credits a completed TCP sweep, UDP sweep, version check, and default-script check separately from the actual command output. A recorded quote alone cannot mark those checks complete. When no current open or `open|filtered` port is observed for a literal IP, version and script checks are audited as not applicable. A source-port candidate still reaches the validation tier. Coverage means the selected bounded scans completed; it does not imply every possible port or firewall path was tested.

### Executor coverage

| Surface | Current behavior |
| --- | --- |
| Network | Tiered asset and service discovery, fingerprinting, finding parsers, and evidence-linked candidate tasks. |
| Web | HTTP and browser collection, source analysis, role-aware observations, and replay through the scoped broker. |
| Local | Identity, privilege, permission, capability, scheduled-task, and service enumeration; focused executable inspection. Without a declared foothold, local work describes the isolated runner. |
| Active Directory | External discovery and enumeration of exposed directory services, with authenticated and finding-driven task paths using shared gated tools. |
| Cloud | AWS, Azure, and GCP reconnaissance ladders over shared gated tools. |
| Container | Container and Kubernetes task paths through specialized reconnaissance and shared execution. |
| AI application | Endpoint and model discovery, capability checks, and evidence-derived follow-on candidates. |

### External surface and advisory scans

A recon task naming an HTTP or HTTPS origin queues bounded checks for TLS, response headers,
cookies, CORS, allowed methods, metadata paths, and subdomain names derived from captured
material. The checks use the engagement gate and store each observation with its evidence.
Unreachable origins and incomplete checks remain coverage gaps.

A dispatched `vuln-analysis` task can fetch an in-scope lockfile, manifest, SBOM, or image archive
when its target is an HTTP or HTTPS URL ending in a recognized filename. The code uses a fixed
`curl` command through the RoE gate, accepts only HTTP 200, does not follow redirects, and limits
the response to 16 MiB and 10 seconds. URLs with credentials, queries, fragments, path traversal,
or unsafe output filenames are not fetched automatically. A successful fetch triggers offline
OSV and Grype scans in the isolated worker. A model-issued `curl -o` fetch of recognized material
also triggers those scans. Scanner databases come from `blk engage setup`; workers mount them
read-only and do not update them during an engagement.

```sh
blk engage --roe ROE.md --workspace ./assessment \
  "Create a vuln-analysis task for https://staging.example.test/package-lock.json and report version-match advisories"
blk store vulns --workspace ./assessment --package lodash --limit 20
blk store surface --workspace ./assessment --kind tls-protocol --limit 20
```

Advisory records name the scanner, package, installed and fixed versions, asset, and exact source
evidence. Two scanners can report the same advisory as separate records. A version match is a lead;
code-path reachability and impact require separate validation before a finding is confirmed.
Scanner failures and missing databases are recorded as gaps, not clean results.

### Foothold execution

An optional RoE `Foothold` declaration names a host the operator already controls and the surfaces that execute there. Declared carriers include SSH, an operator-supplied command prefix, a Metasploit RPC command-shell session, and an HTTP form shell. A retained raw shell can only be attached after access evidence is recorded. Credentials come from named environment references. A RoE declaration, its covered surfaces, and target scope are sealed into the policy.

Commands on covered surfaces execute on the foothold. The command gate applies scope checks, and actions record their execution destination. The runner filters SSH, command, and HTTP form connections to the foothold. Raw sessions use a loopback control connection and require a verified attachment. Metasploit RPC uses a loopback service and checks the active session peer.

For access gained during an engagement, record the session as evidence on an armed exploit task. Stop the run, approve any discovered private CIDR, attach an execution carrier, then resume. The attached host must be an IP in the original RoE or an approved private CIDR. SSH and command attachments cover local, network, web, AD, container, AWS, and GCP surfaces. Raw, Metasploit RPC, and HTTP form attachments cover command surfaces; they cannot carry the binary TCP stream required by the web broker. Resume probes the carrier with `true` before it opens local tasks. The command-carrier probe checks execution, while the operator vouches for the remote endpoint.

Private networks learned after access do not need to be guessed in the initial RoE. Approve each discovered private CIDR. The approval applies only to actions carried through a declared or attached foothold; direct worker requests retain the initial scope. When the foothold covers web, the browser and API broker validates every request, redirect, and subresource against approved addresses and opens the TCP stream through the carrier. Hostname URLs require `getent ahosts` on the foothold; every returned address must be approved. SSH uses its stream forwarder; a command carrier needs `ncat` on the foothold for web traffic. Resume seeds a recon task for each approved CIDR when the foothold covers the network surface.

```sh
blk engage stop --workspace ./assessment
blk engage approve-network --workspace ./assessment 10.20.30.0/24
blk engage attach-foothold --workspace ./assessment --task exploit-1 --evidence 42 \
  --entry '10.20.30.7 transport=ssh user=svc key=$FOOTHOLD_KEY knownhosts=$FOOTHOLD_KNOWN_HOSTS surfaces=local,network,web,ad,container,cloud-aws,cloud-gcp'
blk engage resume --workspace ./assessment
```

Set `FOOTHOLD_KEY` and `FOOTHOLD_KNOWN_HOSTS` to paths of operator-owned files before attaching. For a non-SSH session with a reusable execution command, use `transport=command ... exec=COMMAND ARG...` in the same `--entry` value. The carrier binary must be allowed by the external runner policy and its network endpoint must be in the original scope or the approved foothold IP. A `kubectl exec` carrier also needs its API endpoint in that scope.

For a raw POSIX shell, start a listener before the shell connects. The listener binds only to `127.0.0.1`, stays alive when the engagement stops, and expires with the engagement wall budget. After the shell connects, attach its workspace record to the exploit evidence and resume. Use a host IP from the original scope or an approved private CIDR in the attachment entry. The local listener does not accept a shell from a remote test host until an operator supplies an authorized route to loopback.

```sh
blk engage listen-shell --workspace ./assessment
blk engage stop --workspace ./assessment
blk engage attach-foothold --workspace ./assessment --task exploit-1 --evidence 42 \
  --entry '127.0.0.1 transport=raw-session session=/absolute/path/to/assessment/raw-session.json surfaces=local,network,ad,container,cloud-aws,cloud-gcp'
blk engage resume --workspace ./assessment
blk engage close-shell --workspace ./assessment
```

The raw broker retains one shell connection. It wraps authorized argv in a POSIX command, bounds output and time, and drops the shell after a failed or incomplete receipt. `close-shell` stops the broker; if the process has died, it removes the stale record. The workspace record contains a control token and must remain private.

Metasploit RPC supports active command-shell sessions through its [versioned MessagePack API](https://docs.rapid7.com/metasploit/rpc-api/). Keep the RPC server running on loopback across stop and resume. Set the named password environment variable before attaching. blkChain checks that the session is a shell and that its reported target host or tunnel peer matches the approved foothold IP. The adapter serializes commands, tracks the shell read pointer, and requires a command receipt. It does not use Meterpreter console sessions.

```sh
blk engage attach-foothold --workspace ./assessment --task exploit-1 --evidence 42 \
  --entry '10.20.30.7 transport=msf-rpc rpc=http://127.0.0.1:55552/api/1.0 session=7 user=msf passenv=MSF_RPC_PASSWORD surfaces=local,network,ad,container,cloud-aws,cloud-gcp'
```

An HTTP form shell must accept a POST field containing a POSIX shell command and return its raw output. The URL must use the approved foothold IP and an explicit port. `headerenv=` optionally names an environment variable containing one complete authorization header, such as `Authorization: Bearer ...`; blkChain provisions it as a private file in the guarded worker. The adapter disables redirects and proxies, URL-encodes the command field, and requires a command receipt. Other web-shell request formats require a command carrier wrapper.

```sh
blk engage attach-foothold --workspace ./assessment --task exploit-1 --evidence 42 \
  --entry '10.20.30.7 transport=http-form url=https://10.20.30.7:8443/shell.php param=cmd headerenv=WEB_SHELL_AUTH surfaces=local,network,ad,container,cloud-aws,cloud-gcp'
```

In the REPL or TUI, replace `blk engage` with `/engage` for the same approval, attachment, and resume commands.

For AWS or GCP credentials found on the foothold, include `cloud-aws` or `cloud-gcp` in a declared foothold's `surfaces=` list. An attached foothold covers both. Record the credential source as task evidence, then approve the provider and its absolute credential file path on the foothold. The approval file stores the path and evidence ID, not the credential contents. The foothold must provide `aws` or `gcloud`, respectively. A raw credential captured only in command output needs a credential file on the foothold before this path can use it.

```sh
blk engage approve-cloud-identity --workspace ./assessment \
  --provider aws --file /srv/keys/aws --task cloud-1 --evidence 42
blk engage resume --workspace ./assessment
```

In the REPL or TUI, prefix the cloud approval command with `/engage` instead of `blk engage`.

The approval permits provider CLI commands on the matching foothold surface under the RoE action and task gates. Recon accepts bounded read-only provider forms; other operations require an armed exploit or post-ex task. It does not prove that every provider operation stays in one account or project. AWS profile and endpoint overrides and GCP identity overrides remain denied. Provider commands start with a clean environment and a fixed `/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin` path on the foothold. AWS uses the approved shared credentials file with other configuration and metadata credentials disabled. GCP uses the approved credential file override. The action transcript records the original command and the foothold destination.

## Web application analysis

`blk engage web` provides `collect`, `analyze`, `inspect`, `import`, `archive`, `export`, and `replay`. Collection, archive acquisition, and replay make network requests under the RoE. HAR import also requires policy context. Analysis, inspection, and export work from saved workspace data.

The collector processes HTML references, scripts, frames, module dependencies, manifests, source maps, and selected framework chunk patterns. An isolated browser adds rendered pages, runtime and generated scripts, worker sources, cached responses, observed requests, and WebSocket traffic. Role sessions use supplied credentials through environment references bound to their configured origin.

Analysis uses JavaScript and TypeScript syntax trees, lexical binding checks, common HTTP-client patterns, and source locations to reconstruct operations and parameters. It identifies credential candidates and library advisory matches and records them as leads for review.

Saved HTTP examples retain request-body representations for replay. Structured operations can also be replayed with supplied values. WebSocket exchange validation compares an operator-supplied bounded transcript with expected opcodes and bytes. Discovery, observed responses, cached responses, handshakes, messages, advisory matches, and matched exchanges have distinct evidence grades.

Collection records supplied roles and visited states under configured asset, page-state, request, byte, and time budgets.

Browser collection requires a separately provisioned pinned Playwright driver and container. `PLAYWRIGHT_DRIVER_PATH` and `BLKCHAIN_PLAYWRIGHT_CONTAINER` identify them; headed assistance also requires `BLKCHAIN_PLAYWRIGHT_CDP` to name its loopback CDP endpoint. The adapter verifies package integrity and container
isolation and does not install a browser on demand. `blk engage setup` builds the command runner, not the browser environment.

### Signed-in Chrome roles

Authenticated web collection can import one role from a Chrome CDP endpoint bound to host loopback. [Provision a separate signed-in Chrome profile](cli/webbrowser-provisioning.md#optional-signed-in-chrome-source), then sign in to the approved site in that window. Keep the isolated browser container from the setup guide running. The host CDP URL and the container's `BLKCHAIN_PLAYWRIGHT_CDP` URL are separate endpoints.

The session file names the role and exact target origin. It contains no credential values:

```json
{"roles":[{"name":"reader","origin":"https://app.example.test"}]}
```

For direct collection, use the session file, role, and host CDP URL together:

```sh
blk engage web collect https://app.example.test/ --roe ROE.md --workspace ./assessment \
  --browser --session ./roles.json --role reader --session-cdp http://127.0.0.1:9223
```

The same options apply to HTTP `blk engage web replay`. Archived collection and WebSocket replay do not import CDP state. Autonomous web tasks can use the role when the engagement starts with these options:

```sh
blk engage --roe ROE.md --workspace ./assessment --session ./roles.json \
  --role reader --session-cdp http://127.0.0.1:9223 "Assess the authorized web application"
blk engage resume --workspace ./assessment --session ./roles.json \
  --role reader --session-cdp http://127.0.0.1:9223
```

In the plain REPL or TUI, use `/engage` with the same flags. Resume with `/engage --resume ./assessment --session ./roles.json --role reader --session-cdp http://127.0.0.1:9223`.

The import requires the role origin to be in the RoE. Direct collection and autonomous `web_collect` require every target to match that exact origin; autonomous collection selects the isolated browser when the role is present. An autonomous web recon task at that origin collects through the browser and returns its evidence without running the anonymous command ladder for that task. The tool result includes a bounded, redacted preview of the browser DOM captured in that collection, with an artifact ID; exact bytes stay in the evidence store. Parent-domain cookies are narrowed to the selected host, and only local storage from the exact origin is copied. Session storage, IndexedDB, and WebAuthn credentials are not imported, so sites relying on them for authentication may remain anonymous. Browser and API requests to other in-scope origins send no imported credentials and their evidence is labeled anonymous. Supplemental assets fetched outside the browser do not use imported cookies and are also labeled anonymous. Target traffic still crosses the engagement gate and web broker. The source Chrome profile remains open; blkChain does not read its profile files or persist the imported storage state. Resume requires the same role and origin and imports fresh state from CDP.

Inspect saved operations without contacting a target:
```sh
blk engage web inspect --workspace ./assessment --view apis
blk engage web inspect --workspace ./assessment --view coverage
blk engage web help
```

## Engagement store and findings

`blk store` opens saved engagements for inspection and review. It provides engagement selection, surface filters, paginated records, finding filters, an interactive navigator, and local answers about the stored evidence.

```sh
blk store list
blk store show --workspace ./assessment
blk store records --workspace ./assessment --kind evidence --limit 20
blk store findings --workspace ./assessment --status validated
blk store vulns --workspace ./assessment --scanner osv-scanner --limit 20
blk store surface --workspace ./assessment --kind tls-protocol --limit 20
blk store ask --workspace ./assessment "Which observations remain unvalidated?"
blk store --interactive --workspace ./assessment
```

The default catalog lists workspaces under the blkChain configuration directory. Use `--workspace` for a workspace stored elsewhere, or `--id` to select a catalog entry.

Findings have explicit `lead`, `observed`, `validated`, and `dismissed` states. Detector and parsed records start as leads. Operator `add` and `review` actions persist conclusions and review events. Validated findings require exact evidence IDs belonging to the selected task.

`store vulns` lists scanner-reported advisories with `--advisory`, `--package`, `--ecosystem`,
`--scanner`, `--asset`, `--severity`, and pagination filters. `store surface` lists external
observations with `--kind`, `--name`, `--asset`, and pagination filters. Neither command turns a
version match or a surface observation into a validated finding.

`store ask` uses a loopback model endpoint and a bounded selection of engagement records. Answers cite supplied `[R1]` references and flag partial selection. When synthesis fails or references are invalid, it returns selected records for inspection. It does not run assessment tools or web search.

`blk kg` and the `kg_query` MCP tool expose task, asset, and evidence relationships, including dependencies and provenance. The graph refreshes from the engagement store.

A workspace includes `engagement.db`, captured artifacts under `evidence/`, `actions.jsonl`, `audit.jsonl`, policy/checkpoint data, and Markdown/JSON reports. Reports include completed and unfinished tasks, persisted finding review states, and exact evidence IDs. The final assessment uses fixed report sections with escaped model text. The action transcript labels internal help probes and separates command arguments. Use `blk store findings` to inspect those conclusions and their review history.

`max_commands` counts substantive command attempts. `max_actions` counts those attempts and other policy actions. Exact read-only `sudo -l` listings and internal help checks do not spend either count, but still pass the remaining RoE and runtime limits. A command cap denial ends planning and produces a final report.

For a network task that requests an HTTP banner, the recon executor follows an observed open HTTP port with a bounded, gated HEAD request. It records the port line and exact `Server:` response line as evidence. The runner includes Nmap's service-detection data. Network Nmap calls add `-n` unless the command explicitly selects a DNS mode, avoiding reverse-DNS waits behind the worker's egress guard.

## Terminal, MCP, and HTTP interfaces

Bare `blk` starts the interactive session. A terminal uses the keyboard-driven UI; redirected input
uses the plain REPL. Finished answers remain in normal terminal scrollback. The UI supports
multiline drafts, external editing, history search, context previews, source inspection, model
controls, cancellation, and bounded queues.

| Interactive command | Purpose |
| --- | --- |
| `/agent auto` or `/agent NAME` | Select native answer routing and a research specialist. |
| `/tool-host sandbox` or `/tool-host local` | Choose where native file and terminal tools run. |
| `/browser-cdp URL` or `/browser-cdp off` | Explicitly select or clear a loopback signed-in browser source. |
| `/model` | Select the model and reasoning level. The selected model answers every call of a turn, with no failover. |
| `/models` | Inspect and administer native chat models, reranking, and web settings. |
| `/hermes PROMPT` | Run one legacy Hermes turn. It writes no session. |
| `/attach PATH` or `/context` | Queue, preview, or remove bounded context for the next question. URLs are references and are not fetched. |
| `/queue` | Review, edit, pause, resume, or remove queued questions in the UI. |
| `/history`, `/clear`, `/undo` | Inspect or change blk's local conversation state. |
| `/store ACTION` | Inspect engagement records and findings. |
| `/help` | Show the current command surface and keyboard help. |

The plain REPL uses text commands. The terminal UI adds picker overlays and asynchronous question
queues. Model and web preferences, conversation history, and engagement state are separate stores.

`blk mcp` serves these tools over stdio:

| Tool | Purpose |
| --- | --- |
| `kb_search` | Ranked local retrieval with source pointers. |
| `kb_answer` | Bounded native research answers. |
| `chat` | One agent turn with adaptive routing, the knowledge base, files, terminal, browser and web research, and the allowlisted MCP client tools. Omit `session_id` to start a session and pass the returned id to continue it. |
| `route_skill` | Deterministic domain-based playbook selection. |
| `engage` | Run under the operator-approved RoE configured by `BLKCHAIN_MCP_ROE_PATH`. The supplied inline RoE must match that policy. |
| `kg_query` | Query an engagement's task, asset, and evidence graph. |

`chat` takes an optional `agent` and `tool_host`. `tool_host` is `sandbox` (the default) or `local`. `local` is accepted because the server speaks only stdio, so its client is a local process that already holds the operator's privileges. Every `chat` turn is saved as a session.

The server also serves saved sessions as read-only `session://{id}` resources. A client reads one by id, and the listing covers up to 50 sessions that exist when the server starts. To resume one, pass its id back to `chat`.

MCP engagement defaults to Auto. `confirm=elicit` requires compatible client elicitation support.
The tool returns workspace, transcript, report, and policy references. `blk analyze --schema NAME`
provides schema-validated JSON generation.

`blk serve` offers the same turn over HTTP. It listens on `127.0.0.1:8787` unless `--bind` names another address.

| Endpoint | Purpose |
| --- | --- |
| `GET /health` | `{"status":"ok","version":...}`. |
| `POST /v1/sessions` | Create a session and return its listing fields with status 201. This server may run turns on it. A new session reads as 404 until its first turn writes a transcript. |
| `GET /v1/sessions` | List sessions from every surface, newest first, as `{"sessions":[...],"truncated":bool}`. At most 50 are listed, and `truncated` is true when more exist. |
| `GET /v1/sessions/{id}` | Read a session's `id`, `title`, `msg_count`, `model` and newest `turns` in a body of at most 256 KiB. `trimmed` is present and true when turns or content were dropped to fit. |
| `POST /v1/sessions/{id}/turns` | Run a turn and return the turn result as JSON: `answer`, `citations`, `used_web`, `model` and `usage`, plus `session_id`, `agent`, `route`, `actions` and `results` when set. |
| `POST /v1/sessions/{id}/turns/stream` | Run a turn and stream it as Server-Sent Events. |

A turn body is JSON with `message`, which is required and at most 256 KiB, and optional `agent`, `tool_host`, `browser_cdp`, `force_rag` and `web_only`. A turn without a body is refused with 415. A turn that produced an answer but did not finish cleanly returns it with status 200 and an `error` field. The stream sends five events:

| Event | Payload |
| --- | --- |
| `tool.started` | `{"tool":NAME}` |
| `tool.completed` | `{"tool":NAME}`, with `error` when the call failed, was skipped past the call cap, or did not complete. |
| `assistant.delta` | `{"delta":TEXT}` |
| `run.completed` | `{"usage":{"completion_tokens":N}}` |
| `run.failed` | `{"error":TEXT}` |

The stream ends on `run.completed` or `run.failed` unless the connection is cut. A request refused before the turn starts, such as a bad body, a session this server did not create or a turn already in flight, answers with a plain status. Once the turn starts the status is already 200, so a failure inside it arrives as `run.failed`.

A turn can be run only on a session this server process created with `POST /v1/sessions`, as with `chat` over MCP, and any other well-formed id answers 403. The server tracks its 128 most recently used session ids in memory, so a session that falls out of them, or that predates a restart, answers 403 too. Any session on disk can be listed and read, whichever surface created it.

A bind that is not loopback needs `--allow-remote` and a bearer token. The token comes only from `BLKCHAIN_SERVE_TOKEN`, is compared in constant time, and is never logged or returned. A token that is set is required on every request, loopback included, and a request without it is refused with 401. With none set, any process on this machine can call the API.

`tool_host: local` and `browser_cdp` grant the operator's own reach: the host's terminal and files outside the sandbox, and the signed-in browser. A turn may use them only when the bind is loopback and the request's peer address is loopback. On a bind that is not loopback they are refused to every caller with 403, because behind a tunnel, a published container port or a local proxy a loopback peer address does not show who sent the request. On a loopback bind with no token, any local process qualifies.

Three controls guard the API against a web page the operator has open, which can reach loopback. Each stands on its own:

- A request body must be `application/json`, or the request is refused with 415. A cross-site form post or no-cors request cannot send that type, and a JSON request from a page needs a preflight this server refuses.
- The `Host` header must name an address the bind serves, or the request is refused with 421. This defeats DNS rebinding, where a hostile name resolves to the server. A loopback bind accepts loopback addresses, `localhost` and `*.localhost`, and a bind on one other host accepts only that host. A wildcard bind accepts any `Host` because a client's `Host` cannot be predicted from it, so the control does not run there. The port is not compared.
- Any `Origin` header is refused with 403, a loopback origin included. This defeats a cross-origin request from a page's script, which a browser marks with `Origin`, and the preflight that would authorize one.

These checks are on request headers. A request without an `Origin` header passes the third, whoever sends it, and a local process that sends a JSON body, an accepted `Host` and no `Origin` passes all three. Only the token stops it.

The server bounds its own work:

| Bound | Value |
| --- | --- |
| Request body | 1 MiB, refused with 413. |
| One turn's message | 256 KiB, refused with 400. |
| Turns per session | 1 in flight. A second is refused with 409. |
| Turns across the server | 4 in flight. A fifth is refused with 503. No request queues. |
| One turn's wall clock | 300 seconds unless `BLKCHAIN_TIMEOUT_SECONDS` sets it. On the JSON route a turn with no answer at that point returns 504, and the stream ends on `run.failed`. |
| One stream | 32 MiB on the wire, framing included. At the limit the stream ends on `run.failed`. |
| Request rate | 240 per minute with a burst of 32, shared by all callers of the server and refused with 429. |
| Request head | 10 seconds to arrive. An idle kept-alive connection closes after 2 minutes. |

## Architecture

| Component | Responsibility |
| --- | --- |
| `cli/` | Go retrieval, answers, terminal interfaces, engagement orchestration, policy enforcement, web analysis, storage, reports, MCP, and the HTTP API. |
| `blkchain/` | Python MLX embedding/reranking service, offline ingestion/indexing, and evaluation harnesses. |
| Qdrant | Persistent dense and sparse index. |
| OpenAI-compatible LLM endpoint | Separately managed native answer and engagement inference. |
| Hermes | Separately configured legacy backend for explicit one-shot turns. |

Go owns query-time retrieval, answering, engagement execution, MCP, and the HTTP API. Python serves the MLX models
and builds the index offline. Models and corpus content are supplied by the operator.

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) documents what a change has to hold to: the language
boundary, the two cross-language contracts, the command output shapes the evaluation harness parses,
the security invariants, and the testing and commit conventions. Read it before changing the
retrieval path, the engagement harness, or the embedding service.

## Complete setup guide

This guide targets macOS on Apple Silicon. Run the core steps first to get local retrieval and
native answers working. Add Hermes for the optional legacy one-shot. Add the
command runner for engagements and the browser container for runtime web collection.

| Component | Required for |
| --- | --- |
| Apple Silicon, Python 3.12.14, uv, Go 1.27.2, Xcode Command Line Tools | Building blk and running the MLX embedding service. |
| Docker Desktop | Qdrant and the isolated execution containers. |
| Embedder and reranker model files | Local retrieval. |
| OpenAI-compatible chat server and chat model | Native answers and model-driven engagements. |
| Hermes | Explicit `blk hermes`, `/hermes`, and `blk ask --hermes`. |
| Pinned Playwright package and browser container | Runtime browser collection. |

Choose a chat model that fits alongside the embedder, reranker, Docker, and the operating system.
Long contexts also consume memory. The guide uses a small MLX chat model for initial setup; select a
larger model when your hardware and workload support it. Reserve disk space for weights, corpus
files, Qdrant storage, evidence, and the chat server's cache.

### 1. Install the host prerequisites

Install [Homebrew](https://brew.sh/) if it is not already available. Install the command-line tools
and build dependencies:

```sh
xcode-select --install
brew install uv go
```

If Xcode Command Line Tools are already installed, skip the installer. Check the compiler and
package tools:

```sh
xcode-select -p
clang --version
uv --version
go version
```

The Go module requires Go 1.27.2. Use that version or a compatible newer toolchain. Go's automatic
toolchain selection can obtain the module's required version when enabled. See the
[Go installation guide](https://go.dev/doc/install) and
[uv installation guide](https://docs.astral.sh/uv/getting-started/installation/) for other methods.

Install [Docker Desktop for Apple Silicon](https://docs.docker.com/desktop/setup/install/mac-install/),
move it to Applications, and open it. Wait for the engine to start:

```sh
docker version
docker info
```

Both the client and server must answer. A Docker CLI without a running engine is not sufficient.
Container images and model downloads require internet access during provisioning.

### 2. Get the repository and build blk

Download or clone this repository from its distribution location, then enter the checkout. Replace
the path below with your own. Keep this shell in the repository root for the remaining core steps:

```sh
cd /absolute/path/to/blkChain
export BLKCHAIN_ROOT="$PWD"
uv python install 3.12.14
uv venv .venv --python 3.12.14
uv sync --locked
(cd cli && go mod download && go build -o blk .)
.venv/bin/python --version
cli/blk version
```

`uv sync --locked` installs the repository's pinned Python dependencies. `cli/go.mod` and
`cli/go.sum` provide the Go module versions and checksums. Keep CGO enabled; the Go client uses
SQLite and syntax-tree dependencies that need the C compiler.

Install the binary and add its directory to your shell path:

```sh
cli/blk install
export PATH="$HOME/.local/bin:$PATH"
blk version
```

Add `export PATH="$HOME/.local/bin:$PATH"` to your shell profile if needed. For the default macOS
shell, use `~/.zshrc`. Optional shell completion is available through `blk completion zsh` or
`blk completion bash`.

### 3. Configure paths and the native provider

Create the local configuration template without replacing an existing file:

```sh
if [ ! -e .env ]; then
  (umask 077; cp .env.example .env)
fi
mkdir -p models/chat corpus/notes data/qdrant_storage
```

For the guide's default layout, export these settings in the current shell:

```sh
export BLKCHAIN_MODELS_DIR="$PWD/models"
export BLKCHAIN_SOURCES_DIR="$PWD/corpus"
export BLKCHAIN_COLLECTION=blkchain
export OMLX_BASE_URL=http://127.0.0.1:8000/v1
export OMLX_MODEL=Qwen3-4B-Instruct-2507-4bit
```

Copy non-secret settings into `.env` if you want them loaded by blk on later runs. Use absolute paths
for custom model and corpus directories. Process environment values take precedence over `.env`.
Keep credentials in the process environment or a secret manager and leave `.env` untracked.

The default endpoint layout is:

| Service | Endpoint |
| --- | --- |
| Qdrant HTTP | `http://127.0.0.1:6333` |
| Qdrant gRPC | `127.0.0.1:6334` |
| Embedding/reranking | `http://127.0.0.1:8100` |
| Native chat server | `http://127.0.0.1:8000/v1` |

Keep these defaults for the initial setup. To use another embedding endpoint, set
`BLKCHAIN_EMBED_HOST` and `BLKCHAIN_EMBED_PORT`. These settings configure the Python service,
Python indexing client, Go retrieval client, and stack lifecycle checks together. Keep the service
bound to loopback for local operation. The Go retrieval parameters live in
`blkchain/contract/rag.json`; Python indexing settings live in `blkchain/config.py`.

These settings are read but are not part of the guide's path above. Leave them unset unless you need
the behavior described.

| Setting | Default | Effect |
| --- | --- | --- |
| `BLKCHAIN_DOCKER_BIN` | `docker` | Container runtime binary used to run and inspect the isolated browser and proxy. Changing it changes what executes the sandbox. |
| `BLKCHAIN_REPUTABLE_DOMAINS` | the list in `blkchain/contract/rag.json` | Comma-separated replacement for the domains a web result is treated as reputable from. |
| `BLKCHAIN_POC_DOMAINS` | the list in `blkchain/contract/rag.json` | Comma-separated replacement for the domains permitted as proof-of-concept destinations. |
| `BLKCHAIN_ROUTER_MODEL` | `router_model` in `blkchain/contract/rag.json`, empty | Model for the short decisions of a turn: action classification, routing, the corpus check, context grading and conversation compression. Empty uses the model the turn would otherwise resolve. |
| `BLKCHAIN_ASSESSMENT_MODEL` | `assessment_model` in `blkchain/contract/rag.json`, empty | Model for the direct answer, the tool loop and grounded synthesis. Empty uses the model the turn would otherwise resolve. A call moves to the next model in the role's chain only on the [failures listed in the architecture notes](docs/ARCHITECTURE.md#the-rag-parameter-contract). |
| `BLKCHAIN_WEB_FALLBACK` | unset | Set to `duckduckgo` to use DuckDuckGo when no Tavily key is configured. |
| `BLKCHAIN_PLAYWRIGHT_HEADED` | unset | Must be `1` to permit a headed browser run, alongside an operator-provisioned headed container. |
| `BLKCHAIN_ANALYZE_MAX_INPUT_BYTES` | 1048576 | Subject size cap for `blk analyze`. |
| `BLKCHAIN_MAX_TEXT_FILE_BYTES` | 8388608 | Largest text file the indexer reads. |
| `BLKCHAIN_MAX_JSON_FILE_BYTES` | 4194304 | Largest JSON file the indexer reads. |
| `BLKCHAIN_EMBED_SUBBATCH` | 32 | Forward-pass sub-batch size in the embedding service. |
| `BLKCHAIN_EMBED_CACHE_RELEASE_AFTER` | 64 | Batches processed before the embedding service releases the Metal cache. |
| `BLKCHAIN_MMDFLUX` | `mmdflux` on `PATH` | Path to the diagram renderer used by the engagement views. |
| `BLKCHAIN_POWERLINE` | unset | Set to `0` to force plain unicode status separators instead of powerline glyphs. |
| `HERMES_HOME` | `~/.hermes` | Hermes configuration directory that `blk doctor` reads. |

### 4. Download the pinned models

The locked Python environment already includes the Hugging Face download library. Run this from
the repository root with `BLKCHAIN_MODELS_DIR` set as above:

```sh
.venv/bin/python - <<'MODELS'
import os
from pathlib import Path
from huggingface_hub import snapshot_download

root = Path(os.environ['BLKCHAIN_MODELS_DIR']).expanduser()
models = [
    ('mlx-community/Qwen3-Embedding-0.6B-4bit-DWQ',
     '6c3ae70858513f1a78e9cdca3cae330d9075cd2a',
     root / 'Qwen3-Embedding-0.6B-4bit-DWQ'),
    ('afanjul/gte-reranker-modernbert-base-mlx',
     '0b1cfb9141dd1452e07a328a0dec430f2324da12',
     root / 'gte-reranker-modernbert-base-mlx'),
    ('mlx-community/Qwen3-4B-Instruct-2507-4bit',
     '50d427756c6b1b2fe0c0a10f67fbda1fc8e82c1b',
     root / 'chat' / 'Qwen3-4B-Instruct-2507-4bit'),
]
for repo, revision, destination in models:
    snapshot_download(repo_id=repo, revision=revision, local_dir=str(destination))
    print(f'Ready: {destination}')
MODELS
```

These directory names match the default embedder/reranker paths and the guide's chat model ID.
The downloads use full commit revisions. The
[Hugging Face download guide](https://huggingface.co/docs/huggingface_hub/en/guides/download)
describes resumable snapshots. The
[starter chat model](https://huggingface.co/mlx-community/Qwen3-4B-Instruct-2507-4bit) is an
Apache-2.0 MLX conversion with a tool-aware chat template. Review licenses for other models.

The embedder produces 1024-dimensional vectors. A different embedding dimension requires a
compatible Qdrant collection. `BLKCHAIN_RERANKER_KIND` selects an alternative reranker; its model
path and weights must match that choice.

Both default models are Apache-2.0. The reranker alternatives are not equivalent in licensing:
`BLKCHAIN_RERANKER_KIND=qwen3` uses Qwen3-Reranker-0.6B, which is Apache-2.0, and
`BLKCHAIN_RERANKER_KIND=jina` uses jina-reranker-v3, which is CC-BY-NC-4.0 and permits
non-commercial use only. Select the jina backend only where that license fits your use. See NOTICE.

### 5. Start Qdrant and the embedding service

Start the local retrieval stack:

```sh
blk up
blk status
curl --fail --silent --show-error http://127.0.0.1:8100/health
```

`blk up` creates or starts `blkchain-qdrant` using the image digest pinned in `cli/stack.go` and
starts the Python embedding service. Qdrant ports bind to loopback. Its persistent data lives under
`data/qdrant_storage`. The embedding service loads the downloaded embedder and reranker and writes
its log under `.run/`.

Expected embedding health includes `status: "ok"`, `embedder: true`, and `reranker: true`. Initial
model loading can take time. Use `blk logs embed_server` to inspect startup and `blk status` to check
both managed services.

If image access is denied, authenticate with `docker login dhi.io`, then retry `blk up`. Keep the
repository's digest rather than substituting a floating image tag.

### 6. Add your corpus and build the index

blkChain does not download a security corpus automatically. Start with your own Markdown notes.
The manifest reads the `notes/` directory below `BLKCHAIN_SOURCES_DIR`.

For a fresh setup, create a small document to verify indexing:

```sh
cat > "$BLKCHAIN_SOURCES_DIR/notes/setup-example.md" <<'NOTE'
# Contextual output encoding

Encode untrusted text for the output context where it is rendered.
HTML text, HTML attributes, JavaScript, and URLs require different handling.
Input validation checks business constraints and does not replace output encoding.
NOTE
.venv/bin/python -c "from blkchain import index; print(index.build_index(snapshot_version='v1'))"
blk sources --json
blk search --json --top-k 5 "contextual output encoding"
```

Confirm that `sources` reports indexed chunks and that search returns the setup document with its
source pointer. Re-running the indexer resumes by content hash.

Populate the source directories you use before building a larger index:

| Location under the corpus root | Content |
| --- | --- |
| `notes/` | Personal Markdown notes. |
| `hacktricks/hacktricks/`, `hacktricks/hacktricks-cloud/` | Supplied HackTricks checkouts. |
| `payloadsallthethings/` | Supplied payload/reference files. |
| `arsenal/curated-en/`, `arsenal/checklists-en/` | Supported technique JSON and checklists. |
| `skills/`, `violin-skills/` | Skill/reference Markdown. |
| `AI-penetration-testing/`, `arc_pi_taxonomy/`, `cai/` | Additional supported source directories. |

`BLKCHAIN_WSTG_PDF` selects an existing WSTG PDF. `BLKCHAIN_SECLISTS_DIR` adds catalog-style
wordlist metadata, and `BLKCHAIN_SKILLS_DIR` adds another skill directory. Unconfigured or absent
sources are skipped. The full manifest is in `blkchain/config.py`.

For an individual file or directory outside the manifest, use an absolute path and a distinct
source label:

```sh
blk add /absolute/path/to/my-notes --source my-notes
```

### 7. Start the native chat server

The guide uses oMLX. Install it with its
[official macOS app or Homebrew instructions](https://github.com/jundot/omlx):

```sh
brew tap jundot/omlx https://github.com/jundot/omlx
brew install jundot/omlx/omlx
omlx serve --help
```

For a fresh foreground server, create an API key in your password manager and enter it securely.
The following `read` hides the value while you type it; press Enter when finished:

```sh
read -r -s OMLX_API_KEY
export OMLX_API_KEY
omlx serve --model-dir "$BLKCHAIN_MODELS_DIR/chat" --host 127.0.0.1 --port 8000
```

Keep that terminal open. In a second terminal, enter the repository, repeat the exports from step 3,
and export the same `OMLX_API_KEY` from your secret manager. An existing oMLX installation can use
its configured API key and model directory instead. Confirm the server's actual model ID before
setting `OMLX_MODEL`.

Inspect the model list without printing the key:

```sh
.venv/bin/python - <<'CHECK'
import json
import os
import urllib.request

base = os.environ['OMLX_BASE_URL'].rstrip('/')
request = urllib.request.Request(base + '/models')
key = os.environ.get('OMLX_API_KEY', '')
if key:
    request.add_header('Authorization', 'Bearer ' + key)
with urllib.request.urlopen(request, timeout=15) as response:
    data = response.read((1 << 20) + 1)
if len(data) > 1 << 20:
    raise SystemExit('Model list exceeds the size limit')
models = json.loads(data)
print('\n'.join(item['id'] for item in models.get('data', [])))
CHECK
blk health --json
blk ask --agent auto --rag "Explain contextual output encoding"
```

The model list must include the ID configured in `OMLX_MODEL`. `health --json` should report
`ok: true` with all three native services available. The answer command should return text and
source references from your corpus. This verifies the native answer path without requiring Hermes.
Use a tool-calling model and a supporting server configuration for engagement orchestration.

### 8. Set up Hermes and connect the knowledge base

Hermes provides an optional legacy backend for one-shot `blk hermes`, `/hermes`, and `blk ask --hermes` turns. Install it using the
[official quickstart](https://hermes-agent.nousresearch.com/docs/getting-started/quickstart/).
This CLI installer is pinned to a source commit and verified before execution:

```sh
hermes_installer="$(mktemp -t blkchain-hermes-install)"
curl --fail --location --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 120 \
  https://raw.githubusercontent.com/NousResearch/hermes-agent/354724fb085162678964c116ceb4c40fc57c717c/scripts/install.sh \
  --output "$hermes_installer"
printf '14b4c89518cf0e4e71841708dd5d8a28f1f494d22cd20e12f4d5eeb29c7d2fdb  %s\n' \
  "$hermes_installer" | shasum -a 256 -c - && \
  bash "$hermes_installer" --commit 354724fb085162678964c116ceb4c40fc57c717c
```

Open a new terminal after installation, enter the repository, and restore the path/provider exports
and API key. Run `hermes setup` for initial configuration, then `hermes model`. Choose the custom
OpenAI-compatible endpoint and enter:

| Setting | Value for this guide |
| --- | --- |
| Base URL | `http://127.0.0.1:8000/v1` |
| Model | The actual ID from the server model list. |
| API key | The same local server key. |
| Context | At least 64,000 tokens, supported by the selected model and server. |

Add this server entry to `~/.hermes/config.yaml` under `mcp_servers`. Merge it into any existing
mapping rather than replacing the file. Replace the root path with your checkout:

```yaml
mcp_servers:
  blkchain:
    command: "${userHome}/.local/bin/blk"
    args: ["mcp"]
    enabled: true
    env:
      BLKCHAIN_ROOT: "/absolute/path/to/blkChain"
      OMLX_BASE_URL: "http://127.0.0.1:8000/v1"
      OMLX_MODEL: "Qwen3-4B-Instruct-2507-4bit"
      OMLX_API_KEY: "${OMLX_API_KEY}"
    tools:
      include: [kb_search, kb_answer, route_skill, kg_query]
```

Hermes resolves environment references from its secret scope or the process environment. Keep the
key in that scope rather than writing it into the YAML. The
[Hermes MCP reference](https://hermes-agent.nousresearch.com/docs/reference/mcp-config-reference)
explains server fields and tool selection.

Verify the integration:

```sh
hermes --version
blk doctor
blk ask --hermes "Use kb_search to explain contextual output encoding from my local notes"
```

`hermes --version` checks that the installed launcher runs; `doctor` checks that it is on `PATH`
and that the blkChain MCP entry is enabled. This one-shot answer should use Hermes and retrieve from
the connected knowledge base.

`blk up` does not start Hermes.

### 9. Provision the isolated command runner

Build the runner and warm its scanner databases after Docker is available:

```sh
blk engage setup
blk help engage
```

The build uses the embedded Dockerfile, a digest-pinned base, architecture-specific package
locks, and checksum-verified curl and ike-scan sources. The build toolchain stays outside the runtime image.
Setup then downloads OSV archives for Go, npm, PyPI, Maven,
crates.io, RubyGems, Packagist, NuGet, Alpine, and Debian, and asks Grype to update its database.
It needs outbound HTTPS, a writable cache, and several GiB of free disk. The cache is
`$XDG_CACHE_HOME/blkchain/vulndb` when `XDG_CACHE_HOME` is set, otherwise
`~/.cache/blkchain/vulndb`. Setup prints the path it uses. Re-run setup after rebuilding blk when
runner assets change, or when you need fresh scanner data.

Check setup output for `scanner database update failed`; the command's exit status alone does not
prove every database was warmed. A failed download leaves a gap for scans that need it; rerun setup
until it reports no download failure. Engagement workers mount the cache read-only and scan
offline. The general worker is limited to 2 GiB of memory so it can
load the OSV database. The raw-socket worker stays at 256 MiB. Both keep CPU, process, scratch,
output, duration, and RoE parallelism limits. Verify packaged tool availability with the local
image check:

```sh
(cd cli && BLKCHAIN_ENGAGE_DOCKER_E2E=1 go test -run '^TestCatalogToolsRunInTheImage$' -v -count=1 -timeout 10m .)
```

Create an operator-owned `ROE.md` for each engagement. At first use in a fresh directory without a
policy, blk writes the commented template and stops. Fill in the actual authorized targets,
exclusions, action permissions, command denials, resource caps, and any foothold declaration before
starting target-facing work. Safe mode requires an interactive approval channel; Auto follows the
operator's policy.

The MCP `engage` tool additionally requires `BLKCHAIN_MCP_ROE_PATH` to point to that approved file.
Its supplied inline policy must match. Configure that tool separately when the operator chooses to
expose engagement execution; the knowledge-base MCP example above exposes research tools.

### 10. Provision the isolated browser

The browser is a separate optional container. The following headless setup matches the repository's
Apple Silicon driver and image checks. It does not require Node on the host.

Set the driver location and container identity:

```sh
export PLAYWRIGHT_DRIVER_PATH="$HOME/.local/share/blkchain/playwright-1.62.1"
export BLKCHAIN_PLAYWRIGHT_CONTAINER=blk-web-browser
export BLKCHAIN_PLAYWRIGHT_CDP=http://127.0.0.1:9222
```

Download and verify the driver before extracting it:

```sh
(
  set -eu
  mkdir -p "$PLAYWRIGHT_DRIVER_PATH"
  curl --fail --location --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 120 \
    https://registry.npmjs.org/playwright-core/-/playwright-core-1.62.1.tgz \
    --output "$PLAYWRIGHT_DRIVER_PATH/playwright-core-1.62.1.tgz"
  .venv/bin/python - <<'INTEGRITY'
import base64
import hashlib
import os
from pathlib import Path

archive = Path(os.environ['PLAYWRIGHT_DRIVER_PATH']) / 'playwright-core-1.62.1.tgz'
expected = 'wPYSwEBJY9GHraISXqyqtx0na0LpO3XEX7jNDhntbex7tzUS7kLnZsOlFruFJB4Hi/rhDMjXGqHewDZ68nYZVw=='
with archive.open('rb') as file:
    actual = base64.b64encode(hashlib.file_digest(file, 'sha512').digest()).decode()
if actual != expected:
    raise SystemExit('Playwright integrity check failed')
print('Playwright integrity verified')
INTEGRITY
  tar -xzf "$PLAYWRIGHT_DRIVER_PATH/playwright-core-1.62.1.tgz" -C "$PLAYWRIGHT_DRIVER_PATH"
  chmod -R a+rX "$PLAYWRIGHT_DRIVER_PATH/package"
  cp cli/playwright-container-node.sh "$PLAYWRIGHT_DRIVER_PATH/node"
  chmod 700 "$PLAYWRIGHT_DRIVER_PATH/node"
  printf '5021d5f31f68d772f4e5c0e2f418ef63e181ba314500f5b1fabdaa6174de1aa3  %s\n' \
    "$PLAYWRIGHT_DRIVER_PATH/node" | shasum -a 256 -c -
)
```

Keep the verified archive beside `package/`. blk compares every extracted file against it and
checks the launcher hash. The package is public code; its read permissions allow the container's
non-root user to read the bind mount.

Pull the pinned browser image and start Chromium:

```sh
docker pull dhi.io/playwright@sha256:362a6b32631204936ec45c03f5c0f0b75bab6489a05031d59f51665fef3d7851
docker run -d --name "$BLKCHAIN_PLAYWRIGHT_CONTAINER" \
  --network none --user 1000:1000 --read-only --memory 1g --cpus 2 \
  --pids-limit 256 --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,nosuid,nodev,size=256m \
  --mount "type=bind,src=$PLAYWRIGHT_DRIVER_PATH/package,dst=/opt/blkchain-playwright/package,readonly" \
  --entrypoint /ms-playwright/chromium-1243/chrome-linux-arm64/chrome \
  dhi.io/playwright@sha256:362a6b32631204936ec45c03f5c0f0b75bab6489a05031d59f51665fef3d7851 \
  --headless=new --no-sandbox --disable-dev-shm-usage \
  --remote-debugging-address=127.0.0.1 --remote-debugging-port=9222 \
  --user-data-dir=/tmp/blk-profile about:blank
docker inspect --format '{{.State.Running}}' "$BLKCHAIN_PLAYWRIGHT_CONTAINER"
```

CDP is container loopback, not a host-published port. The launcher starts Node inside the container,
so it reaches that endpoint there. Browser target traffic crosses the Go broker. Do not add a Docker
socket, home-directory mount, or direct network access to this container.

Verify the real browser adapter against the repository's local fixture:

```sh
(cd cli && BLKCHAIN_PW_E2E=1 go test -run '^TestWebPlaywrightE2E$' -v -count=1 -timeout 120s .)
```

Require a named `PASS`, not a skipped test. Keep the driver/container exports in the environment
that launches blk or its MCP server. The browser container is started separately from `blk up`.
For collection, select `--browser` through `blk engage web`; use `blk engage web help` for the
operator-policy and workspace arguments.

#### Optional local library advisories

Library matching uses a pinned local [RetireJS advisory repository](https://github.com/RetireJS/retire.js).
Provision its snapshot and integrity manifest from the repository root:

```sh
.venv/bin/python - <<'ADVISORIES'
import hashlib
import json
import os
from pathlib import Path
import urllib.request

os.umask(0o077)
revision = 'e644a46aa9d2bde1f7f9c82fea7ebc3a19660aa5'
expected = '557465843feee5d84b0a6d440448be44984ffa5c534b07f5bce5c7b95ff7fbd5'
url = f'https://raw.githubusercontent.com/RetireJS/retire.js/{revision}/repository/jsrepository.json'
with urllib.request.urlopen(url, timeout=30) as response:
    data = response.read((4 << 20) + 1)
if len(data) > 4 << 20 or hashlib.sha256(data).hexdigest() != expected:
    raise SystemExit('Advisory snapshot integrity check failed')
json.loads(data)
root = Path('data/advisories').resolve()
root.mkdir(parents=True, exist_ok=True)
snapshot = root / f'retire-{revision}.json'
snapshot.write_bytes(data)
manifest = {'path': str(snapshot), 'sha256': expected,
            'date': '2026-10-06', 'revision': revision}
(root / 'retire-manifest.json').write_text(json.dumps(manifest) + '\n')
print('Local advisory snapshot ready')
ADVISORIES
export BLKCHAIN_RETIRE_MANIFEST="$PWD/data/advisories/retire-manifest.json"
```

Keep the manifest path in the environment used by blk. Add it as a non-secret setting to `.env` if
needed. Snapshot updates require a new immutable revision, digest, and date.

### 11. Verify the installation and manage its lifecycle

With the native services running:

```sh
blk version
blk health --json
blk sources --json
blk search --json --top-k 5 "contextual output encoding"
blk ask --agent auto --rag "Explain contextual output encoding"
blk doctor
```

Start bare `blk` to open the terminal UI in native auto mode. `/agent NAME` selects a specialist,
`/hermes PROMPT` runs one legacy Hermes turn, and `/help` lists commands.

| Data or process | Location or control |
| --- | --- |
| Qdrant index | `<checkout>/data/qdrant_storage/` |
| Embedding log and PID | `<checkout>/.run/` |
| Preferences and default engagements | `~/.config/blkchain/`, or `XDG_CONFIG_HOME` |
| Conversation history and sessions | `~/.local/share/blk/`, or `XDG_DATA_HOME` |
| Command runner | Built by `blk engage setup`; engagement workers are managed by the harness. |
| Scanner database cache | `$XDG_CACHE_HOME/blkchain/vulndb`, or `~/.cache/blkchain/vulndb` when unset. |
| Browser container | `docker start blk-web-browser` / `docker stop blk-web-browser` |
| Native chat server | Its own foreground terminal or provider's service manager. |

`blk down` stops Qdrant and the embedding service without deleting the index. `blk up` starts them
again. `blk engage stop --workspace PATH` requests an engagement stop. Keep evidence directories
when they are needed for review or resume.

#### Public web research

Fresh REPL/TUI profiles enable web on first launch. For native one-shot CLI or MCP use, enable it explicitly. Select a provider or change the saved switch:

```sh
blk web provider duckduckgo
blk web on
blk web status
```

For Tavily, export `TAVILY_API_KEY` or `TAVILY_SETUP_TOKEN` from your secret manager, then select
`blk web provider tavily`. `blk web off` revokes native web permission. `NVD_API_KEY` is optional for
CVE lookups. Hermes provider and tool permissions are configured separately.

### Setup troubleshooting

| Symptom | Check and action |
| --- | --- |
| `blk` is not found | Add `~/.local/bin` to `PATH`, or use `cli/blk` from the checkout. |
| Go build cannot find a C compiler | Install Xcode Command Line Tools and keep CGO enabled. |
| Docker reports it cannot connect | Open Docker Desktop and wait for `docker info` to answer. |
| An image pull is denied | Authenticate to `dhi.io` and confirm access to the exact pinned image. |
| The embedding service does not become ready | Check configured model paths and `blk logs embed_server`; confirm the weights finished downloading. |
| Retrieval has no results | Check `blk sources --json`, corpus paths, collection name, and the completed indexing output. |
| Chat returns 401 or an unknown-model error | Supply the server's actual API key and use an ID returned by its `/v1/models` endpoint. |
| A default answer cannot start | Check `blk health --json` and `blk web status` for the native model and retrieval services. |
| An offline scanner reports a database gap | Run `blk engage setup`, check its output for update failures, and ensure the printed cache path is readable by Docker workers. |
| A feature binary reads another checkout's configuration | Set `BLKCHAIN_ROOT` to the intended worktree before running that binary. |
| Browser provisioning is rejected | Check all driver exports, archive/launcher hashes, the read-only package mount, and the required container settings. |

## Ingestion and data handling

The indexer accepts supplied Markdown, code/text, PDFs, supported JSON techniques, and catalog-only
wordlist metadata. Stable chunk identifiers and content hashes support resumable indexing. Resume
refreshes metadata for unchanged text while retaining its vectors. Directory adds have file and byte
limits. Public URL ingestion validates destinations, pins resolution,
rechecks redirects, and records external provenance.

Use `blk add /absolute/path/to/notes --source my-notes` for a separately managed addition. Relative
paths resolve against your current directory. Re-adding an input updates that input's chunks while
preserving other inputs with the same source label. The completion message reports additions,
updates, skipped embeddings, and deletions.

Target data, retrieved content, model text, and command output are untrusted inputs. Prompts frame
embedded instructions as data. The execution gate and broker enforce authority independently of
research text. Public URL ingestion rejects private destinations, while an engagement can authorize
private targets through explicit IP/CIDR scope. A hostname alone does not authorize its private
resolved address.

Engagement artifacts can contain raw responses, request bodies, credentials, and candidate secrets.
Display redaction does not make every saved artifact or exact export safe to share. Review selected
records and exported files before distribution and apply an appropriate retention policy.

## License

blkChain code is licensed under Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Models,
corpus content, target data, and external services retain their own terms. Review those terms before
redistribution or commercial use.
