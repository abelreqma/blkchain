# Assessment surfaces

An engagement surface is the kind of target a task runs against. `blk engage`
assigns every task a surface, and the surface decides three things: which
executor runs the task, which recon ladder structures its enumeration, and which
persona prompt and tool rules the model works under. This directory documents
each surface in detail. This file documents the model they all share, so the
per-surface files do not repeat it.

See [pivot-and-vantage.md](pivot-and-vantage.md) first: the pivot and vantage
chain connects the surfaces into a single lateral-movement engagement rather than
a set of independent scanners. The per-surface files describe what each surface
does; that file describes how an engagement moves between them.

The surfaces are:

| Surface | File | Short description |
| --- | --- | --- |
| network | [network.md](network.md) | Host, port, and service enumeration over IP, external or internal. |
| web | [web.md](web.md) | Web application and API analysis, traffic and source collection, external-surface sweeps. |
| active-directory | [active-directory.md](active-directory.md) | Domain enumeration and identity attack paths: Kerberos, delegation, ACLs, ADCS. |
| cloud | [cloud.md](cloud.md) | AWS, GCP, and Azure exposure, metadata-credential, storage, and IAM paths. |
| container | [container.md](container.md) | Kubernetes and container runtime surfaces, RBAC, and escape paths. |
| ai-security | [ai-security.md](ai-security.md) | LLM and AI endpoint assessment under OWASP LLM Top 10 and MITRE ATLAS. |
| local | [local.md](local.md) | Linux post-access enumeration and privilege escalation, plus binary analysis. |

## How a surface task runs

Every surface uses one shared execution path. The surface-specific code is small
on purpose: it registers an executor factory, a recon ladder, and a persona, and
the shared `genericExecutor` does the rest.

- `cli/surfaceexec.go` holds the executor registry. `executorFor` selects a
  surface's registered executor, or falls back to `genericExecutor` for a surface
  that has not registered one. Most surface executors embed `genericExecutor` and
  override only the recon driver, so they inherit the vantage check, the gate
  stamping, the exploit and post-exploitation lifecycle, and the evidence capture
  unchanged.
- `cli/recon_ladder.go` holds the recon ladders. A ladder is an ordered list of
  tiers, each naming the coverage dimensions it is responsible for. Code owns the
  tiers and their order; the model only proposes commands within the current
  tier. A surface without a dedicated ladder uses `genericReconLadder`, a single
  bounded enumerate pass.
- `cli/domains.go` holds the personas. `domainForTask` maps a task to its persona
  by task kind first, then by surface. The persona is the system prompt the
  executor runs under. It names the domain, the method, the exact tools, and the
  tool-specific gate rules the model must work within.

## Vantage: what a surface can reach

An engagement has a vantage, the position execution runs from. `genericExecutor`
refuses a task whose surface the current vantage does not reach, so a locked
surface cannot be entered before the vantage that unlocks it. An unset vantage is
unrestricted. A store read error fails closed: the task does not run rather than
proceed ungated. This is what makes an engagement a chain rather than a flat
scan: external recon runs first, access is gained and recorded as evidence, the
operator approves any discovered private network, a carrier is attached, and only
then do internal surfaces become reachable.

## Recon, exploit, and arming

A task carries a phase. Recon-phase tasks run the tier ladder and are read-only
enumeration. Exploit and post-exploitation tasks run through the command gate
under the current execution policy. The gate derives a per-command tier from the
surface, the phase, and whether the task is armed (`tier = f(surface, phase,
armed)`, derived at gate time, never stored).

Candidates start unarmed. Only code may arm them, from the operator-approved
policy. An exploit-tier tool runs only from an armed task. The two modes then
differ: in Safe mode every exploit or post-exploitation action is confirmed
interactively before it runs, while in Auto an action the RoE automation policy
authorizes runs without a per-action prompt and an action the policy does not
authorize still requires one. No model-supplied or corpus-supplied text can arm a
task, choose a target, or change a gate verdict; every candidate field is
code-derived, and no gate verdict reads a model-supplied technique or citation.

## The command gate

Every `run_command` call passes `cli/internal/secgate` before execution. The gate
checks, from code-derived facts only: the target against the sealed scope, the
action class against the policy, the binary against the audited catalog, the flag
spellings against the structural denials (shells, interpreters, exec wrappers,
code-execution flags, file-write and file-read-exfil flags, config indirection,
and glued or bundled target flags that would hide a destination from the scope
check), and the resource bounds against the episode caps. A command that names no
verifiable target fails closed. An empty or ambiguous scope permits nothing.

Retrieved corpus text and model output are advisory. They can suggest a technique
and supply a citation label, but they never authorize an action. Tool output and
target responses are wrapped as untrusted before they re-enter the model context.

## The runner

Surface commands run in an isolated worker container that joins a guard
container's network namespace. The guard pins a firewall to the in-scope
addresses, so the worker's egress is bounded to scope at the network boundary as
well as in the gate. The worker is read-only, drops all capabilities, runs
non-root (the raw-socket worker holds only `NET_RAW`), and is bounded on memory,
CPU, pids, file descriptors, file size, and a tmpfs workspace. Offline OSV and
Grype databases mount read-only.

## Footholds and pivoting

The declared foothold is the one deliberate exception to the runner's network
guard. A command carried to an operator-declared foothold runs on a host whose
egress is not ours to filter, so its scope is enforced by the command gate alone.
Five carrier transports exist: SSH and an arbitrary-argv command carrier (which
cover local, network, web, AD, container, AWS, and GCP surfaces), and raw
loopback shell, Metasploit RPC, and HTTP form carriers (which cover command
surfaces only and cannot carry the binary TCP stream the web broker needs). Every
foothold address must be in scope, the foothold is sealed into the policy so a
resume with a different foothold is refused, and every pivoted action records its
destination. Approved private CIDRs are held separately from the sealed RoE and
apply only to foothold-covered surfaces.

## Cross-cutting capabilities

Two capabilities feed every surface rather than being surfaces of their own:

- External-surface sweeps (`cli/extsurface.go`, `cli/internal/webacquire`): when a
  recon task names an HTTP origin, code-owned probes characterize TLS, headers,
  cookies, CORS, methods, metadata paths, and subdomains, each census run
  alongside random same-host controls so a finding is a delta rather than an
  absolute. TLS runs first because its certificate names feed subdomain
  derivation. Each result is stored as a surface record bound to the output it
  came from. A failed probe records a gap; derived names do not expand scope.
- Dependency and advisory scanning (`vuln-analysis` task kind): OSV and Grype run
  offline against databases prepared by `blk engage setup`. A dispatched
  `vuln-analysis` task with a recognized in-scope HTTP or HTTPS manifest URL may
  fetch it through the gate before scanning. Scanner output is evidence linked to
  task and advisory records. A missing database or failed scan records a gap, not
  a clean result. A package and version match does not establish reachable code or
  attacker impact.

## Evidence and chaining

Every surface records exact-quote evidence for material findings into the
engagement store (SQLite, with action records, surface records, advisory records,
a provenance graph, and coverage records). A finding chains to the next task with
`plan_add` and `basis_ids` set to the source task, so the engagement graph records
why each step followed the last. Completion is recorded with the cited evidence;
blkChain verifies that the cited evidence exists, not that the stated done-when
condition is independently true.
