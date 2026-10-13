# The pivot and vantage chain

An engagement is not a flat list of commands run against reachable targets. It is
a chain: the operator starts outside, gains access, the position advances, new
surfaces open from the new position, and each move is carried through a declared
foothold, checked against the sealed policy, and recorded. The engagement
progresses from one vantage to the next, and every hop is enforced in scope.

The other surface documents describe what each surface does. This one describes
how an engagement moves between them.

## Vantage: the spine

An engagement has a vantage, the position execution runs from. It advances
monotonically as access-yielding exploits succeed. The levels are defined in
`cli/internal/engagement/vantage.go`:

| Rank | Vantage | Meaning |
| --- | --- | --- |
| 0 | external-unauth | Outside, no credentials. The default seed. |
| 1 | external-auth | Outside, but holding a valid session or credential. |
| 2 | internal-foothold | Executing from inside, on a declared foothold host. |
| 3 | local-elevated | Elevated (for example root) on a foothold host. |
| 4 | lateral-domain | Moved laterally across the internal or domain boundary. |

`Vantage.Reaches(surface)` decides what the current position can touch. The
externally reachable surfaces (network, web, cloud, container, ai-security, and
AD) are reachable at any vantage. The local surface requires internal-foothold or
better, because a host cannot be enumerated for privilege escalation until
execution is on it. An unset vantage is unrestricted. `genericExecutor` refuses a task whose
surface the current vantage does not reach, and a store read error fails closed:
the task does not run rather than proceed ungated.

Vantage advances only through code, from an access-yielding exploit that the
operator-approved policy permits. No model-supplied or corpus-supplied text can
advance it. Exploit output alone cannot advance an external vantage to an internal
foothold; an operator attaches a carrier to an evidenced, armed exploit task after
approving its private network, and resume validates the attachment, pins its IP in
the guard, probes execution through the carrier, and only then advances the
vantage.

## Carriers: how a command reaches a pivoted host

The declared foothold is the one deliberate exception to the runner's network
guard. A command carried to an operator-declared foothold runs on a host whose
egress is not ours to filter, so its scope is enforced by the command gate alone.
Five carrier transports exist:

| Carrier | Reaches surfaces | Mechanism |
| --- | --- | --- |
| SSH (default) | local, network, web, AD, container, AWS, GCP | Forwards the checked TCP stream; needs `user=` and `key=`. |
| command (argv prefix) | local, network, web, AD, container, AWS, GCP | Carries the command behind an operator-supplied argv prefix, for example `kubectl exec -i web-0 --`, for access SSH cannot reach. |
| raw-session | command surfaces only | A retained loopback POSIX shell, attached after access evidence; survives stop and resume until the wall budget expires. |
| msf-rpc | command surfaces only | A Metasploit command-shell session over a loopback MessagePack service, peer-checked against the approved foothold IP. |
| http-form | command surfaces only | A bounded POST command field to an in-scope IP URL through the guarded worker; requires a command receipt. |

SSH and command carriers forward the binary TCP stream the web broker needs, so
they cover the web surface. Raw, Metasploit RPC, and HTTP form carriers do not
provide that stream and cover command surfaces only. On a pivoted web surface the
host-side broker validates every request and redirect against the pivot scope,
resolves hostnames through the foothold, and dials the checked IP through the
carrier.

## The control property

Every property below is enforced in code, not asserted in a prompt:

- The foothold address must be in scope, and the foothold is sealed into the
  policy, so a resume with a different foothold is refused.
- A command carried to the foothold is authorized by the command gate from
  code-derived facts (scope, action class, binary, flags, bounds). The foothold's
  egress is not ours to firewall, so the gate is the control, not the runner's
  network namespace.
- Every pivoted action records its destination.
- Approved private CIDRs are held separately from the sealed RoE and apply only to
  foothold-covered surfaces. They do not widen the worker's direct network guard.
- The surface of a task decides whether it pivots, so no model or corpus text can
  move execution.
- A check that establishes a file's identity by resolving a path cannot speak for
  a file on the foothold, because this host's PATH and symlinks describe this host.
  Such a check compares lexically for a pivoted command and fails closed on a
  spelling it cannot resolve. This is why a pivoted target-analysis task must name
  its inspection tool by absolute path.
- AWS and GCP provider CLI commands additionally require a separate operator
  approval tied to engagement evidence and a credential file on a foothold that
  covers the matching cloud surface.

## What an engagement reads as

The engagement store already records the spine: the current vantage (in the meta
table) and every advance, dispatch, foothold attach, and recon tier (in the
transition table, via `Transitions()`), with action records carrying their
destination and findings chaining by `basis_ids`. Presented around that spine, an
engagement reads as a lateral-movement narrative rather than a rev-ordered scan
log. The following is an illustrative example of that narrative shape; the ids,
hosts, and findings are sample data, not a real capture.

```
ENGAGEMENT  acme-staging            policy 0856c810  sealed
Lateral path: external-unauth -> external-auth -> internal-foothold -> local-elevated

[0] EXTERNAL-UNAUTH                                     vantage seeded, rev 1
    exercised: web, network
    a-0003  nmap -sS -F -n 203.0.113.10         -> ALLOWED  80,443 open
    a-0007  curl https://app.acme.test/         -> ALLOWED  200, Express 4.18
    finding f1  exposed /api/debug (web)              basis a-0007
    >> advanced by exploit t4 (web): auth bypass on /api/debug, session minted
       scope-checked, recorded a-0012

[1] EXTERNAL-AUTH                                       rev 9
    exercised: web (role: app-user)
    a-0014  replay GET /api/users/{id}  role=app-user -> ALLOWED  IDOR, 1041 records
    finding f2  IDOR -> credential disclosure (web)    basis a-0014
    >> advanced by exploit t9 (web): recovered SSH key for svc-deploy
       operator approved private CIDR 10.0.20.0/24
       SSH carrier attached to 10.0.20.9  (in scope)  recorded a-0021

[2] INTERNAL-FOOTHOLD   via SSH carrier -> 10.0.20.9    rev 18
    exercised: network, local, ad  (pivoted hops gated by the command gate)
    a-0024  [pivot 10.0.20.9] id                -> ALLOWED  uid=1000(svc-deploy)
    a-0026  [pivot 10.0.20.9] nmap -sS -F -n 10.0.20.0/24 -> ALLOWED  3 hosts, SMB/LDAP
    a-0029  [pivot 10.0.20.9] GetUserSPNs.py ... -> DENIED   exploit-tier, task not armed
    finding f3  kerberoastable svc-sql (ad)            basis a-0026
    >> advanced by exploit t15 (local): sudo misconfig -> root
       scope enforced by the command gate (foothold egress), recorded a-0033

[3] LOCAL-ELEVATED      on 10.0.20.9                    rev 31
    exercised: local (root), network, ad
    a-0035  [pivot 10.0.20.9] cat /etc/krb5.keytab -> ALLOWED  (evidence, redacted)
    open: t15-chain -> lateral-domain (armed, awaiting operator confirm in Safe mode)

SEALED POLICY HELD: 1 action denied for scope, 1 for arming. 0 out-of-scope hops.
Every pivoted action pinned to an approved foothold IP and recorded.
```

In this shape each segment is a vantage, each arrow is the specific exploit or
carrier attach that advanced it, each pivoted hop shows its destination and its
gate verdict, and the footer is the control summary. "Exercised" names the
surfaces actually worked in that segment, which is narrower than what
`Reaches()` would permit from that vantage.

## Planned expansion

The data for this narrative is already in the store. The planned work is the
renderer: present the engagement report, and the live progress view in the REPL
and TUI, grouped by vantage segment as above, rather than as the current
rev-ordered timeline. The engagement report and the live REPL and TUI progress
views render the same vantage segmentation from one code path, so all three stay
consistent. This is a rendering change over existing records, not new capability
and not a change to the gate.
