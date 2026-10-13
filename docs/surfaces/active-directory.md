# Active Directory surface

The Active Directory surface enumerates a domain and builds identity attack
paths: from domain, forest, controller, and trust context, through anonymous and
authenticated directory enumeration, to the specific primitives that reach
privileged groups, controllers, or cross-domain trust.

Executor: `cli/adexec.go`. Persona: `ad` in `cli/domains.go`.

## Capabilities

Read-only enumeration:

- Discover domain controllers and directory hosts and the domain on in-scope
  targets (bounded `nmap -p` over the AD service set with no NSE, and `nbtscan`).
- Enumerate unauthenticated and null-session exposure where a controller permits
  it: anonymous LDAP RootDSE and base, and null SMB and RPC sessions.
- Enumerate authenticated directory contents with operator-supplied in-scope
  credentials: users, groups, computers, and password policy.
- Enumerate finding-driven targets read-only: SPN accounts, delegation flags,
  ACLs, and ADCS templates and CAs.
- Turn each finding into a principal-to-object-to-right-to-impact chain,
  prioritizing paths to privileged groups, controllers, or cross-domain trust.

Abuse primitives (exploit-tier, arm-gated), run with the impacket suite, each
taking its target as `[domain/]user[:password]@host`:

- Kerberoasting and AS-REP roasting: `GetUserSPNs.py`, `GetNPUsers.py`.
- Credential and replication impact: `secretsdump.py`.
- Ticket work: `getTGT.py`, `ticketer.py`.
- Enumeration helpers: `lookupsid.py`, `samrdump.py`, `rpcdump.py`.
- Database access: `mssqlclient.py`.
- Authenticated execution: `psexec.py`, `smbexec.py`, `wmiexec.py`.
- Relay: `ntlmrelayx.py`, with an explicit `-t` target.

Credential guessing or spraying requires an explicit account set, rate, and test
window. The persona does not modify directory state or perform high-impact
replication during recon; those run as separate evidence-linked, arm-gated tasks
that record the exact output, the affected principal and object, the privilege
gained, and any cleanup need, chained with `basis_ids`. The surface is typically
reached after a foothold, and SSH and command carriers cover it.

## Future expansion

- A finding parser set for the directory enumeration tools, so SPNs, delegation
  types, and ADCS template flags derive from structured parsers rather than
  output-shape matching.
- BloodHound-style path computation over the enumerated principals, objects, and
  rights, as a code-owned graph query against the engagement store rather than
  manual chain construction.
- Expanded ADCS coverage (the specific vulnerable-template classes) as named
  finding-driven dimensions with their own arm-gated abuse tasks.
- Trust and cross-domain enumeration as an explicit step.

The shared engagement model (the command gate, the Auto and Safe arming modes,
vantage reachability, the isolated runner, foothold carriers, and evidence
recording) is described in [the index](README.md).
