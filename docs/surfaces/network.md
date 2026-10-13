# Network surface

The network surface maps targets over IP: which hosts are up, which ports and
services they expose, what versions those services run, and which of them is a
validation lead. It is the entry surface for most engagements and the one from
which other surfaces are discovered.

Executor: `cli/networkexec.go`. Persona: `recon` in `cli/domains.go` (or `wifi`
for a `wifi`-kind task).

## Capabilities

- Host discovery: confirm which in-scope hosts are up.
- Port and service discovery: find open ports and the services behind them.
- Service version fingerprinting using safe detection only (no arbitrary NSE
  scripts).
- Finding-driven targeted enumeration from what the earlier steps found.
- Run a bounded, audited tool set: DNS (`host`, `dig`, `nslookup`); SMB and
  NetBIOS (`smbclient`, `rpcclient`, `nbtscan`, `showmount`); LDAP
  (`ldapsearch`); SNMP (`snmpwalk`); HTTP and content discovery (`ffuf`,
  `curl`); TLS (`sslscan`, `openssl s_client`); path and service interaction
  (`traceroute`, `ncat`); and service detection (`nmap`, `masscan`).
- Scan within enforced bounds: `nmap` takes `-n` and must carry a port or timing
  bound (an unbounded `nmap` is refused); `-sS`, `-sU`, and `-O` are available
  for a raw scan; `masscan` needs a port bound and an explicit `--rate`;
  `tcpdump` needs a `-c` packet bound and a host filter. A CIDR range is a valid
  target for either scanner when the policy authorizes it.
- Shift technique emphasis by vantage: from an external vantage, host, port, and
  service enumeration; from an internal foothold, internal SMB, LDAP, and SNMP
  exposure and lateral-movement surface.
- Record evidence with host, port, service, observed version, the command, and
  the exact output, treating version strings as leads until corroborated, and
  chain an open service to its matching surface, a new in-scope host to a fresh
  recon task, and a credential finding to an approved auth or lateral task.

All of the above is read-only reconnaissance. State-changing or exploit actions
move to an exploit or post-exploitation task, which is arm-gated. The surface is
reachable from an external vantage, and SSH and command carriers cover it from a
foothold.

## Future expansion

- A dedicated wireless command surface. The `wifi` persona exists and is selected
  for a `wifi`-kind task, but the executor has no wireless-specific command tool
  today and reports the missing capability as a coverage gap rather than
  substitute unrelated network commands. The expansion is a registered wireless
  tool and a wireless recon ladder (discovery, encryption and authentication
  assessment, client isolation, management-frame protection, authorized client
  compromise).
- Vantage-specific internal recon ladders, so internal SMB and LDAP enumeration
  and lateral-movement mapping are code-structured rather than prompt-steered.
- Protocol-specific finding parsers, so findings derive from dedicated parsers
  rather than leaning on a single tool's output shape.

The shared engagement model (the command gate, the Auto and Safe arming modes,
vantage reachability, the isolated runner, foothold carriers, and evidence
recording) is described in [the index](README.md).
