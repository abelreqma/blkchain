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
- Run a bounded, audited tool set: DNS (`host`, `dig`, `nslookup`); registration
  data (`whois`); SMB and NetBIOS (`smbclient`, `rpcclient`, `nbtscan`,
  `showmount`); LDAP (`ldapsearch`); SNMP (`snmpwalk`); HTTP and content
  discovery (`ffuf`, `curl`); TLS (`sslscan`, `openssl s_client`); path and
  service interaction (`traceroute`, `ncat`, `nc`); packet capture (`tcpdump`);
  and service detection and probing (`nmap`, `nping`, `ike-scan`).
- Scan within enforced bounds. `nmap` takes `-n` and must carry a port bound
  (`-p` with a port spec, `--top-ports`, or `-F`) or be a `-sn` host-discovery
  scan of exactly one host; an otherwise unbounded `nmap` is refused. `-sS`,
  `-sU`, and `-O` are available for a raw scan, and `--script` and `--datadir`
  are denied because NSE runs arbitrary Lua. `nping` takes one literal IP, one
  port, `-c 1-3` and `--rate 1`, with up to 512 hex bytes of UDP `--data`.
  `ike-scan` runs only against a UDP port already observed. `tcpdump` needs a
  `-c` packet bound and a host filter. Decoy and spoofed-source packet paths are
  denied, because the worker cannot constrain their source. A CIDR range is a
  valid `nmap` target when the policy authorizes that range.
- Separate what a probe establishes from what it suggests: a completed `nmap`
  result can establish a port state, while ACK, FIN, NULL, Xmas, idle,
  fragmented, and source-port diagnostic scans explain a filter rather than
  establish service reachability, and a TCP accept permits a protocol check
  without identifying the service.
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
- A guarded fast port scanner. `masscan` is deliberately absent: its raw Ethernet
  packets leave the worker's destination guard behind, so bounded `nmap` scans
  are the guarded equivalent today and a request for `masscan` is refused with
  that reason.

The shared engagement model (the command gate, the Auto and Safe arming modes,
vantage reachability, the isolated runner, foothold carriers, and evidence
recording) is described in [the index](README.md).
