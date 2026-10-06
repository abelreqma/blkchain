package main

import "sort"

// toolcatalog.go is the single source of truth for every binary the harness may
// run inside the isolated runner. The persona prompts, the EXTERNAL-profile
// allowlist, the exploit-tier allowlist, and the wiring tests all read it, so a
// persona cannot name a tool the image lacks and a tool cannot reach the
// allowlist without a recorded audit. toolaudit.go holds the per-binary argv the
// gate must permit and must refuse.

// toolTier is the authority a tool needs to run, which is also which gate
// profile may run it.
type toolTier uint8

const (
	// tierEnum is a network or enumeration tool on the EXTERNAL-profile
	// allowlist, eligible for unattended Auto execution when the operator's
	// allowed_binaries permits it.
	tierEnum toolTier = iota
	// tierLocal is a host-introspection or analysis tool that runs only in the
	// LOCAL profile, which has no allowlist (ClassifyLocal governs) and confirms
	// every command. It stays off the EXTERNAL allowlist on purpose: in external
	// Auto, a read utility with an in-scope host operand and a file operand would
	// disclose the file, because the scope check passes on the host operand and
	// FileAccessViolation does not cover cat or grep. Keeping these off the
	// external allowlist closes that disclosure with the smallest surface.
	tierLocal
	// tierExploit never runs unattended. It needs an armed task and per-action
	// operator confirmation, which the exploit tier enforces for the exploit and
	// post-ex phases.
	tierExploit
)

// rawNeed is whether a tool needs CAP_NET_RAW, which only the raw-socket worker
// provides.
type rawNeed uint8

const (
	rawNever rawNeed = iota
	rawAlways
	// rawByFlag needs the capability only for some argv; rawSocketCommand decides
	// per command.
	rawByFlag
)

// tool is one catalog entry.
type tool struct {
	// Binary is the basename as executed.
	Binary string
	// Package is the apk package that provides it, empty for a binary the base
	// image already carries.
	Package string
	// Personas are the domains whose prompt may name this tool.
	Personas []string
	Tier     toolTier
	Raw      rawNeed
	// Probe is an argv that proves the binary exists and runs, and ProbeWant is a
	// substring its combined output must contain. Exit status is not a signal:
	// masscan --version and nbtscan both exit non-zero while working. The image
	// end-to-end test runs every entry's probe.
	Probe     []string
	ProbeWant string
	// Note records an operator-facing capability constraint.
	Note string
}

// toolCatalog is every tool the harness may run. A binary absent from here is
// absent from the allowlists and must not appear in a persona prompt.
var toolCatalog = []tool{
	// Network and service discovery.
	{
		Binary: "nmap", Package: "nmap", Tier: tierEnum, Raw: rawByFlag,
		Personas:  []string{"recon", "web", "ad", "cloud", "k8s", "container", "ai-security"},
		Probe:     []string{"--version"},
		ProbeWant: "Nmap version",
		Note:      "connect scanning runs unprivileged; -sS, -sA, -sF, -sX, -sN, -sO, -sU, -O and --traceroute need the raw-socket worker. Always pass -n: the runner has no DNS, so a reverse lookup of the target stalls the scan until the command timeout",
	},
	{
		Binary: "masscan", Package: "masscan", Tier: tierEnum, Raw: rawAlways,
		Personas:  []string{"recon"},
		Probe:     []string{"--version"},
		ProbeWant: "Masscan version",
		Note:      "SYN scanning only, so every invocation needs the raw-socket worker",
	},
	{
		Binary: "tcpdump", Package: "tcpdump", Tier: tierEnum, Raw: rawAlways,
		Personas:  []string{"recon", "ad"},
		Probe:     []string{"--version"},
		ProbeWant: "tcpdump version",
		Note:      "packet capture needs the raw-socket worker; it sees the whole guard namespace, not one worker",
	},
	{
		Binary: "ncat", Package: "nmap-ncat", Tier: tierEnum,
		Personas:  []string{"recon", "ad"},
		Probe:     []string{"--version"},
		ProbeWant: "Ncat: Version",
	},
	{
		Binary: "nc", Tier: tierEnum,
		Personas:  []string{"recon"},
		Probe:     []string{"--help"},
		ProbeWant: "BusyBox",
		Note:      "the base image's busybox nc, not the OpenBSD or Nmap build",
	},
	{
		Binary: "traceroute", Tier: tierEnum,
		Personas:  []string{"recon"},
		Probe:     []string{"--help"},
		ProbeWant: "traceroute",
	},

	// DNS.
	{
		Binary: "dig", Package: "bind-tools", Tier: tierEnum,
		Personas:  []string{"recon", "web", "ad", "cloud"},
		Probe:     []string{"-v"},
		ProbeWant: "DiG 9",
	},
	{
		Binary: "host", Package: "bind-tools", Tier: tierEnum,
		Personas:  []string{"recon", "web", "ad"},
		Probe:     []string{"-V"},
		ProbeWant: "host 9",
	},
	{
		Binary: "nslookup", Package: "bind-tools", Tier: tierEnum,
		Personas:  []string{"recon"},
		Probe:     []string{"-version"},
		ProbeWant: "nslookup 9",
	},
	{
		Binary: "whois", Tier: tierEnum,
		Personas:  []string{"recon"},
		Probe:     []string{"--help"},
		ProbeWant: "BusyBox",
		Note:      "the base image's busybox whois",
	},

	// SMB, RPC, NetBIOS, NFS.
	{
		Binary: "smbclient", Package: "samba-client", Tier: tierEnum,
		Personas:  []string{"recon", "ad"},
		Probe:     []string{"--version"},
		ProbeWant: "Version 4",
	},
	{
		Binary: "rpcclient", Package: "samba-client", Tier: tierEnum,
		Personas:  []string{"recon", "ad"},
		Probe:     []string{"--version"},
		ProbeWant: "Version 4",
	},
	{
		Binary: "nbtscan", Package: "nbtscan", Tier: tierEnum,
		Personas:  []string{"recon", "ad"},
		Probe:     []string{"-v"},
		ProbeWant: "Usage",
	},
	{
		Binary: "showmount", Package: "nfs-utils", Tier: tierEnum,
		Personas:  []string{"recon"},
		Probe:     []string{"--version"},
		ProbeWant: "showmount for",
	},

	// Directory, identity, SNMP.
	{
		Binary: "ldapsearch", Package: "openldap-clients", Tier: tierEnum,
		Personas:  []string{"recon", "ad"},
		Probe:     []string{"-VV"},
		ProbeWant: "OpenLDAP",
	},
	{
		Binary: "snmpwalk", Package: "net-snmp-tools", Tier: tierEnum,
		Personas:  []string{"recon"},
		Probe:     []string{"--version"},
		ProbeWant: "NET-SNMP version",
	},
	{
		Binary: "kinit", Package: "krb5", Tier: tierEnum,
		Personas:  []string{"ad"},
		Probe:     []string{},
		ProbeWant: "Unable to identify",
		Note:      "the KDC is resolved from the realm through DNS and krb5.conf, so the destination is not visible to the scope extractor; the guard firewall is the enforcing layer",
	},
	{
		Binary: "klist", Package: "krb5", Tier: tierEnum,
		Personas:  []string{"ad"},
		Probe:     []string{"-V"},
		ProbeWant: "Kerberos 5 version",
	},

	// Web and TLS.
	{
		Binary: "curl", Package: "curl", Tier: tierEnum,
		Personas:  []string{"recon", "web", "ad", "cloud", "k8s", "container", "ai-security", "generic"},
		Probe:     []string{"--version"},
		ProbeWant: "curl 8",
	},
	{
		Binary: "ffuf", Package: "ffuf", Tier: tierEnum,
		Personas:  []string{"recon", "web"},
		Probe:     []string{"-V"},
		ProbeWant: "ffuf version",
		Note:      "the image stages no wordlist, so -w must name a file the executor wrote into its working directory",
	},
	{
		Binary: "sslscan", Package: "sslscan", Tier: tierEnum,
		Personas:  []string{"recon", "web"},
		Probe:     []string{"--version"},
		ProbeWant: "2.2.0",
	},
	{
		Binary: "openssl", Package: "openssl", Tier: tierEnum,
		Personas:  []string{"recon", "web"},
		Probe:     []string{"version"},
		ProbeWant: "OpenSSL 3",
	},
	{
		Binary: "jq", Package: "jq", Tier: tierEnum,
		Personas:  []string{"web", "cloud", "k8s", "ai-security"},
		Probe:     []string{"--version"},
		ProbeWant: "jq-1",
	},

	// Binary and host analysis. Every one of these reads a path rather than a
	// host, so the target-channel class does not apply.
	{
		Binary: "file", Package: "file", Tier: tierLocal,
		Personas:  []string{"target-analysis", "exploit-dev", "local"},
		Probe:     []string{"--version"},
		ProbeWant: "file-5",
	},
	{
		Binary: "strings", Package: "binutils", Tier: tierLocal,
		Personas:  []string{"target-analysis", "exploit-dev"},
		Probe:     []string{"--version"},
		ProbeWant: "GNU strings",
	},
	{
		Binary: "nm", Package: "binutils", Tier: tierLocal,
		Personas:  []string{"target-analysis", "exploit-dev"},
		Probe:     []string{"--version"},
		ProbeWant: "GNU nm",
	},
	{
		Binary: "objdump", Package: "binutils", Tier: tierLocal,
		Personas:  []string{"target-analysis", "exploit-dev"},
		Probe:     []string{"--version"},
		ProbeWant: "GNU objdump",
	},
	{
		Binary: "readelf", Package: "binutils", Tier: tierLocal,
		Personas:  []string{"target-analysis", "exploit-dev"},
		Probe:     []string{"--version"},
		ProbeWant: "GNU readelf",
	},
	{
		Binary: "ldd", Tier: tierLocal,
		Personas:  []string{"target-analysis", "exploit-dev"},
		Probe:     []string{},
		ProbeWant: "musl libc",
		Note:      "musl ldd is the dynamic loader, which may run code from the inspected file; readelf -d answers the same question without loading it",
	},
	{
		Binary: "getcap", Package: "libcap-utils", Tier: tierLocal,
		Personas:  []string{"target-analysis", "local"},
		Probe:     []string{},
		ProbeWant: "usage: getcap",
	},

	// Local post-access enumeration. The base image provides these; they read
	// local state and name no host.
	{Binary: "id", Tier: tierLocal, Personas: []string{"local"}, Probe: []string{}, ProbeWant: "uid="},
	{Binary: "whoami", Tier: tierLocal, Personas: []string{"local"}, Probe: []string{}, ProbeWant: ""},
	{Binary: "hostname", Tier: tierLocal, Personas: []string{"local"}, Probe: []string{}, ProbeWant: ""},
	{Binary: "uname", Tier: tierLocal, Personas: []string{"local"}, Probe: []string{"-a"}, ProbeWant: "Linux"},
	{Binary: "stat", Tier: tierLocal, Personas: []string{"local", "target-analysis"}, Probe: []string{"/etc/hostname"}, ProbeWant: "File:"},
	{Binary: "mount", Tier: tierLocal, Personas: []string{"local"}, Probe: []string{}, ProbeWant: " on "},
	{Binary: "ps", Tier: tierLocal, Personas: []string{"local"}, Probe: []string{}, ProbeWant: "PID"},
	{Binary: "netstat", Tier: tierLocal, Personas: []string{"local"}, Probe: []string{"-ln"}, ProbeWant: "Active"},
	{Binary: "lsof", Tier: tierLocal, Personas: []string{"local"}, Probe: []string{}, ProbeWant: ""},
	{Binary: "crontab", Tier: tierLocal, Personas: []string{"local"}, Probe: []string{"-l"}, ProbeWant: ""},
	{
		Binary: "sudo", Tier: tierLocal,
		Personas:  []string{"local"},
		Probe:     nil,
		ProbeWant: "",
		Note:      "deliberately absent from the image: a setuid-root binary in the sandbox is a regression for no benefit. Only the exact sudo -l listing is permitted, for a local engagement that runs on a real host",
	},

	// Cloud and cluster. Both reach remote code execution and state change
	// through ordinary subcommands, so neither can run unattended.
	{
		Binary: "aws", Package: "aws-cli", Tier: tierExploit,
		Personas:  []string{"cloud"},
		Probe:     []string{"--version"},
		ProbeWant: "aws-cli/2",
		Note:      "Azure and GCP have no Alpine package, so the cloud persona has a provider CLI for AWS only",
	},
	{
		Binary: "kubectl", Package: "kubectl", Tier: tierExploit,
		Personas:  []string{"k8s", "container"},
		Probe:     []string{"version", "--client=true"},
		ProbeWant: "Client Version",
	},

	// Exploitation and cracking.
	{
		Binary: "socat", Package: "socat", Tier: tierExploit,
		Personas:  []string{"recon", "exploit-dev"},
		Probe:     []string{"-V"},
		ProbeWant: "socat by",
		Note:      "address specs carry code execution (EXEC, SYSTEM, SHELL) and file access (OPEN, CREATE, GOPEN), so only the TCP, TCP4, TCP6, OPENSSL, UDP and STDIO specs are permitted",
	},
	{
		Binary: "gdb", Package: "gdb", Tier: tierExploit,
		Personas:  []string{"exploit-dev"},
		Probe:     []string{"--version"},
		ProbeWant: "GNU gdb",
		Note:      "static inspection only: -x, --command, -ex and -p run code or attach to a process and are denied",
	},
	{
		Binary: "john", Package: "john", Tier: tierExploit,
		Personas:  []string{"ad", "exploit-dev"},
		Probe:     []string{"--list=build-info"},
		ProbeWant: "Version: 1.9.0-jumbo",
	},
	{
		Binary: "secretsdump.py", Package: "py3-impacket", Tier: tierExploit,
		Personas:  []string{"ad"},
		Probe:     []string{"--help"},
		ProbeWant: "Impacket",
	},
	{
		Binary: "GetUserSPNs.py", Package: "py3-impacket", Tier: tierExploit,
		Personas:  []string{"ad"},
		Probe:     []string{"--help"},
		ProbeWant: "Impacket",
	},
	{
		Binary: "GetNPUsers.py", Package: "py3-impacket", Tier: tierExploit,
		Personas:  []string{"ad"},
		Probe:     []string{"--help"},
		ProbeWant: "Impacket",
	},
	{
		Binary: "getTGT.py", Package: "py3-impacket", Tier: tierExploit,
		Personas:  []string{"ad"},
		Probe:     []string{"--help"},
		ProbeWant: "Impacket",
	},
	{
		Binary: "lookupsid.py", Package: "py3-impacket", Tier: tierExploit,
		Personas:  []string{"ad"},
		Probe:     []string{"--help"},
		ProbeWant: "Impacket",
	},
	{
		Binary: "rpcdump.py", Package: "py3-impacket", Tier: tierExploit,
		Personas:  []string{"ad", "recon"},
		Probe:     []string{"--help"},
		ProbeWant: "Impacket",
	},
	{
		Binary: "samrdump.py", Package: "py3-impacket", Tier: tierExploit,
		Personas:  []string{"ad"},
		Probe:     []string{"--help"},
		ProbeWant: "Impacket",
	},
	{
		Binary: "mssqlclient.py", Package: "py3-impacket", Tier: tierExploit,
		Personas:  []string{"ad"},
		Probe:     []string{"--help"},
		ProbeWant: "Impacket",
	},
	{
		Binary: "psexec.py", Package: "py3-impacket", Tier: tierExploit,
		Personas:  []string{"ad"},
		Probe:     []string{"--help"},
		ProbeWant: "Impacket",
	},
	{
		Binary: "smbexec.py", Package: "py3-impacket", Tier: tierExploit,
		Personas:  []string{"ad"},
		Probe:     []string{"--help"},
		ProbeWant: "Impacket",
	},
	{
		Binary: "wmiexec.py", Package: "py3-impacket", Tier: tierExploit,
		Personas:  []string{"ad"},
		Probe:     []string{"--help"},
		ProbeWant: "Impacket",
	},
	{
		Binary: "ntlmrelayx.py", Package: "py3-impacket", Tier: tierExploit,
		Personas:  []string{"ad"},
		Probe:     []string{"--help"},
		ProbeWant: "Impacket",
	},
	{
		Binary: "ticketer.py", Package: "py3-impacket", Tier: tierExploit,
		Personas:  []string{"ad"},
		Probe:     []string{"--help"},
		ProbeWant: "Impacket",
	},
}

// unavailableTools are tools a persona prompt must not name, with the reason. A
// gate audit for one of these stays in place: it costs nothing and protects an
// operator who adds the binary through allowed_binaries.
var unavailableTools = map[string]string{
	"gobuster":    "no Alpine package on either architecture; ffuf covers directory, DNS and vhost fuzzing",
	"nikto":       "no Alpine package on either architecture; curl plus the web collection path covers its checks",
	"onesixtyone": "no Alpine package on either architecture; snmpwalk with an explicit community string covers SNMP enumeration",
	"dnsrecon":    "the Alpine package imports the stamina module, which has no Alpine package, so the tool fails at startup; dig, host and nslookup cover DNS enumeration",
	"wget":        "the base image provides only busybox wget, whose flag surface differs from the audited GNU build; curl covers retrieval",
	"hashcat":     "needs an OpenCL runtime the image does not carry; john covers offline cracking",
}

// toolFor returns the catalog entry for a binary basename.
func toolFor(binary string) (tool, bool) {
	for _, t := range toolCatalog {
		if t.Binary == binary {
			return t, true
		}
	}
	return tool{}, false
}

// toolsForPersona returns the catalog entries a persona's prompt may name, in
// catalog order.
func toolsForPersona(persona string) []tool {
	var out []tool
	for _, t := range toolCatalog {
		for _, p := range t.Personas {
			if p == persona {
				out = append(out, t)
				break
			}
		}
	}
	return out
}

// catalogBinaries returns every binary in the catalog that the image ships, in
// sorted order. sudo is excluded: it is catalogued for its gate exception, not
// installed.
func catalogBinaries() []string {
	var out []string
	for _, t := range toolCatalog {
		if t.Probe == nil {
			continue
		}
		out = append(out, t.Binary)
	}
	sort.Strings(out)
	return out
}

// catalogPackages returns the distinct apk packages the catalog requires, in
// sorted order. It is the set packages.list must declare.
func catalogPackages() []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range toolCatalog {
		if t.Package == "" || seen[t.Package] {
			continue
		}
		seen[t.Package] = true
		out = append(out, t.Package)
	}
	sort.Strings(out)
	return out
}

// enumToolBinaries returns the tierEnum binaries: the EXTERNAL-profile
// allowlist candidates. A candidate reaches the allowlist only once its flag
// surface is audited, which externalEngageAllowlist enforces.
func enumToolBinaries() []string {
	var out []string
	for _, t := range toolCatalog {
		if t.Tier == tierEnum {
			out = append(out, t.Binary)
		}
	}
	sort.Strings(out)
	return out
}

// localToolBinaries returns the tierLocal binaries: host-introspection and
// analysis tools the LOCAL profile runs under per-command confirmation.
func localToolBinaries() []string {
	var out []string
	for _, t := range toolCatalog {
		if t.Tier == tierLocal {
			out = append(out, t.Binary)
		}
	}
	sort.Strings(out)
	return out
}

// exploitToolBinaries returns the tierExploit binaries: the code-owned default
// exploit-tier catalog that the operator's exploit_tools extends. None of them
// may appear in an unattended allowlist.
func exploitToolBinaries() []string {
	var out []string
	for _, t := range toolCatalog {
		if t.Tier == tierExploit {
			out = append(out, t.Binary)
		}
	}
	sort.Strings(out)
	return out
}

// rawSocketCommand reports whether a command needs the raw-socket worker. It
// reads the catalog and the argv only: no prompt, corpus, or model text selects
// the worker. An unknown binary never routes raw.
func rawSocketCommand(binary string, args []string) bool {
	t, ok := toolFor(binary)
	if !ok {
		return false
	}
	switch t.Raw {
	case rawAlways:
		return true
	case rawByFlag:
		return rawScanFlag(binary, args)
	}
	return false
}

// nmapRawFlags are the nmap scan modes that need raw sockets. Each is an exact
// argv token: nmap takes no abbreviation for a scan-type flag.
var nmapRawFlags = map[string]bool{
	"-sS": true, "-sA": true, "-sF": true, "-sX": true, "-sN": true,
	"-sO": true, "-sU": true, "-sM": true, "-sW": true, "-sY": true, "-sZ": true,
	"-O": true, "--traceroute": true, "-PE": true, "-PP": true, "-PM": true,
}

// rawScanFlag reports whether argv selects a raw-socket mode of a rawByFlag
// tool.
func rawScanFlag(binary string, args []string) bool {
	if binary != "nmap" {
		return false
	}
	for _, a := range args {
		if nmapRawFlags[a] {
			return true
		}
	}
	return false
}
