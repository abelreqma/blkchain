package main

import (
	"strings"

	"blkchain/cli/internal/retrieval"
)

// personas.go routes a grounded answer to a domain-expert persona chosen from
// what retrieval actually returned. A persona is a specialist preamble plus the
// shared answerConstraints (llm.go), so every persona keeps the same grounding,
// citation, payload-generation, no-fabrication, and untrusted-source rules; only
// the expertise framing changes. No LLM call: the domain is derived from the
// retrieved chunks' source/path/section/CWE tokens.
type persona struct {
	label    string   // cue shown to the operator ("answering as <label>")
	preamble string   // replaces answerGenericPreamble
	signals  []string // lowercase substrings matched against a chunk's metadata
}

// personas maps a domain key to its specialist. The generic fallback (key "")
// is intentionally absent: personaPrompt returns answerSystemPrompt for it and
// personaLabel returns "" (no cue).
var personas = map[string]persona{
	"web": {"web application security expert",
		"You are an expert web application penetration tester for authorized testing. ",
		[]string{"xss", "sqli", "sql-injection", "ssrf", "idor", "ssti", "xxe", "csrf", "jwt", "oauth", "graphql", "file-upload", "file upload", "request-smuggling", "request smuggling", "open-redirect", "open redirect", "pentesting-web", "web-app", "wstg", "login-bypass", "waf-bypass", "waf bypass", "deserialization", "parameter-pollution"}},
	"ad": {"Active Directory attack expert",
		"You are an expert Active Directory attacker and red teamer for authorized testing. ",
		[]string{"active-directory", "active directory", "kerberoast", "kerberos", "ntlm", "ldap", "bloodhound", "adcs", "powerview", "delegation", "dcsync", "asreproast"}},
	"cloud": {"cloud security expert",
		"You are an expert cloud security and penetration testing specialist for authorized testing. ",
		[]string{"pentesting-cloud", "aws-security", "aws security", "azure", "gcp", "cloud", "imds", "metadata-service", "169.254.169.254", "s3-", "iam-"}},
	"k8s": {"Kubernetes and container security expert",
		"You are an expert in Kubernetes and container security for authorized testing. ",
		[]string{"kubernetes", "k8s", "kubelet", "container-escape", "container escape", "docker", "containerd"}},
	"linux": {"Linux privilege escalation expert",
		"You are an expert in Linux privilege escalation for authorized testing. ",
		[]string{"linux-privesc", "linux-hardening", "linux privilege", "escalating-linux", "suid", "sgid", "gtfobins", "capabilities", "pspy", "dirtypipe", "dirtycow", "pwnkit"}},
	"windows": {"Windows privilege escalation expert",
		"You are an expert in Windows privilege escalation for authorized testing. ",
		[]string{"windows-privesc", "windows-local-privilege", "windows privilege", "uac-bypass", "uac bypass", "potato", "juicypotato", "seimpersonate", "alwaysinstallelevated"}},
	"wireless": {"wireless and RF security expert",
		"You are an expert in wireless and RF security for authorized testing. ",
		[]string{"pentesting-wifi", "wifi", "wireless", "wpa2", "wpa3", "wpa-enterprise", "wps", "evil-twin", "deauth", "bluetooth", "zigbee", "sub-ghz", "lorawan", "z-wave", "krack"}},
	"binexp": {"binary exploitation expert",
		"You are an expert in binary exploitation and exploit development for authorized testing. ",
		[]string{"exploit-dev", "exploit development", "shellcode", "crash-analysis", "fuzzing", "buffer-overflow", "rop-", "mitigation", "heap-", "format-string"}},
	"network": {"network attack expert",
		"You are an expert in network-level attacks for authorized testing. ",
		[]string{"network-attacks", "pentesting-network", "mitm", "responder", "arp-spoof", "llmnr", "nbt-ns", "mitm6", "relay", "vlan", "dhcp"}},
	"mobile": {"mobile application security expert",
		"You are an expert in mobile application security for authorized testing. ",
		[]string{"mobile", "android", "ios-", "apk", "frida", "objection"}},
	"recon": {"reconnaissance and OSINT expert",
		"You are an expert in reconnaissance and OSINT for authorized testing. ",
		[]string{"osint", "recon", "information-gathering", "enumeration", "subdomain"}},
}

// domainOrder fixes iteration and tie-breaking (Go maps are unordered). The
// first domain to reach the top count wins, so more specific domains that share
// tokens with a broader one are listed before it (k8s before cloud).
var domainOrder = []string{"ad", "web", "k8s", "cloud", "linux", "windows", "wireless", "binexp", "network", "mobile", "recon"}

// domainFromResults tallies, per retrieved chunk, which domains its metadata
// matches (each chunk counts at most once per domain), and returns the domain
// with the most matching chunks. It returns "" (generic) when nothing matches.
func domainFromResults(results []retrieval.Result) string {
	counts := map[string]int{}
	for _, r := range results {
		hay := strings.ToLower(r.Payload.Source + " " + r.Payload.Path + " " + r.Payload.Section + " " + r.Payload.CWEClass)
		for _, dom := range domainOrder {
			for _, sig := range personas[dom].signals {
				if strings.Contains(hay, sig) {
					counts[dom]++
					break
				}
			}
		}
	}
	best, bestN := "", 0
	for _, dom := range domainOrder {
		if counts[dom] > bestN {
			best, bestN = dom, counts[dom]
		}
	}
	return best
}

// personaPrompt is the system prompt for a domain: the specialist preamble plus
// the shared constraints. An unknown/generic domain returns answerSystemPrompt.
func personaPrompt(domain string) string {
	p, ok := personas[domain]
	if !ok {
		return answerSystemPrompt
	}
	return p.preamble + answerConstraints
}

// personaLabel is the cue label for a domain, or "" for the generic fallback
// (no cue is shown).
func personaLabel(domain string) string {
	return personas[domain].label
}
