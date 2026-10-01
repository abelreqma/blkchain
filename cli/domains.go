package main

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"blkchain/cli/internal/engagement"
)

type domain struct {
	Name   string
	Prompt string
}

const executorPreamble = "You are a security-testing executor for authorized, single-user engagements, and you are EXECUTING the assigned task NOW, not planning it. Work only on this task. Act against the in-scope target with run_command; every call is bounded by scope and the security gate, so stay within scope and expect out-of-scope or dangerous commands to be denied. Record exact-quote evidence of real output with record_evidence. Use kb_search and kb_answer to ground your reasoning when it helps. plan_add is ONLY for a genuinely NEW task you discover from a finding, never the action you are performing now; do not re-plan the current task. "

var domains = map[string]domain{
	"generic":         {Name: "generic", Prompt: executorPreamble + "This is a general task with no specialized domain."},
	"recon":           {Name: "recon", Prompt: executorPreamble + "Domain: reconnaissance and enumeration. Focus on discovering hosts, services, and attack surface. Go non-intrusive and passive first, then move to targeted enumeration, always within scope. Use run_command for these tools and record exact-quote evidence for each finding: DNS (host, dig, nslookup, dnsrecon); SMB/NetBIOS (smbclient, rpcclient, nbtscan, showmount); LDAP (ldapsearch); SNMP (snmpwalk, onesixtyone); HTTP and directory discovery (gobuster, ffuf, nikto); TLS and service-version detection (nmap). Write scan output files to the working directory with relative paths, not absolute paths, and stage any wordlists into the working directory first; the gate denies absolute paths. When a finding implies more surface, propose a chained follow-on task with plan_add and set basis_ids to this task's id for provenance: an open service or port becomes a service-enum task of the matching kind (e.g. web, ad); a newly discovered host becomes a recon task; a found credential becomes a lateral or auth task. Stay non-intrusive first and in scope for every chained task."},
	"web":             {Name: "web", Prompt: executorPreamble + "Domain: web application security (OWASP WSTG). Focus on injection, auth, access control, and client-side issues."},
	"ad":              {Name: "ad", Prompt: executorPreamble + "Domain: Active Directory and identity. Focus on AD enumeration, credential and ACL abuse, delegation, and ADCS."},
	"cloud":           {Name: "cloud", Prompt: executorPreamble + "Domain: cloud security. Focus on IAM, metadata, storage, and misconfiguration across cloud providers."},
	"k8s":             {Name: "k8s", Prompt: executorPreamble + "Domain: Kubernetes and containers. Focus on RBAC, workload escape, and cluster misconfiguration."},
	"wifi":            {Name: "wifi", Prompt: executorPreamble + "Domain: wireless and RF. Focus on Wi-Fi and radio protocol assessment within scope."},
	"exploit-dev":     {Name: "exploit-dev", Prompt: executorPreamble + "Domain: exploit development. Focus on crash analysis, mitigations, and shellcode reasoning."},
	"target-analysis": {Name: "target-analysis", Prompt: executorPreamble + "Domain: target/binary analysis. You are given one executable path as the task target. Gather as much as possible about it NON-destructively with structured argv, recording exact-quote evidence: permissions, ownership, and SUID/SGID bits (ls -l, stat); file capabilities (getcap); type and format (file); linked libraries and RPATH or RUNPATH (ldd); readable strings (strings); symbols, sections, and exploit mitigations (nm, readelf, objdump); version and any config it reads. Then assess whether and how it is a privilege-escalation vector: route_skill with domain \"target-analysis\" or \"local\" for a GTFOBins-style playbook, and kb_search for known-CVE or abuse techniques for this binary and version. Never execute or modify the target binary; only inspect it. Report a clear verdict (is it a privesc vector, and the exact path to abuse) and, if exploitable, propose a chained escalation task with plan_add and basis_ids set to this task's id. Every command is human-confirmed."},
	"local":           {Name: "local", Prompt: executorPreamble + "Domain: local/post-access privilege escalation on a host you already have access to. Enumerate NON-destructively with structured argv and record exact-quote evidence for each finding: identity and groups (id, whoami); sudo rights (sudo -l); SUID/SGID binaries (find / -perm -4000 -type f and find / -perm -2000 -type f, with NO exec or delete predicate); file capabilities (getcap -r /); world-writable files and directories; cron jobs and writable cron paths; kernel and OS version (uname -a, and read /etc/os-release); running services and listening ports; and readable credential or config files. Never run a destructive action. When a finding is an escalation vector, propose a chained follow-on task with plan_add and set basis_ids to this task's id: an exploitable SUID/SGID or sudo entry or interesting binary becomes a target-analysis task (kind \"target-analysis\") naming that executable path; a discovered credential becomes an auth or lateral task; a newly discovered host or service becomes a recon task; a writable service or cron path becomes an escalation (target-analysis) task. Every command you run is subject to human confirmation; keep each one a single non-destructive enumeration step."},
}

// registerDomain registers a persona by name. It is the seam a new persona
// (e.g. container, ai-security) fills from its OWN file via init(), so a new
// domain can be added disjointly without editing this file. The fixed set above
// stays in-file, preserving today's personas.
func registerDomain(name string, d domain) {
	domains[name] = d
}

// domainFor maps a task kind to a domain, falling back to generic for an unknown
// kind. The lookup is case-insensitive.
func domainFor(kind string) domain {
	if d, ok := domains[strings.ToLower(strings.TrimSpace(kind))]; ok {
		return d
	}
	return domains["generic"]
}

// domainNames returns the registered domain names in sorted order.
func domainNames() []string {
	names := make([]string, 0, len(domains))
	for n := range domains {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// projectionMaxPerList caps each task list in the projection; coverage carries
// the full totals.
const projectionMaxPerList = 20

// projectionText builds a compact, bounded view of the engagement for an agent:
// a coverage line, the open tasks, and a duplicate-discovery guard listing what
// is already done. It is the same data for orchestrator and executors.
func projectionText(ctx context.Context, st *engagement.Store) (string, error) {
	cov, err := st.CoverageIndex()
	if err != nil {
		return "", err
	}
	open, err := st.OpenTasks()
	if err != nil {
		return "", err
	}
	snap, err := st.Snapshot(ctx)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Coverage: %d tasks, %d done, %d open. By kind:", cov.Total, cov.Done, cov.Open)
	kinds := make([]string, 0, len(cov.Kinds))
	for k := range cov.Kinds {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		fmt.Fprintf(&b, " %s=%d", k, cov.Kinds[k])
	}
	// Vantage-as-context: carry the current access-state into every executor's
	// projection so per-surface reasoning skews vantage-appropriate. Prints "" when unset.
	fmt.Fprintf(&b, "\nVantage: %s", snap.Vantage)
	b.WriteString("\n\nOpen tasks:")
	if len(open) == 0 {
		b.WriteString(" none")
	}
	for i, t := range open {
		if i == projectionMaxPerList {
			fmt.Fprintf(&b, "\n... (+%d more)", len(open)-projectionMaxPerList)
			break
		}
		fmt.Fprintf(&b, "\n- %s [%s] status=%s target=%s objective=%s", t.ID, t.Kind, t.Status, t.Target, t.Objective)
	}
	b.WriteString("\n\nAlready discovered (do not repeat):")
	discovered := 0
	for _, t := range snap.Tasks {
		if t.Status != engagement.StatusDone && t.Status != engagement.StatusNA {
			continue
		}
		discovered++
		if discovered <= projectionMaxPerList {
			fmt.Fprintf(&b, "\n- %s [%s] target=%s objective=%s", t.ID, t.Kind, t.Target, t.Objective)
		}
	}
	if discovered == 0 {
		b.WriteString(" none")
	} else if discovered > projectionMaxPerList {
		fmt.Fprintf(&b, "\n... (+%d more)", discovered-projectionMaxPerList)
	}
	return b.String(), nil
}
