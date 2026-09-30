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

const executorPreamble = "You are a security-testing executor for authorized, single-user engagements. Work only on the assigned task. Use kb_search and kb_answer to ground your reasoning when it helps. Record exact-quote evidence for what you find with record_evidence, and propose plan updates for new tasks you discover. You cannot run commands against targets in this phase. "

var domains = map[string]domain{
	"generic":     {Name: "generic", Prompt: executorPreamble + "This is a general task with no specialized domain."},
	"recon":       {Name: "recon", Prompt: executorPreamble + "Domain: reconnaissance and enumeration. Focus on discovering hosts, services, and attack surface without intrusive actions."},
	"web":         {Name: "web", Prompt: executorPreamble + "Domain: web application security (OWASP WSTG). Focus on injection, auth, access control, and client-side issues."},
	"ad":          {Name: "ad", Prompt: executorPreamble + "Domain: Active Directory and identity. Focus on AD enumeration, credential and ACL abuse, delegation, and ADCS."},
	"cloud":       {Name: "cloud", Prompt: executorPreamble + "Domain: cloud security. Focus on IAM, metadata, storage, and misconfiguration across cloud providers."},
	"k8s":         {Name: "k8s", Prompt: executorPreamble + "Domain: Kubernetes and containers. Focus on RBAC, workload escape, and cluster misconfiguration."},
	"wifi":        {Name: "wifi", Prompt: executorPreamble + "Domain: wireless and RF. Focus on Wi-Fi and radio protocol assessment within scope."},
	"exploit-dev": {Name: "exploit-dev", Prompt: executorPreamble + "Domain: exploit development. Focus on crash analysis, mitigations, and shellcode reasoning."},
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
