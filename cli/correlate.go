package main

import (
	"strconv"
	"strings"

	"blkchain/cli/internal/engagement"
)

// correlate.go owns the deterministic graph edge from a discovered service to a
// candidate (unarmed) exploit task. The catalog is code-owned: the same
// service+version always yields the same candidate task. The corpus/LLM only
// advises the technique (correlate_selector.go), never whether a candidate
// exists - code owns the edge, and correlation fails closed to this catalog.

// exploitCatalog maps a normalized product name to a short technique label. A
// product not listed yields no candidate (correlateService returns false): the
// harness never invents an exploit path for an unknown service.
var exploitCatalog = map[string]string{
	"openssh":      "known-CVE exploitation of OpenSSH",
	"apache httpd": "known-CVE exploitation of Apache httpd",
	"nginx":        "known-CVE exploitation of nginx",
	"vsftpd":       "known-CVE / backdoor exploitation of vsftpd",
	"proftpd":      "known-CVE exploitation of ProFTPD",
	"samba":        "known-CVE exploitation of Samba",
	"smbd":         "known-CVE exploitation of Samba",
	// nmap -sV reports Samba as "Samba smbd 3.X - 4.X (workgroup: ...)", so
	// splitProductVersion yields the product "Samba smbd" (the first digit-leading
	// token "3.X" becomes the version). Key on that real banner form too.
	"samba smbd": "known-CVE exploitation of Samba",
	"mysql":      "known-CVE exploitation of MySQL",
	"isc bind":   "known-CVE exploitation of ISC BIND",
}

func correlateService(svc Service) (engagement.Task, bool) {
	if !svc.Prov.valid() {
		return engagement.Task{}, false
	}
	key := strings.ToLower(strings.TrimSpace(svc.Product))
	tech, ok := exploitCatalog[key]
	if !ok {
		return engagement.Task{}, false
	}
	target := svc.Host
	if svc.Port > 0 {
		if target != "" {
			target = target + ":" + strconv.Itoa(svc.Port)
		} else {
			target = strconv.Itoa(svc.Port)
		}
	}
	objective := tech
	if pv := strings.TrimSpace(svc.Product + " " + svc.Version); pv != "" {
		objective = tech + " against " + pv
	}
	id := "exploit-" + sanitizeSegment(svc.Host) + "-" + strconv.Itoa(svc.Port) + "-" + sanitizeSegment(key)
	return engagement.Task{
		ID:        id,
		Kind:      "exploit",
		Target:    target,
		Objective: objective,
		Status:    engagement.StatusTodo,
		Phase:     engagement.PhaseExploit,
		Surface:   engagement.SurfaceNetwork,
		Armed:     false,
		BasisIDs:  []string{svc.Prov.TaskID},
	}, true
}

// correlateFromEvidence reads a task's stored evidence rows, parses services
// from each quote (provenance = that task + the quote's row id), and returns the
// deduped set of candidate exploit tasks the catalog maps them to. It is
// deterministic and does not consult the corpus or the model.
func correlateFromEvidence(store *engagement.Store, taskID string) ([]engagement.Task, error) {
	rows, err := store.EvidenceRowsFor(taskID)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []engagement.Task
	for _, r := range rows {
		prov := Provenance{TaskID: taskID, EvidenceID: r.ID}
		for _, svc := range parseServices(prov, r.Quote) {
			cand, ok := correlateService(svc)
			if !ok || seen[cand.ID] {
				continue
			}
			seen[cand.ID] = true
			out = append(out, cand)
		}
	}
	return out, nil
}

// sanitizeSegment maps a string to a task-id-safe segment: characters outside
// [A-Za-z0-9._] become '-', so a host or product name is safe to key on.
func sanitizeSegment(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return b.String()
}
