package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/ragconfig"
)

func finalizeCandidate(base engagement.Task, cit engagement.Citation, audit func(action, detail string), gapDetail string) engagement.Task {
	base.CodeCandidate = true
	if cit.Source != "" {
		base.Citation = cit
		if base.Status == "" {
			base.Status = engagement.StatusTodo
		}
		return base
	}
	markCoverageGap(&base)
	if audit != nil {
		audit("corpus-coverage-gap", gapDetail)
	}
	return base
}

// groundCandidate grounds a code-derived base candidate that has NO model label
// (the deterministic logic-gap path): it runs the shared corpus grounding
// (groundCitation over query+term) and finalizes via finalizeCandidate. The
// bizlogic detector calls this per matched rule, handing a code-owned base
// candidate plus a context-bearing query - detection stays code-owned in
// bizlogic, while the citation bar + emission + audit stay here, shared with the
// service path.
func groundCandidate(ctx context.Context, rc searcher, cfg ragconfig.Config, audit func(action, detail string), base engagement.Task, query, term string) engagement.Task {
	cit, _ := groundCitation(ctx, rc, cfg, query, term)
	return finalizeCandidate(base, cit, audit, fmt.Sprintf("%s query=%q reason=no-accepted-citation", base.ID, query))
}

// correlate.go owns the code-derived FIELDS of a candidate (unarmed) exploit task
// from a discovered service (candidateTask): id and target from host:port, Kind
// exploit, UNARMED, phase exploit, basis from provenance. The DETECTION decision
// (does a candidate exist?) has two paths, both ending in candidateTask: the
// code-owned exploitCatalog fast-path here, and the corpus-grounded path in
// correlateNewEvidence, which creates a candidate only when the selector returns a
// technique backed by a corpus CITATION (fail closed: no citation -> no candidate).
// The corpus/LLM supplies only the advisory technique label and the citation -
// never the target, the arm state, or any gate/scope/tier verdict - so untrusted
// corpus text cannot steer what is targeted or whether it runs. Candidates are
// always unarmed and gated behind per-action HITL confirm at execution.

// exploitCatalog maps a normalized product name to a short technique label. It is
// the high-confidence FAST PATH (always a candidate for a listed product); a
// product NOT listed is no longer dropped - correlateNewEvidence falls back to
// cited-grounding detection, so coverage is not capped by this hand-maintained
// list.
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
	return candidateTask(svc, tech), true
}

// candidateTask builds the deterministic, code-owned candidate exploit task for a
// service, with `technique` as its objective label. EVERY field is derived from
// the parsed service: id and target from host:port, Kind exploit, UNARMED, phase
// exploit, basis from provenance. `technique` is advisory label text only; it
// never controls the target or the arm state, so untrusted corpus text that
// reaches the technique cannot steer what is targeted or whether it runs. Shared
// by the catalog edge (correlateService) and the grounded edge
// (correlateNewEvidence): both produce identical, code-owned candidates - only the
// detection DECISION (catalog membership vs cited grounding) differs.
func candidateTask(svc Service, technique string) engagement.Task {
	key := strings.ToLower(strings.TrimSpace(svc.Product))
	target := svc.Host
	if svc.Port > 0 {
		if target != "" {
			target = target + ":" + strconv.Itoa(svc.Port)
		} else {
			target = strconv.Itoa(svc.Port)
		}
	}
	objective := technique
	if pv := strings.TrimSpace(svc.Product + " " + svc.Version); pv != "" {
		objective = technique + " against " + pv
	}
	id := "exploit-" + sanitizeSegment(svc.Host) + "-" + strconv.Itoa(svc.Port) + "-" + sanitizeSegment(key)
	return engagement.Task{
		ID:            id,
		Kind:          "exploit",
		Target:        target,
		Objective:     objective,
		Status:        engagement.StatusTodo,
		Phase:         engagement.PhaseExploit,
		Surface:       engagement.SurfaceNetwork,
		Armed:         false,
		CodeCandidate: true,
		BasisIDs:      []string{svc.Prov.TaskID},
	}
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
