package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/webanalysis"
)

// vulningest.go turns a scanner report captured as evidence into vuln_record rows, identified and filled from the report itself and bound to the row it came from.

// scannerKeys maps a scanner to the raw top-level keys its report must carry, which a case-insensitive trial decode could not tell apart.
var scannerKeys = []struct {
	scanner  string
	required []string
}{
	{"grype", []string{"matches", "descriptor"}},
	{"trivy", []string{"Results", "SchemaVersion"}},
	{"osv-scanner", []string{"results"}},
}

// reportObject returns the first complete JSON object in s, which a decoder bounds exactly despite the progress lines that follow.
func reportObject(s string) (json.RawMessage, bool) {
	start := strings.IndexByte(s, '{')
	if start < 0 || len(s)-start > maxScanBytes {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(s[start:])))
	var raw json.RawMessage
	if dec.Decode(&raw) != nil {
		return nil, false
	}
	return raw, true
}

// scannerFromReport names the scanner that produced raw, or false for anything that is not a report.
func scannerFromReport(raw json.RawMessage) (string, bool) {
	var top map[string]json.RawMessage
	if json.Unmarshal(raw, &top) != nil {
		return "", false
	}
	for _, c := range scannerKeys {
		ok := true
		for _, k := range c.required {
			if _, present := top[k]; !present {
				ok = false
				break
			}
		}
		if ok {
			return c.scanner, true
		}
	}
	return "", false
}

// ingestVulnReports persists each report's advisories against the row it was read from, auditing what the store rejects.
func ingestVulnReports(ctx context.Context, store *engagement.Store, taskID, asset string, surface engagement.Surface, rows []engagement.EvidenceRow) (int, error) {
	stored := 0
	for _, r := range rows {
		raw, ok := reportObject(r.Quote)
		if !ok {
			continue
		}
		scanner, ok := scannerFromReport(raw)
		if !ok {
			continue
		}
		parsed, err := parseVulnScan(scanner, raw, asset, "")
		if err != nil {
			if err := store.Audit("vulnscan", "parse-failed",
				fmt.Sprintf("%s evidence=%d scanner=%s: %s", taskID, r.ID, scanner, err)); err != nil {
				return stored, err
			}
			continue
		}
		reportHash := sha256.Sum256(raw)
		for _, v := range parsed {
			quote := fmt.Sprintf("scanner=%s source_evidence=%d report_sha256=%x\nadvisory=%s package=%s version=%s asset=%s ecosystem=%s",
				scanner, r.ID, reportHash, v.Advisory, v.Package, v.PackageVersion, v.Asset, v.Ecosystem)
			id, err := store.RecordEvidence(taskID, quote)
			if err != nil {
				return stored, err
			}
			v.TaskID, v.Surface, v.EvidenceID = taskID, surface, id
			v.ID = "cve:" + webanalysis.ID(taskID, v.ID)[:40]
			if _, err := store.SaveVuln(ctx, v); err != nil {
				if err := store.Audit("vulnscan", "record-rejected",
					fmt.Sprintf("%s evidence=%d advisory=%s: %s", taskID, r.ID, v.Advisory, err)); err != nil {
					return stored, err
				}
				continue
			}
			stored++
		}
		if err := store.Audit("vulnscan", "ingested",
			fmt.Sprintf("%s evidence=%d scanner=%s advisories=%d", taskID, r.ID, scanner, len(parsed))); err != nil {
			return stored, err
		}
	}
	return stored, nil
}
