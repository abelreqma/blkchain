package main

import (
	"strconv"
	"strings"
)

// findings_finding.go parses general, severity-ranked findings from recon
// output. Severity comes from a fixed code mapping, never from the model.

// parseFindings extracts findings from recon output: an open port
// (SeverityInfo), a disclosed product+version banner (SeverityLow,
// "version-disclosure"), and an anonymous/auth-exposure marker (SeverityMedium,
// "anonymous-access"). Host is filled from the preceding "Nmap scan report for"
// line. Every Finding carries prov. It returns nil when prov is invalid and
// never invents a finding absent from the text.
func parseFindings(prov Provenance, quote string) []Finding {
	if !prov.valid() {
		return nil
	}
	var out []Finding
	host := ""
	for _, line := range strings.Split(quote, "\n") {
		l := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if m := reNmapReport.FindStringSubmatch(l); m != nil {
			host = hostFromReport(m[1])
			continue
		}
		if m := reServiceLine.FindStringSubmatch(l); m != nil {
			port, err := strconv.Atoi(m[1])
			if err != nil {
				continue
			}
			out = append(out, Finding{
				Title: "open-port", Severity: SeverityInfo,
				Host: host, Port: port, Detail: m[3], Prov: prov,
			})
			if remainder := strings.TrimSpace(m[4]); remainder != "" {
				if product, version := splitProductVersion(remainder); version != "" {
					out = append(out, Finding{
						Title: "version-disclosure", Severity: SeverityLow,
						Host: host, Port: port,
						Detail: strings.TrimSpace(product + " " + version), Prov: prov,
					})
				}
			}
			continue
		}
		// The anonymous/auth-exposure markers are substring matches, so a negated
		// summary line ("No anonymous access", "Anonymous access: disabled") must
		// not become a positive finding.
		if lineNegates(l) {
			continue
		}
		ll := strings.ToLower(l)
		if strings.Contains(ll, "anonymous ftp login allowed") ||
			strings.Contains(ll, "anonymous access") ||
			strings.Contains(ll, "null session") {
			out = append(out, Finding{
				Title: "anonymous-access", Severity: SeverityMedium,
				Host: host, Detail: l, Prov: prov,
			})
		}
	}
	return out
}
