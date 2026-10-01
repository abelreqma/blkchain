package main

import "strings"

// findings_asset.go parses discovered hosts from reconnaissance output text.

// parseAssets extracts the hosts named in recon output: nmap "Nmap scan report
// for <name> (<ip>)" and "... for <ip>" lines (the parenthesized IP is
// preferred), and "Host: <ip>" lines. Every Asset carries prov. It returns nil
// when prov is invalid, dedups by host in first-seen order, and never invents a
// host absent from the text.
func parseAssets(prov Provenance, quote string) []Asset {
	if !prov.valid() {
		return nil
	}
	seen := map[string]bool{}
	var out []Asset
	add := func(h string) {
		h = strings.TrimSpace(h)
		if h == "" || seen[h] {
			return
		}
		seen[h] = true
		out = append(out, Asset{Host: h, Prov: prov})
	}
	for _, line := range strings.Split(quote, "\n") {
		l := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if m := reNmapReport.FindStringSubmatch(l); m != nil {
			add(hostFromReport(m[1]))
			continue
		}
		if m := reHostLine.FindStringSubmatch(l); m != nil {
			add(m[1])
		}
	}
	return out
}
