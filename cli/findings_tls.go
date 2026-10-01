package main

import "strings"

// findings_tls.go parses TLS details and issues from TLS-scanner output text
// (sslscan "enabled" rows and nmap ssl-enum section headers).

// deprecatedTLSProtos are the protocol versions whose presence is itself an
// issue.
var deprecatedTLSProtos = []string{"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}

// parseTLSInfo extracts TLS problems the output actually shows: an enabled
// deprecated protocol (Issue "deprecated-protocol", Protocol set), a self-signed
// cert (Issue "self-signed"), or an expired cert (Issue "expired"). A clean,
// modern block yields no records. Every record carries prov. It returns nil when
// prov is invalid and never invents an issue.
func parseTLSInfo(prov Provenance, quote string) []TLSInfo {
	if !prov.valid() {
		return nil
	}
	var out []TLSInfo
	for _, line := range strings.Split(quote, "\n") {
		l := strings.TrimSpace(strings.TrimRight(line, "\r"))
		// A summary line reporting the ABSENCE of a problem ("No deprecated
		// protocols (SSLv2, SSLv3, ...) offered", "not self-signed") must not
		// become a positive finding.
		if lineNegates(l) {
			continue
		}
		ll := strings.ToLower(l)
		for _, p := range deprecatedTLSProtos {
			if !strings.Contains(l, p) {
				continue
			}
			// sslscan prints "<proto>   enabled"; nmap ssl-enum prints the
			// protocol as a section header "<proto>:". Either means the
			// deprecated protocol is offered.
			enabled := strings.Contains(ll, "enabled") ||
				strings.Contains(ll, "accepted") ||
				strings.Contains(ll, "offered") ||
				strings.Contains(l, p+":")
			if enabled {
				out = append(out, TLSInfo{Protocol: p, Issue: "deprecated-protocol", Prov: prov})
			}
		}
		if strings.Contains(ll, "self-signed") || strings.Contains(ll, "self signed") {
			out = append(out, TLSInfo{Issue: "self-signed", Prov: prov})
		}
		if strings.Contains(ll, "expired") {
			out = append(out, TLSInfo{Issue: "expired", Prov: prov})
		}
	}
	return out
}
