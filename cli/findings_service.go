package main

import (
	"strconv"
	"strings"
)

// findings_service.go parses network services (port, transport, product,
// version) from nmap -sV output text.

// parseServices extracts the open services in nmap -sV output. Each Service's
// Host is filled from the most recent preceding "Nmap scan report for" line.
// Product and Version come from the service remainder (see splitProductVersion)
// and are empty when the output discloses none. Every Service carries prov. It
// returns nil when prov is invalid and never invents a product or version.
func parseServices(prov Provenance, quote string) []Service {
	if !prov.valid() {
		return nil
	}
	var out []Service
	host := ""
	for _, line := range strings.Split(quote, "\n") {
		l := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if m := reNmapReport.FindStringSubmatch(l); m != nil {
			host = hostFromReport(m[1])
			continue
		}
		m := reServiceLine.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		port, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		svc := Service{Host: host, Port: port, Transport: m[2], Prov: prov}
		if remainder := strings.TrimSpace(m[4]); remainder != "" {
			svc.Product, svc.Version = splitProductVersion(remainder)
		}
		out = append(out, svc)
	}
	return out
}
