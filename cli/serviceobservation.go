package main

import (
	"net"
	"path/filepath"
	"regexp"
	"strings"

	"blkchain/cli/internal/secgate"
)

var scanPortLine = regexp.MustCompile(`^([0-9]{1,5})/(tcp|udp)\s+(open\|filtered|open|closed|filtered)\s+`)
var masscanPortLine = regexp.MustCompile(`^Discovered open port ([0-9]{1,5})/(tcp|udp) on (\S+)$`)

func scanServiceObservations(c secgate.Command, output string) []serviceObservation {
	name := strings.ToLower(filepath.Base(c.Binary))
	if name != "nmap" && name != "masscan" {
		return nil
	}
	negativeOnly := name == "nmap" && nmapServiceScan(c.Args)
	hosts, nets, ok := secgate.ExtractTargetSet(c)
	if !ok {
		return nil
	}
	allowedHost := func(host string) bool {
		for _, h := range hosts {
			if strings.EqualFold(h, host) {
				return true
			}
		}
		ip := net.ParseIP(host)
		for _, network := range nets {
			if ip != nil && network.Contains(ip) {
				return true
			}
		}
		return false
	}
	defaultTransport := "tcp"
	if name == "nmap" {
		defaultTransport = nmapDefaultTransport(c.Args)
	}
	requested := scanPortSpec(c.Args, defaultTransport)
	portAllowed := func(transport string, port int) bool {
		if len(requested) == 0 {
			return true
		}
		for _, r := range requested {
			if r.port == port && r.transport == transport {
				return true
			}
		}
		return false
	}
	var out []serviceObservation
	host := ""
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if name == "nmap" {
			if m := reNmapReport.FindStringSubmatch(line); m != nil {
				host = hostFromReport(m[1])
				if !allowedHost(host) {
					host = ""
					if fields := strings.Fields(m[1]); len(fields) > 0 && allowedHost(fields[0]) {
						host = fields[0]
					}
				}
				continue
			}
			if host == "" {
				continue
			}
			if m := scanPortLine.FindStringSubmatch(line); m != nil {
				if negativeOnly && m[3] != "closed" && m[3] != "filtered" {
					continue
				}
				port := mustPort(m[1])
				if !portAllowed(m[2], port) {
					continue
				}
				ep, err := endpoint(host, m[2], port)
				if err == nil {
					out = append(out, serviceObservation{endpoint: ep, state: m[3]})
				}
			}
			continue
		}
		if m := masscanPortLine.FindStringSubmatch(line); m != nil && allowedHost(m[3]) {
			port := mustPort(m[1])
			if portAllowed(m[2], port) {
				ep, err := endpoint(m[3], m[2], port)
				if err == nil {
					out = append(out, serviceObservation{endpoint: ep, state: "open"})
				}
			}
		}
	}
	return out
}
