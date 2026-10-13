package main

import (
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"blkchain/cli/internal/secgate"
)

var scanPortLine = regexp.MustCompile(`^([0-9]{1,5})/(tcp|udp)\s+(open\|filtered|open|closed|filtered)\s+`)
var masscanPortLine = regexp.MustCompile(`^Discovered open port ([0-9]{1,5})/(tcp|udp) on (\S+)$`)
var nmapDoneLine = regexp.MustCompile(`^Nmap done: [1-9][0-9]* IP address(?:es)? \([1-9][0-9]* hosts? up\) scanned in .+ seconds$`)

func nmapDiagnostic(args []string) bool {
	for _, arg := range args {
		if strings.HasPrefix(arg, "-s") && strings.ContainsAny(arg[2:], "AFNIXWMOYZ") {
			return true
		}
		for _, flag := range []string{"-f", "-D", "-S", "-g", "-e", "--source-port", "--mtu", "--scanflags", "--spoof-mac", "--badsum", "--ip-options"} {
			if arg == flag || strings.HasPrefix(arg, flag+"=") || len(flag) == 2 && strings.HasPrefix(arg, flag) {
				return true
			}
		}
	}
	return false
}

func scanPortContains(spec, defaultTransport, transport string, port int) bool {
	if spec == "" {
		return true
	}
	matched := false
	for _, part := range strings.Split(spec, ",") {
		if strings.HasPrefix(part, "T:") {
			defaultTransport, part = "tcp", strings.TrimPrefix(part, "T:")
		} else if strings.HasPrefix(part, "U:") {
			defaultTransport, part = "udp", strings.TrimPrefix(part, "U:")
		}
		lo, hi := 0, 0
		if part == "-" {
			lo, hi = 1, 65535
		} else if strings.Count(part, "-") == 1 {
			left, right, _ := strings.Cut(part, "-")
			var err error
			lo, err = strconv.Atoi(left)
			if err != nil {
				return false
			}
			hi, err = strconv.Atoi(right)
			if err != nil {
				return false
			}
		} else {
			var err error
			lo, err = strconv.Atoi(part)
			if err != nil {
				return false
			}
			hi = lo
		}
		if lo < 1 || hi > 65535 || hi < lo {
			return false
		}
		matched = matched || defaultTransport == transport && lo <= port && port <= hi
	}
	return matched
}

func scanServiceObservations(c secgate.Command, output string) []serviceObservation {
	name := strings.ToLower(filepath.Base(c.Binary))
	if name != "nmap" && name != "masscan" {
		return nil
	}
	if name == "nmap" {
		if nmapDiagnostic(c.Args) {
			return nil
		}
		trimmed := strings.TrimSpace(output)
		last := trimmed[strings.LastIndex(trimmed, "\n")+1:]
		if !nmapDoneLine.MatchString(last) {
			return nil
		}
	}
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
	spec := rawPortSpec(c.Args)
	portAllowed := func(transport string, port int) bool {
		return scanPortContains(spec, defaultTransport, transport, port)
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
					out = append(out, serviceObservation{endpoint: ep, state: "candidate"})
				}
			}
		}
	}
	return out
}
