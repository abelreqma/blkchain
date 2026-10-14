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
var nmapDoneLine = regexp.MustCompile(`^Nmap done: [1-9][0-9]* IP address(?:es)? \([1-9][0-9]* hosts? up\) scanned in .+ seconds$`)
var nmapFinishedLine = regexp.MustCompile(`^Nmap done: [1-9][0-9]* IP address(?:es)? \([0-9]+ hosts? up\) scanned in .+ seconds$`)
var ikeDoneLine = regexp.MustCompile(`^Ending ike-scan [0-9.]+: 1 hosts scanned in .+\.  ([0-9]+) returned handshake; ([0-9]+) returned notify$`)

func nmapFinished(output string) bool {
	trimmed := strings.TrimSpace(output)
	return nmapFinishedLine.MatchString(trimmed[strings.LastIndex(trimmed, "\n")+1:])
}

func nmapHostUp(output string) bool {
	trimmed := strings.TrimSpace(output)
	return nmapDoneLine.MatchString(trimmed[strings.LastIndex(trimmed, "\n")+1:])
}

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

func nmapFirewallDiagnostic(args []string) bool {
	for _, arg := range args {
		if arg == "-sY" || arg == "-sZ" || arg == "-sO" || arg == "-sn" {
			return false
		}
	}
	for _, arg := range args {
		if arg == "-sA" || arg == "-sF" || arg == "-sN" || arg == "-sX" || arg == "-sW" || arg == "-sM" || strings.HasPrefix(arg, "-f") && !strings.HasPrefix(arg, "--") {
			return true
		}
		for _, flag := range []string{"-g", "--source-port", "--mtu", "--scanflags", "--badsum", "--ip-options"} {
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
	if name != "nmap" {
		return nil
	}
	if nmapDiagnostic(c.Args) {
		return nil
	}
	if !nmapHostUp(output) {
		return nil
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
	defaultTransport := nmapDefaultTransport(c.Args)
	spec := rawPortSpec(c.Args)
	portAllowed := func(transport string, port int) bool {
		return scanPortContains(spec, defaultTransport, transport, port)
	}
	var out []serviceObservation
	host := ""
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
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
	}
	return out
}

func scanSourcePortCandidates(c secgate.Command, output string) []serviceObservation {
	if !strings.EqualFold(filepath.Base(c.Binary), "nmap") {
		return nil
	}
	port, stripped := nmapSourcePortArgs(c.Args)
	if port == 0 {
		return nil
	}
	seenSYN := false
	for _, arg := range stripped {
		if strings.HasPrefix(arg, "-s") {
			if arg != "-sS" || seenSYN {
				return nil
			}
			seenSYN = true
		}
	}
	if !seenSYN || nmapDiagnostic(stripped) {
		return nil
	}
	clean := c
	clean.Args = stripped
	var out []serviceObservation
	for _, observation := range scanServiceObservations(clean, output) {
		if observation.endpoint.transport != "tcp" {
			continue
		}
		if observation.state == "open" {
			observation.state = "candidate"
		}
		out = append(out, observation)
	}
	return out
}

func scanIKEObservations(c secgate.Command, output string) []serviceObservation {
	if !strings.EqualFold(filepath.Base(c.Binary), "ike-scan") {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) == 0 {
		return nil
	}
	done := ikeDoneLine.FindStringSubmatch(strings.TrimSpace(lines[len(lines)-1]))
	if done == nil || done[1] == "0" && done[2] == "0" {
		return nil
	}
	hosts, nets, ok := secgate.ExtractTargetSet(c)
	if !ok || len(nets) != 0 || len(hosts) != 1 {
		return nil
	}
	port := 500
	for _, arg := range c.Args {
		if arg == "--nat-t" {
			port = 4500
		}
	}
	prefix := hosts[0] + "\t"
	for _, line := range lines {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		message := strings.TrimSpace(strings.TrimPrefix(line, prefix))
		if strings.HasPrefix(message, "IKE Handshake returned") || strings.HasPrefix(message, "Notify message ") {
			return []serviceObservation{{endpoint: serviceEndpoint{host: hosts[0], transport: "udp", port: port}, state: "open"}}
		}
	}
	return nil
}
