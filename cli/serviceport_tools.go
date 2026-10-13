package main

import (
	"errors"
	"net"
	"path/filepath"
	"strconv"
	"strings"

	"blkchain/cli/internal/secgate"
)

func impacketDefaultPort(name string) (int, bool) {
	switch name {
	case "getuserspns.py":
		return 389, true
	case "getnpusers.py", "gettgt.py":
		return 88, true
	case "rpcdump.py", "wmiexec.py":
		return 135, true
	case "mssqlclient.py":
		return 1433, true
	case "secretsdump.py", "lookupsid.py", "samrdump.py", "psexec.py", "smbexec.py", "ntlmrelayx.py":
		return 445, true
	}
	return 0, false
}

func commandExplicitEndpoint(c secgate.Command) ([]serviceEndpoint, bool, error) {
	name := strings.ToLower(filepath.Base(c.Binary))
	if name == "kubectl" {
		out, err := commandURLs(c)
		return out, false, err
	}
	if name == "openssl" {
		for i, arg := range c.Args {
			if arg == "-connect" && i+1 < len(c.Args) {
				ep, err := hostPortEndpoint(c.Args[i+1], "tcp")
				return []serviceEndpoint{ep}, false, err
			}
		}
		return nil, false, errors.New("openssl connection port cannot be verified")
	}
	if name == "socat" {
		var out []serviceEndpoint
		for _, arg := range c.Args {
			parts := strings.SplitN(arg, ":", 3)
			if len(parts) == 3 && strings.Contains(strings.ToUpper(parts[0]), "TCP") || len(parts) == 3 && strings.Contains(strings.ToUpper(parts[0]), "UDP") {
				transport := "tcp"
				if strings.Contains(strings.ToUpper(parts[0]), "UDP") {
					transport = "udp"
				}
				ep, err := endpoint(parts[1], transport, mustPort(parts[2]))
				if err != nil {
					return nil, false, err
				}
				out = append(out, ep)
			}
		}
		if len(out) == 0 {
			return nil, false, errors.New("socat connection port cannot be verified")
		}
		return out, false, nil
	}
	if len(c.Args) < 2 {
		return nil, false, errors.New("connection host and port are required")
	}
	transport := "tcp"
	for _, arg := range c.Args {
		if arg == "-u" || arg == "--udp" {
			transport = "udp"
		}
	}
	ep, err := endpoint(c.Args[len(c.Args)-2], transport, mustPort(c.Args[len(c.Args)-1]))
	return []serviceEndpoint{ep}, false, err
}

func dnsRequirement(c secgate.Command) ([]serviceEndpoint, bool, error) {
	name := strings.ToLower(filepath.Base(c.Binary))
	server := ""
	port := 53
	explicitPort := false
	mode := "udp"
	ignoreFallback := false
	for i, arg := range c.Args {
		if name == "dig" && strings.HasPrefix(arg, "@") {
			server = strings.TrimPrefix(arg, "@")
		}
		if arg == "-p" && i+1 < len(c.Args) {
			port = mustPort(c.Args[i+1])
			explicitPort = true
		}
		if strings.HasPrefix(arg, "-p") && len(arg) > 2 && !strings.HasPrefix(arg, "--") {
			port = mustPort(arg[2:])
			explicitPort = true
		}
		if name == "nslookup" && strings.HasPrefix(arg, "-port=") {
			port = mustPort(strings.TrimPrefix(arg, "-port="))
			explicitPort = true
		}
		if arg == "+trace" || strings.HasPrefix(arg, "+nohttps") || strings.HasPrefix(arg, "+notls") || strings.HasPrefix(arg, "+nohttp-plain") || arg == "+notcp" || arg == "+novc" {
			return nil, false, errors.New("DNS option changes the destination after it was classified")
		}
		if arg == "+ignore" {
			ignoreFallback = true
		}
		if arg == "+noignore" {
			ignoreFallback = false
		}
		next := ""
		switch {
		case arg == "+tcp" || arg == "+vc" || name == "host" && arg == "-T" || name == "nslookup" && arg == "-vc":
			next = "tcp"
		case arg == "+tls":
			next = "tls"
		case strings.HasPrefix(arg, "+https"):
			next = "https"
		case strings.HasPrefix(arg, "+http-plain"):
			next = "http"
		case strings.EqualFold(arg, "AXFR") || strings.EqualFold(arg, "ANY") || strings.HasPrefix(strings.ToUpper(arg), "IXFR="):
			next = "tcp"
		}
		if next != "" {
			if mode != "udp" && mode != next {
				return nil, false, errors.New("DNS transport options conflict")
			}
			mode = next
		}
	}
	if name != "dig" && len(c.Args) >= 2 {
		server = c.Args[len(c.Args)-1]
	}
	if server == "" {
		return nil, true, nil
	}
	transport := "udp"
	if mode != "udp" {
		transport = "tcp"
	}
	if !explicitPort {
		switch mode {
		case "tls":
			port = 853
		case "https":
			port = 443
		case "http":
			port = 80
		}
	}
	ep, err := endpoint(server, transport, port)
	if err != nil {
		return nil, false, err
	}
	if mode == "udp" && !ignoreFallback {
		tcp := ep
		tcp.transport = "tcp"
		return []serviceEndpoint{ep, tcp}, false, nil
	}
	return []serviceEndpoint{ep}, false, nil
}

func hostPortEndpoint(raw, transport string) (serviceEndpoint, error) {
	host, portText, err := net.SplitHostPort(raw)
	if err != nil {
		return serviceEndpoint{}, err
	}
	return endpoint(host, transport, mustPort(portText))
}

func mustPort(text string) int {
	port, _ := strconv.Atoi(text)
	return port
}

func nmapServiceScan(args []string) bool {
	for _, arg := range args {
		if arg == "-sV" || arg == "-sC" || arg == "-A" || arg == "-O" || strings.HasPrefix(arg, "--script") || strings.HasPrefix(arg, "--version-") {
			return true
		}
		if strings.HasPrefix(arg, "-s") && (strings.ContainsAny(arg[2:], "VC")) {
			return true
		}
	}
	return false
}

func nmapDefaultTransport(args []string) string {
	for _, arg := range args {
		if strings.HasPrefix(arg, "-s") && strings.Contains(arg[2:], "U") {
			return "udp"
		}
	}
	return "tcp"
}

func nmapRequiredEndpoints(c secgate.Command) ([]serviceEndpoint, bool, error) {
	hosts, nets, ok := secgate.ExtractTargetSet(c)
	if !ok || len(nets) != 0 || len(hosts) != 1 {
		return nil, false, errors.New("service scan requires one identified host")
	}
	udp, tcp := false, false
	for _, arg := range c.Args {
		if strings.HasPrefix(arg, "-s") {
			udp = udp || strings.Contains(arg[2:], "U")
			tcp = tcp || strings.ContainsAny(arg[2:], "STA")
		}
	}
	if udp && tcp {
		spec := rawPortSpec(c.Args)
		if !strings.Contains(spec, "T:") || !strings.Contains(spec, "U:") {
			return nil, false, errors.New("mixed TCP/UDP service scan requires transport-qualified ports")
		}
	}
	ports := scanPortSpec(c.Args, nmapDefaultTransport(c.Args))
	if len(ports) == 0 {
		return nil, false, errors.New("service scan requires explicit identified ports")
	}
	return portsForHost(hosts[0], ports), false, nil
}

func portsForHost(host string, ports []serviceEndpoint) []serviceEndpoint {
	out := make([]serviceEndpoint, len(ports))
	for i, p := range ports {
		out[i] = p
		out[i].host = strings.ToLower(host)
	}
	return out
}

func scanPortSpec(args []string, defaultTransport string) []serviceEndpoint {
	return parsePortSpec(rawPortSpec(args), defaultTransport)
}

func rawPortSpec(args []string) string {
	for i, arg := range args {
		if arg == "-p" && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(arg, "-p") && len(arg) > 2 {
			return arg[2:]
		}
	}
	return ""
}

func parsePortSpec(spec, transport string) []serviceEndpoint {
	if spec == "" {
		return nil
	}
	var out []serviceEndpoint
	for _, part := range strings.Split(spec, ",") {
		if strings.HasPrefix(part, "T:") {
			transport, part = "tcp", strings.TrimPrefix(part, "T:")
		}
		if strings.HasPrefix(part, "U:") {
			transport, part = "udp", strings.TrimPrefix(part, "U:")
		}
		lo, hi := mustPort(part), mustPort(part)
		if strings.Contains(part, "-") {
			bounds := strings.Split(part, "-")
			if len(bounds) != 2 {
				return nil
			}
			lo, hi = mustPort(bounds[0]), mustPort(bounds[1])
		}
		if lo < 1 || hi > 65535 || hi < lo || hi-lo+len(out) >= 1024 {
			return nil
		}
		for port := lo; port <= hi; port++ {
			out = append(out, serviceEndpoint{host: "placeholder", transport: transport, port: port})
		}
	}
	return out
}
