package main

import (
	"errors"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"blkchain/cli/internal/secgate"
)

func endpoint(host, transport string, port int) (serviceEndpoint, error) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" || port < 1 || port > 65535 || transport != "tcp" && transport != "udp" {
		return serviceEndpoint{}, errors.New("target host, transport, or port cannot be verified")
	}
	return serviceEndpoint{host: host, transport: transport, port: port}, nil
}

func urlEndpoint(raw string) (serviceEndpoint, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return serviceEndpoint{}, errors.New("URL endpoint cannot be verified")
	}
	port := 0
	switch strings.ToLower(u.Scheme) {
	case "http":
		port = 80
	case "https":
		port = 443
	case "ldap":
		port = 389
	case "ldaps":
		port = 636
	default:
		return serviceEndpoint{}, errors.New("URL scheme has no audited port mapping")
	}
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil {
			return serviceEndpoint{}, errors.New("URL port cannot be verified")
		}
	}
	return endpoint(u.Hostname(), "tcp", port)
}

var serviceURL = regexp.MustCompile(`(?i)(?:https?|ldaps?)://[^\s'"<>]+`)

func commandURLs(c secgate.Command) ([]serviceEndpoint, error) {
	var out []serviceEndpoint
	for _, arg := range c.Args {
		for _, raw := range serviceURL.FindAllString(arg, -1) {
			ep, err := urlEndpoint(raw)
			if err != nil {
				return nil, err
			}
			out = append(out, ep)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("command has no verifiable service URL")
	}
	return out, nil
}

func singleTarget(c secgate.Command, transport string, defaultPort int) ([]serviceEndpoint, error) {
	hosts, nets, ok := secgate.ExtractTargetSet(c)
	if !ok || len(nets) != 0 || len(hosts) != 1 {
		return nil, errors.New("command requires one verifiable host")
	}
	port := defaultPort
	for i, arg := range c.Args {
		if arg == "-port" || arg == "--port" || arg == "-target-port" || arg == "--target-port" {
			if i+1 >= len(c.Args) {
				return nil, errors.New("command port cannot be verified")
			}
			port = mustPort(c.Args[i+1])
		}
		for _, flag := range []string{"-port=", "--port=", "-target-port=", "--target-port="} {
			if strings.HasPrefix(arg, flag) {
				port = mustPort(strings.TrimPrefix(arg, flag))
			}
		}
		if h, p, err := net.SplitHostPort(arg); err == nil && strings.EqualFold(h, hosts[0]) {
			port, err = strconv.Atoi(p)
			if err != nil {
				return nil, errors.New("command port cannot be verified")
			}
		}
		for _, prefix := range []string{"udp:", "tcp:"} {
			if strings.HasPrefix(strings.ToLower(arg), prefix) {
				host, value, ok := strings.Cut(strings.TrimPrefix(arg, prefix), ":")
				if !ok || !strings.EqualFold(host, hosts[0]) {
					return nil, errors.New("command port cannot be verified")
				}
				transport, port = strings.TrimSuffix(prefix, ":"), mustPort(value)
			}
		}
	}
	ep, err := endpoint(hosts[0], transport, port)
	if err != nil {
		return nil, err
	}
	return []serviceEndpoint{ep}, nil
}

func serviceRequirement(c secgate.Command) ([]serviceEndpoint, bool, error) {
	name := strings.ToLower(filepath.Base(c.Binary))
	if c.InternalProbe {
		return nil, true, nil
	}
	if reason := hiddenServiceRoute(name, c.Args); reason != "" {
		return nil, false, errors.New(reason)
	}
	if strings.HasPrefix(name, "web-api:") || strings.HasPrefix(name, "web-browser:") {
		if len(c.Args) != 1 {
			return nil, false, errors.New("web action requires one URL")
		}
		ep, err := urlEndpoint(c.Args[0])
		return []serviceEndpoint{ep}, false, err
	}
	if spec, ok := toolFor(c.Binary); ok && (spec.Reach == reachLocal || spec.Reach == reachScratch) {
		return nil, false, nil
	}
	switch name {
	case "nmap":
		if nmapServiceScan(c.Args) {
			return nmapRequiredEndpoints(c)
		}
		return nil, true, nil
	case "masscan", "traceroute", "tcpdump", "whois":
		return nil, true, nil
	case "dig", "host", "nslookup":
		return dnsRequirement(c)
	case "curl", "wget", "ffuf", "gobuster", "nikto":
		out, err := commandURLs(c)
		return out, false, err
	case "snmpwalk", "onesixtyone":
		out, err := singleTarget(c, "udp", 161)
		return out, false, err
	case "ldapsearch":
		out, err := commandURLs(c)
		return out, false, err
	case "smbclient", "rpcclient":
		out, err := singleTarget(c, "tcp", 445)
		return out, false, err
	case "nbtscan":
		out, err := singleTarget(c, "udp", 137)
		return out, false, err
	case "showmount":
		out, err := singleTarget(c, "tcp", 111)
		return out, false, err
	case "sslscan":
		out, err := singleTarget(c, "tcp", 443)
		return out, false, err
	case "nc", "ncat", "socat", "openssl", "kubectl":
		return commandExplicitEndpoint(c)
	case "aws", "gcloud", "ticketer.py":
		return nil, false, nil
	default:
		if port, ok := impacketDefaultPort(name); ok {
			out, err := singleTarget(c, "tcp", port)
			return out, false, err
		}
		return nil, false, errors.New("no audited service prerequisite for " + name)
	}
}

func hiddenServiceRoute(binary string, args []string) string {
	if binary == "wget" || binary == "nikto" {
		return "tool can follow an unverified connection route"
	}
	for _, arg := range args {
		flag, _, _ := strings.Cut(strings.ToLower(arg), "=")
		switch binary {
		case "curl":
			if flag == "-l" || flag == "--location" || flag == "--location-trusted" || flag == "--connect-to" || flag == "--resolve" || flag == "--alt-svc" || flag == "-x" || strings.HasPrefix(flag, "--proxy") || strings.HasPrefix(flag, "--preproxy") || strings.HasPrefix(flag, "--socks") {
				return "connection rewrite or redirect flag is not service-verifiable: " + flag
			}
			if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.ContainsAny(arg[1:], "Lx") {
				return "bundled redirect or proxy flag is not service-verifiable"
			}
		case "ffuf", "gobuster":
			if flag == "-r" || flag == "--follow-redirects" || flag == "-x" || flag == "--proxy" || flag == "-replay-proxy" {
				return "redirect or proxy flag is not service-verifiable: " + flag
			}
		case "nmap":
			if flag == "--proxies" {
				return "proxy target is not service-verifiable"
			}
		case "nc", "ncat":
			if flag == "-x" || flag == "--proxy" || flag == "--proxy-type" {
				return "proxy target is not service-verifiable"
			}
		case "openssl":
			if flag == "-proxy" {
				return "proxy target is not service-verifiable"
			}
		case "kubectl":
			if flag == "--proxy-url" {
				return "proxy target is not service-verifiable"
			}
		}
	}
	return ""
}
