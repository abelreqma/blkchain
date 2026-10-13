package secgate

import (
	"errors"
	"net"
	"strconv"
	"strings"
)

type CurlResolve struct {
	Host    string
	Port    int
	Address string
}

func CurlResolveArgs(args []string) ([]CurlResolve, error) {
	var out []CurlResolve
	for i, arg := range args {
		value := ""
		switch {
		case arg == "--resolve":
			if i+1 >= len(args) {
				return nil, errors.New("curl --resolve needs a host, port, and IP")
			}
			i++
			value = args[i]
		case strings.HasPrefix(arg, "--resolve="):
			value = strings.TrimPrefix(arg, "--resolve=")
		default:
			continue
		}
		if strings.HasPrefix(value, "+") || strings.Contains(value, ",") {
			return nil, errors.New("curl --resolve must name one stable address")
		}
		host, rest, ok := strings.Cut(value, ":")
		if !ok || host == "*" || !validHost(host) {
			return nil, errors.New("curl --resolve host cannot be verified")
		}
		portText, address, ok := strings.Cut(rest, ":")
		port, err := strconv.Atoi(portText)
		if !ok || err != nil || port < 1 || port > 65535 {
			return nil, errors.New("curl --resolve port cannot be verified")
		}
		if strings.HasPrefix(address, "[") != strings.HasSuffix(address, "]") {
			return nil, errors.New("curl --resolve address brackets are malformed")
		}
		address = strings.TrimPrefix(strings.TrimSuffix(address, "]"), "[")
		ip := net.ParseIP(address)
		if ip == nil {
			return nil, errors.New("curl --resolve address must be a literal IP")
		}
		out = append(out, CurlResolve{Host: strings.TrimSuffix(strings.ToLower(host), "."), Port: port, Address: ip.String()})
	}
	return out, nil
}
