package secgate

import "strings"

func nmapEgressViolation(c Command) (Decision, bool) {
	if !strings.EqualFold(baseName(c.Binary), "nmap") {
		return Decision{}, false
	}
	for _, arg := range c.Args {
		if strings.HasPrefix(arg, "-D") || strings.HasPrefix(arg, "-S") {
			return Decision{Reason: "nmap " + arg + " sends spoofed-source packets outside the worker's source control"}, true
		}
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		flag, _, _ := strings.Cut(strings.TrimLeft(strings.ToLower(arg), "-"), "=")
		if len(flag) >= 4 && (strings.HasPrefix("send-eth", flag) || strings.HasPrefix("spoof-mac", flag)) {
			return Decision{Reason: "nmap " + arg + " can bypass the worker IP address guard"}, true
		}
	}
	return Decision{}, false
}
