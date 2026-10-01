package main

import (
	"regexp"
	"strings"
)

// findings_parse.go holds the shared, deterministic helpers the per-type
// evidence parsers use: the nmap "scan report for" host line, a parenthesized
// IPv4, an nmap -sV service line, and the product/version splitter. They parse
// text only; nothing here executes a command.

var (
	// reNmapReport matches an nmap "Nmap scan report for <rest>" line. <rest>
	// is a bare host/IP, or "name (ip)".
	reNmapReport = regexp.MustCompile(`^Nmap scan report for (.+)$`)
	// reParenIP matches a parenthesized IPv4, e.g. "(10.0.0.5)".
	reParenIP = regexp.MustCompile(`\(([0-9]{1,3}(?:\.[0-9]{1,3}){3})\)`)
	// reHostLine matches a "Host: <ipv4>" line.
	reHostLine = regexp.MustCompile(`^Host:\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})`)
	// reServiceLine matches an nmap -sV "open" service row: "<port>/<proto> open
	// <service> [product version...]".
	reServiceLine = regexp.MustCompile(`^(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$`)
)

// hostFromReport extracts the host from the text after "Nmap scan report for":
// the parenthesized IPv4 when present, else the first whitespace-delimited
// token. It returns "" when the text has no usable token.
func hostFromReport(rest string) string {
	rest = strings.TrimSpace(rest)
	if ip := reParenIP.FindStringSubmatch(rest); ip != nil {
		return ip[1]
	}
	if f := strings.Fields(rest); len(f) > 0 {
		return f[0]
	}
	return ""
}

// negationWords mark a line as reporting the ABSENCE of a condition, so a
// substring-matching issue detector must not fire on it (a summary line like
// "No deprecated protocols offered" or "Anonymous access: disabled" must not
// become a positive finding).
var negationWords = map[string]bool{
	"no": true, "not": true, "none": true, "without": true, "disabled": true,
}

// lineNegates reports whether line contains a standalone negation word, matched
// on token boundaries (after trimming surrounding punctuation) so "notable" does
// not count. It lets the TLS and finding parsers skip negated/summary lines.
func lineNegates(line string) bool {
	for _, w := range strings.Fields(strings.ToLower(line)) {
		w = strings.Trim(w, ".,:;()[]{}\"'")
		if negationWords[w] {
			return true
		}
	}
	return false
}

// splitProductVersion splits an nmap service remainder into a product and a
// version. The version is the first whitespace token whose first rune is a
// digit; the product is everything before it. When no token looks like a
// version, the whole remainder is the product and the version is empty. It
// never fabricates a version absent from the text.
func splitProductVersion(s string) (product, version string) {
	fields := strings.Fields(s)
	for i, f := range fields {
		if f != "" && f[0] >= '0' && f[0] <= '9' {
			return strings.Join(fields[:i], " "), f
		}
	}
	return strings.TrimSpace(s), ""
}
