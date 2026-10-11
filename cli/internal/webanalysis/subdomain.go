package webanalysis

import (
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// subdomain.go derives names under a root from captured material only: certificate names, response headers and served bodies, with no query sent.

// SubdomainSource is one piece of captured material a name can come from.
type SubdomainSource struct {
	// Kind is where the material came from: "certificate", "header", or "body".
	Kind string
	// Origin is the host the material was captured from.
	Origin string
	// Values are the strings to read: certificate names, header values, or a body.
	Values []string
	// EvidenceID is the exact quote row the material belongs to.
	EvidenceID int64
}

// SubdomainName is one name under the root and where it was disclosed.
type SubdomainName struct {
	Name       string `json:"name"`
	Source     string `json:"source"`
	Origin     string `json:"origin,omitempty"`
	Wildcard   bool   `json:"wildcard,omitempty"`
	EvidenceID int64  `json:"evidence_id,omitempty"`
}

// hostPattern matches a dotted DNS name of two or more labels with a letter-led final label.
var hostPattern = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]\b`)

// normalizeDNSName lowercases a name, strips a root dot and a wildcard label, and returns "" for an unusable one.
func normalizeDNSName(raw string) (name string, wildcard bool) {
	s := strings.TrimSpace(strings.ToLower(raw))
	s = strings.TrimSuffix(s, ".")
	if after, found := strings.CutPrefix(s, "*."); found {
		s, wildcard = after, true
	}
	if s == "" || len(s) > 253 {
		return "", false
	}
	// An address is not a subdomain; a single label is kept, because an internal root is often one.
	if net.ParseIP(s) != nil {
		return "", false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "", false
			}
		}
	}
	return s, wildcard
}

// UnderDomain reports whether name is root or beneath it, with the label separator as the boundary.
func UnderDomain(name, root string) bool {
	n, _ := normalizeDNSName(name)
	r, _ := normalizeDNSName(root)
	if n == "" || r == "" {
		return false
	}
	return n == r || strings.HasSuffix(n, "."+r)
}

// hostsInHeaderValue reads the hosts a header value names, splitting on the delimiters a URL, a source list and a JSON document use.
func hostsInHeaderValue(v string) []string {
	var out []string
	for _, field := range strings.FieldsFunc(v, func(r rune) bool {
		return strings.ContainsRune(" \t,;{}[]\"", r)
	}) {
		field = strings.TrimSuffix(strings.TrimPrefix(field, "'"), "'")
		if field == "" {
			continue
		}
		if strings.Contains(field, "://") {
			if u, err := url.Parse(field); err == nil && u.Hostname() != "" {
				out = append(out, u.Hostname())
				continue
			}
		}
		// A CSP source may be a bare host or a host with a port or path.
		field = strings.TrimPrefix(field, "//")
		if i := strings.IndexAny(field, "/:"); i > 0 {
			field = field[:i]
		}
		out = append(out, field)
	}
	return out
}

// PassiveSubdomains returns the distinct names under root the sources disclose, sorted, with a wildcard marked as one.
func PassiveSubdomains(root string, sources []SubdomainSource) []SubdomainName {
	r, _ := normalizeDNSName(root)
	type key struct {
		name     string
		source   string
		wildcard bool
	}
	seen := map[key]bool{}
	var out []SubdomainName
	for _, src := range sources {
		for _, value := range src.Values {
			for _, candidate := range candidatesFor(src.Kind, value) {
				name, wildcard := normalizeDNSName(candidate)
				if name == "" || !UnderDomain(name, r) {
					continue
				}
				k := key{name, src.Kind, wildcard}
				if seen[k] {
					continue
				}
				seen[k] = true
				out = append(out, SubdomainName{
					Name: name, Source: src.Kind, Origin: strings.ToLower(src.Origin),
					Wildcard: wildcard, EvidenceID: src.EvidenceID,
				})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		return !out[i].Wildcard && out[j].Wildcard
	})
	return out
}

// candidatesFor extracts the name candidates one value holds, by what kind of material it is.
func candidatesFor(kind, value string) []string {
	if len(value) > 1<<20 {
		value = value[:1<<20]
	}
	switch kind {
	case "certificate":
		return []string{value}
	case "header":
		return hostsInHeaderValue(value)
	}
	return hostPattern.FindAllString(value, 2000)
}

// SubdomainNames returns the distinct host names from a result set, excluding wildcards.
func SubdomainNames(in []SubdomainName) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s.Wildcard || seen[s.Name] {
			continue
		}
		seen[s.Name] = true
		out = append(out, s.Name)
	}
	sort.Strings(out)
	return out
}
