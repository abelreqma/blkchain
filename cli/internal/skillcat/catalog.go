package skillcat

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Catalog is the loaded, validated set of skills, indexed by name and domain.
type Catalog struct {
	byName   map[string]Skill
	byDomain map[string][]string
	errs     []error
}

// Load reads <dir>/<name>/SKILL.md for each immediate subdirectory. An empty
// or missing dir yields an empty catalog and no error. A skill that fails
// ParseSkill, or a duplicate name, is excluded and its error collected (fail
// closed). Load returns an error only when the dir exists but cannot be read.
func Load(dir string) (*Catalog, error) {
	c := &Catalog{byName: map[string]Skill{}, byDomain: map[string][]string{}}
	if strings.TrimSpace(dir) == "" {
		return c, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return nil, fmt.Errorf("skillcat: read %s: %w", dir, err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name(), "SKILL.md")
		raw, err := os.ReadFile(path)
		if err != nil {
			if !os.IsNotExist(err) {
				c.errs = append(c.errs, fmt.Errorf("skillcat: %s: %w", path, err))
			}
			continue // a subdir without a SKILL.md is simply not a skill
		}
		s, err := ParseSkill(path, raw)
		if err != nil {
			c.errs = append(c.errs, err)
			continue
		}
		if _, dup := c.byName[s.Name]; dup {
			c.errs = append(c.errs, fmt.Errorf("skillcat: duplicate skill name %q at %s", s.Name, path))
			continue
		}
		s.Domain = DeriveDomain(s.Name, s.Description)
		c.byName[s.Name] = s
		c.byDomain[s.Domain] = append(c.byDomain[s.Domain], s.Name)
	}
	for d := range c.byDomain {
		sort.Strings(c.byDomain[d])
	}
	return c, nil
}

// Errors returns the per-skill exclusion errors collected during Load.
func (c *Catalog) Errors() []error { return append([]error(nil), c.errs...) }

// Domains returns the sorted list of domains that have at least one skill.
func (c *Catalog) Domains() []string {
	out := make([]string, 0, len(c.byDomain))
	for d := range c.byDomain {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// ForDomain returns the skills in a domain, name-sorted.
func (c *Catalog) ForDomain(domain string) []Skill {
	names := c.byDomain[strings.ToLower(strings.TrimSpace(domain))]
	out := make([]Skill, 0, len(names))
	for _, n := range names {
		out = append(out, c.byName[n])
	}
	return out
}

// Get returns a skill by exact name.
func (c *Catalog) Get(name string) (Skill, bool) {
	s, ok := c.byName[name]
	return s, ok
}

// Len returns the number of valid skills.
func (c *Catalog) Len() int { return len(c.byName) }

// domainRule is one keyword-to-domain rule.
type domainRule struct {
	domain   string
	keywords []string
}

// domainRules are applied in order; first match wins.
var domainRules = []domainRule{
	{"ad", []string{"active directory", "adcs", "ad cs", "kerberos", "ntlm", "ldap", "entra", "saml", "bloodhound"}},
	{"cloud", []string{"aws", "azure", "gcp", "cloud", "s3", "iam", "metadata"}},
	{"k8s", []string{"kubernetes", "k8s", "eks", "gke", "aks", "container", "docker"}},
	{"web", []string{"web", "http", "xss", "sqli", "sql injection", "oauth", "jwt", "ssrf", "idor", "graphql", "api", "request smuggling"}},
	{"wifi", []string{"wifi", "wireless", "bluetooth", "zigbee", "lorawan", "wpa"}},
	{"target-analysis", []string{"target analysis", "binary analysis", "executable analysis", "elf", "gtfobins binary"}},
	{"exploit-dev", []string{"exploit", "shellcode", "buffer overflow", "crash", "fuzzing", "mitigation"}},
	{"local", []string{"privilege escalation", "privesc", "suid", "sgid", "gtfobins", "sudo", "post exploitation", "local privilege"}},
	{"recon", []string{"recon", "osint", "enumeration", "scanning"}},
}

// normalizeText lowercases s and collapses every run of non-alphanumeric
// characters into a single space, wrapping the result in single spaces. This
// makes keyword matching operate on whole words (and whole multi-word phrases)
// rather than substrings, so a short keyword like "aws" cannot match inside
// "laws" and a hyphenated name like "request-smuggling" matches the multi-word
// keyword "request smuggling".
func normalizeText(s string) string {
	var b strings.Builder
	b.WriteByte(' ')
	prevSpace := true
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prevSpace = false
		} else if !prevSpace {
			b.WriteByte(' ')
			prevSpace = true
		}
	}
	if !prevSpace {
		b.WriteByte(' ')
	}
	return b.String()
}

// DeriveDomain maps a skill's name+description to a domain, generic if none
// match. Matching is on whole-word (and whole-phrase) boundaries via
// normalizeText, so short keywords do not false-match inside unrelated words.
func DeriveDomain(name, description string) string {
	hay := normalizeText(name + " " + description)
	for _, r := range domainRules {
		for _, kw := range r.keywords {
			if strings.Contains(hay, normalizeText(kw)) {
				return r.domain
			}
		}
	}
	return "generic"
}
