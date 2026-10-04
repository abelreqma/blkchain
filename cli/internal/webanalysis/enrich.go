package webanalysis

import (
	"encoding/base64"
	"fmt"
	sitter "github.com/smacker/go-tree-sitter"
	"math"
	"regexp"
	"strings"
)

func decodeBase64(s string) (string, bool) {
	if len(s) > 64<<10 {
		return "", false
	}
	b, e := base64.StdEncoding.DecodeString(s)
	if e != nil {
		b, e = base64.RawStdEncoding.DecodeString(s)
	}
	return string(b), e == nil
}
func entropy(s string) float64 {
	counts := map[rune]int{}
	for _, r := range s {
		counts[r]++
	}
	h := 0.0
	for _, c := range counts {
		p := float64(c) / float64(len(s))
		h -= p * math.Log2(p)
	}
	return h
}

var hashOrID = regexp.MustCompile(`(?i)^(?:[a-f0-9]{16,}|[a-f0-9]{8}-[a-f0-9-]{27,})$`)
var secretAlphabet = regexp.MustCompile(`^[A-Za-z0-9_+/=.-]+$`)

func (a *analyzer) secret(n *sitter.Node, e *lexical) {
	v := a.eval(n, e, 0)
	if !v.known {
		return
	}
	s := v.text
	loc := a.loc(n)
	detector := ""
	confidence := "medium"
	if providerValue.MatchString(s) {
		detector = "provider-pattern"
		confidence = "high"
	} else {
		parent := n.Parent()
		key := ""
		if parent != nil {
			if parent.Type() == "pair" {
				key = a.text(field(parent, "key"))
			}
			if parent.Type() == "variable_declarator" {
				key = a.text(field(parent, "name"))
			}
		}
		if Sensitive(key) && len(s) >= 20 && len(s) <= 512 && !hashOrID.MatchString(s) && secretAlphabet.MatchString(s) && entropy(s) >= 3.5 && !strings.Contains(strings.ToLower(s), "example") && !strings.Contains(strings.ToLower(s), "placeholder") {
			detector = "entropy-context"
		}
	}
	if detector != "" {
		a.out.Findings = append(a.out.Findings, Finding{ID: ID(a.in.Unit.ID, detector, s), Kind: "secret-candidate", Detector: detector, Confidence: confidence, Location: loc, Preview: "[REDACTED]", Fingerprint: Fingerprint(s), Version: Version})
	}
}

var libraryBanner = regexp.MustCompile(`(?i)\b(jquery|react|angular|vue|lodash|bootstrap|moment|axios)[ /@v-]+v?([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?)`)

func (a *analyzer) comment(n *sitter.Node) {
	text := a.text(n)
	loc := a.loc(n)
	for _, m := range libraryBanner.FindAllStringSubmatch(text, 20) {
		a.out.Findings = append(a.out.Findings, Finding{ID: ID(a.in.Unit.ID, m[1], m[2]), Kind: "library", Detector: "version-banner", Confidence: "high", Location: loc, Preview: RedactText(m[0]), Version: Version, Library: strings.ToLower(m[1]), LibraryVersion: m[2]})
	}
	for _, word := range []string{"TODO", "FIXME", "feature", "admin", "debug", "internal", "sourceMappingURL"} {
		if strings.Contains(text, word) {
			preview := text
			if len(preview) > 1000 {
				preview = preview[:1000]
			}
			a.out.Findings = append(a.out.Findings, Finding{ID: ID(a.in.Unit.ID, "comment", string(rune(loc.Offset))), Kind: "comment-lead", Detector: "comment-context", Confidence: "low", Location: loc, Preview: RedactText(preview), Version: Version})
			break
		}
	}
}
func (a *analyzer) assignment(n *sitter.Node, e *lexical) {
	left := a.text(field(n, "left"))
	right := field(n, "right")
	loc := a.loc(n)
	if strings.HasSuffix(left, ".innerHTML") || strings.HasSuffix(left, ".outerHTML") || strings.HasSuffix(left, ".__proto__") || strings.HasSuffix(left, ".location") || strings.HasSuffix(left, ".href") {
		finding := Finding{ID: ID(a.in.Unit.ID, left, fmt.Sprint(loc.Offset)), Kind: "sink-lead", Detector: left, Confidence: "low", Location: loc, Preview: RedactText(a.text(n)), Version: Version}
		a.out.Findings = append(a.out.Findings, finding)
		for name, sym := range e.vars {
			if sym.v.kind == "parameter" && regexp.MustCompile(`\b`+regexp.QuoteMeta(name)+`\b`).MatchString(a.text(right)) {
				a.out.Relationships = append(a.out.Relationships, Relationship{ID: ID(e.function, finding.ID, name), From: e.function, To: finding.ID, Kind: "parameter-sink-lead", Field: name, Expression: RedactText(a.text(right))})
			}
		}
		for _, source := range []string{"location.search", "location.hash", "document.URL", "event.data"} {
			if strings.Contains(a.text(right), source) {
				a.out.Relationships = append(a.out.Relationships, Relationship{ID: ID(a.in.Unit.ID, finding.ID, source), From: a.in.Unit.ID, To: finding.ID, Kind: "source-sink-lead", Field: source})
			}
		}
	}
	if strings.HasSuffix(left, ".p") {
		if v := a.eval(right, e, 0); v.known {
			a.publicPaths[strings.TrimSuffix(left, ".p")] = v.text
		}
	}
	if strings.HasSuffix(left, ".u") && right != nil && right.Type() == "arrow_function" {
		keys := map[string]bool{}
		var scan func(*sitter.Node, int)
		scan = func(n *sitter.Node, d int) {
			if n == nil || d > 32 {
				return
			}
			if n.Type() == "pair" {
				k := a.text(field(n, "key"))
				if regexp.MustCompile(`^[0-9]+$`).MatchString(k) && len(keys) < 200 {
					keys[k] = true
				}
			}
			for i := 0; i < int(n.NamedChildCount()); i++ {
				scan(n.NamedChild(i), d+1)
			}
		}
		scan(right, 0)
		p := field(right, "parameter")
		if p == nil {
			p = child(field(right, "parameters"), 0)
		}
		name := a.text(p)
		body := field(right, "body")
		if body != nil && body.Type() == "statement_block" {
			a.gap("unsupported Webpack chunk resolver body")
			return
		}
		for _, k := range sortedBoolKeys(keys) {
			inner := e.child()
			inner.vars[name] = &symbol{v: value{text: k, known: true, kind: "string"}}
			v := a.eval(body, inner, 0)
			if v.known && strings.HasSuffix(v.text, ".js") {
				a.out.Dependencies = append(a.out.Dependencies, Dependency{URL: a.publicPaths[strings.TrimSuffix(left, ".u")] + v.text, Kind: "webpack-chunk", Location: loc})
			} else {
				a.gap("unresolved Webpack chunk expression")
			}
		}
	}
}
func sortedBoolKeys(v map[string]bool) []string {
	m := map[string]value{}
	for k := range v {
		m[k] = value{}
	}
	return sortedValueKeys(m)
}
