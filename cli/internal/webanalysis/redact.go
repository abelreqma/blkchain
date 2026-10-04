package webanalysis

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
)

var credentialValue = regexp.MustCompile(`(?i)((?:authorization|password|passwd|secret|token|api[_-]?key|csrf|session|signature)[\w-]*["']?\s*[:=]\s*["']?)([^\s"'<>;,}]+)`)
var bearerValue = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/-]+`)
var quotedValue = regexp.MustCompile(`['"\x60]([^'"\x60\r\n]{1,1000})['"\x60]`)
var providerValue = regexp.MustCompile(`(?:AKIA|ASIA)[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255}|AIza[0-9A-Za-z_-]{35}|sk_live_[A-Za-z0-9]{16,255}|-----BEGIN [A-Z ]*PRIVATE KEY-----`)

func RedactText(s string) string {
	s = providerValue.ReplaceAllString(s, "[REDACTED]")
	s = bearerValue.ReplaceAllString(s, "Bearer [REDACTED]")
	s = credentialValue.ReplaceAllString(s, "${1}[REDACTED]")
	return SafeText(s)
}
func RedactURL(s string) string {
	u, e := url.Parse(s)
	if e != nil {
		return "[invalid URL]"
	}
	u.User = nil
	q := u.Query()
	for k := range q {
		if Sensitive(k) {
			q[k] = []string{"[REDACTED]"}
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}
func Redacted(s Snapshot) Snapshot {
	b, _ := json.Marshal(s)
	var v any
	_ = json.Unmarshal(b, &v)
	fingerprints := map[string]bool{}
	for _, f := range s.Findings {
		if f.Kind == "secret-candidate" && f.Fingerprint != "" {
			fingerprints[f.Fingerprint] = true
		}
	}
	redactKnown := func(s string) string {
		if fingerprints[Fingerprint(strings.Trim(s, "\"'\x60"))] {
			return "[REDACTED]"
		}
		return quotedValue.ReplaceAllStringFunc(s, func(m string) string {
			inner := m[1 : len(m)-1]
			if fingerprints[Fingerprint(inner)] {
				return "'[REDACTED]'"
			}
			if decoded, ok := decodeBase64(inner); ok && (fingerprints[Fingerprint(decoded)] || providerValue.MatchString(decoded)) {
				return "'[REDACTED encoded value]'"
			}
			return m
		})
	}
	var walk func(any, string) any
	walk = func(v any, key string) any {
		switch x := v.(type) {
		case map[string]any:
			name, _ := x["name"].(string)
			field, _ := x["field"].(string)
			if Sensitive(name + " " + field) {
				if _, ok := x["expression"]; ok {
					x["expression"] = "[REDACTED]"
				}
				if _, ok := x["default"]; ok {
					x["default"] = "[REDACTED]"
				}
			}
			for k, n := range x {
				x[k] = walk(n, k)
			}
		case []any:
			for i, n := range x {
				x[i] = walk(n, key)
			}
		case string:
			if key == "body" {
				return "[REDACTED request body; see parameter shapes]"
			}
			x = redactKnown(x)
			if Sensitive(key) && key != "fingerprint" {
				return "[REDACTED]"
			}
			if strings.Contains(strings.ToLower(key), "url") {
				return RedactURL(x)
			}
			return RedactText(x)
		}
		return v
	}
	b, _ = json.Marshal(walk(v, ""))
	var out Snapshot
	_ = json.Unmarshal(b, &out)
	return out
}

func Display(s Snapshot) Snapshot {
	out := Redacted(s)
	out.Operations = append([]Operation(nil), s.Operations...)
	out.Requests = append([]RequestExample(nil), s.Requests...)
	return out
}
