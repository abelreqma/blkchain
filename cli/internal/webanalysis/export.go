package webanalysis

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

type Template struct {
	Operation  string   `json:"operation"`
	Command    string   `json:"command,omitempty"`
	Body       string   `json:"body,omitempty"`
	BodyFile   string   `json:"body_file,omitempty"`
	Replayable bool     `json:"replayable"`
	Gaps       []string `json:"gaps"`
}

func shellQuote(s string) (string, error) {
	for _, r := range s {
		if r < 32 || r == 127 || r >= 0x80 && r <= 0x9f {
			return "", errors.New("control character in export")
		}
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'", nil
}

var envName = regexp.MustCompile(`[^A-Z0-9_]`)

func EnvName(s string) string { return "BLK_WEB_" + envName.ReplaceAllString(strings.ToUpper(s), "_") }
func CurlTemplate(op Operation) (Template, error) {
	t := Template{Operation: op.ID, Replayable: true, Gaps: []string{}}
	if UnsupportedObservedBody(op) {
		t.Replayable = false
		t.Gaps = append(t.Gaps, "structured export cannot represent this body; select a stored example with --example for exact replay")
		return t, nil
	}
	if op.Protocol != "http" || op.Method == "UNKNOWN" || op.Method == "" {
		t.Replayable = false
		t.Gaps = append(t.Gaps, "protocol-specific reproduction required")
		return t, nil
	}
	raw := op.Origin + op.Path
	if op.Query != "" {
		raw += "?" + op.Query
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Host == "" || u.Scheme != "http" && u.Scheme != "https" {
		return t, errors.New("invalid operation URL")
	}
	q := u.Query()
	for k := range q {
		if Sensitive(k) {
			q.Set(k, "{"+EnvName(k)+"}")
			t.Replayable = false
		}
	}
	u.RawQuery = q.Encode()
	uquote, err := shellQuote(u.String())
	if err != nil {
		return t, err
	}
	method, err := shellQuote(op.Method)
	if err != nil {
		return t, err
	}
	parts := []string{"curl", "--max-time", "30", "--request", method, "--url", uquote}
	headers := http.Header{}
	if len(op.Examples) > 0 {
		headers = op.Examples[len(op.Examples)-1].Headers.Clone()
	}
	if headers == nil {
		headers = http.Header{}
	}
	if op.ContentType != "" {
		headers.Set("Content-Type", op.ContentType)
	}
	for _, p := range op.Parameters {
		if strings.HasPrefix(p.Field, "header.") {
			name := strings.TrimPrefix(p.Field, "header.")
			if headers.Get(name) == "" {
				headers.Set(name, "{"+p.Name+"}")
			}
		}
	}
	keys := []string{}
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Host") || strings.EqualFold(k, "Accept-Encoding") {
			continue
		}
		if Sensitive(k) {
			key, err := shellQuote(k + ": ")
			if err != nil {
				return t, err
			}
			parts = append(parts, "--header", key+"\"${"+EnvName(k)+"}\"")
			t.Replayable = false
			t.Gaps = AddUnique(t.Gaps, "session credential refresh required")
		} else {
			v, err := shellQuote(k + ": " + strings.Join(headers[k], ", "))
			if err != nil {
				return t, err
			}
			parts = append(parts, "--header", v)
		}
	}
	body := map[string]any{}
	for _, p := range op.Parameters {
		if strings.HasPrefix(p.Field, "body.") {
			body[strings.TrimPrefix(p.Field, "body.")] = "{" + p.Name + "}"
		}
		if p.Unresolved {
			t.Replayable = false
			t.Gaps = AddUnique(t.Gaps, "unresolved parameters or signature")
		}
	}
	if op.GraphQL != "" {
		body["query"] = RedactText(op.GraphQL)
		vars := map[string]string{}
		for _, v := range op.Variables {
			vars[v] = "{" + v + "}"
		}
		body["variables"] = vars
	}
	if len(body) > 0 {
		b, _ := json.MarshalIndent(body, "", "  ")
		t.Body = string(b)
		t.BodyFile = Hash([]byte(t.Body)) + ".body.json"
		if strings.Contains(strings.ToLower(op.ContentType), "form-urlencoded") {
			form := url.Values{}
			for k, v := range body {
				if value, ok := v.(string); ok {
					form.Set(k, value)
				} else {
					return t, errors.New("structured body requires JSON content type")
				}
			}
			t.Body = form.Encode()
			t.BodyFile = Hash([]byte(t.Body)) + ".body.txt"
		}
		f, _ := shellQuote("@" + t.BodyFile)
		parts = append(parts, "--data-binary", f)
		t.Replayable = false
		t.Gaps = AddUnique(t.Gaps, "fill the body template")
	}
	if len(op.Unresolved) > 0 || strings.Contains(raw, "{") {
		t.Replayable = false
		t.Gaps = AddUnique(t.Gaps, "unresolved URL or expression")
	}
	t.Command = strings.Join(parts, " ")
	return t, nil
}
