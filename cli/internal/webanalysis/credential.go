package webanalysis

import (
	"bytes"
	"encoding/json"
	"fmt"
	"golang.org/x/net/html"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

const MaxCredentialValue = 64 << 10

var passwordName = regexp.MustCompile(`(?i)^(password|passwd|pwd|pass|passphrase)$|[_-](password|passwd|pwd|passphrase)$`)

func PasswordName(name string) bool {
	name = strings.Trim(name, "\"'`")
	return passwordName.MatchString(name) || strings.HasSuffix(name, "Password") || strings.HasSuffix(name, "Passphrase")
}

func credentialFinding(unit SourceUnit, role, detector, name, value string, location Location) Finding {
	kind := secretType(name)
	if strings.Contains(value, "PRIVATE KEY") && strings.Contains(value, "-----BEGIN ") {
		kind = "private-key"
	}
	if kind == "" {
		kind = "secret"
	}
	return Finding{ID: ID(unit.ID, detector, name, value), Kind: "secret-candidate", Detector: detector, Confidence: "medium", Location: location, Preview: strconv.Quote(value), Value: value, CredentialType: kind, Name: name, SourceURL: unit.URL, Artifact: unit.Artifact, Role: role, Fingerprint: Fingerprint(value), Version: Version}
}

func JSONCredentials(unit SourceUnit, role string, body []byte) ([]Finding, []Gap) {
	if len(body) > MaxSource {
		return nil, []Gap{{Stage: "credentials", URL: unit.URL, Reason: "credential body limit"}}
	}
	var root, extra any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if decoder.Decode(&root) != nil || decoder.Decode(&extra) != io.EOF {
		return nil, nil
	}
	out := []Finding{}
	gaps := []Gap{}
	count := 0
	var walk func(any, string, int, bool)
	walk = func(value any, path string, depth int, env bool) {
		if depth > 32 {
			if len(gaps) == 0 || gaps[len(gaps)-1].Reason != "credential depth limit" {
				gaps = append(gaps, Gap{Stage: "credentials", URL: unit.URL, Reason: "credential depth limit"})
			}
			return
		}
		if count >= 20000 {
			return
		}
		count++
		switch node := value.(type) {
		case map[string]any:
			keys := make([]string, 0, len(node))
			for key := range node {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				if len(out) >= 1000 {
					gaps = append(gaps, Gap{Stage: "credentials", URL: unit.URL, Reason: "credential finding limit"})
					return
				}
				if len(path)+2*len(key)+1 > 4096 {
					gaps = append(gaps, Gap{Stage: "credentials", URL: unit.URL, Reason: "credential field path limit"})
					continue
				}
				field := path + "/" + strings.ReplaceAll(strings.ReplaceAll(key, "~", "~0"), "/", "~1")
				text, known := node[key].(string)
				if env {
					switch value := node[key].(type) {
					case json.Number:
						text, known = value.String(), true
					case bool:
						text, known = strconv.FormatBool(value), true
					}
				}
				if text, ok := text, known; ok && text != "" && (env || secretType(key) != "" || Sensitive(key) || providerValue.MatchString(text)) {
					if len(text) > MaxCredentialValue {
						gaps = append(gaps, Gap{Stage: "credentials", URL: unit.URL, Reason: "credential value exceeds finding limit"})
						continue
					}
					f := credentialFinding(unit, role, "response-field", key, text, Location{Unit: unit.ID})
					f.ID = ID(unit.ID, "response-field", field, text)
					f.Name = field
					f.EnvironmentVariable = env
					if env && secretType(key) == "" {
						f.CredentialType = "environment-variable"
					}
					out = append(out, f)
					continue
				}
				walk(node[key], field, depth+1, env || environmentName(key))
			}
		case string:
			if (env || providerValue.MatchString(node)) && node != "" {
				if len(node) > MaxCredentialValue || len(path) > 4096 || len(out) >= 1000 {
					gaps = append(gaps, Gap{Stage: "credentials", URL: unit.URL, Reason: "credential value, field or finding limit"})
					return
				}
				f := credentialFinding(unit, role, "response-field", path, node, Location{Unit: unit.ID})
				f.EnvironmentVariable = env
				if env && secretType(path) == "" {
					f.CredentialType = "environment-variable"
				}
				out = append(out, f)
			}
		case []any:
			for i, item := range node {
				walk(item, path+"/"+strconv.Itoa(i), depth+1, env)
			}
		}
	}
	walk(root, "", 0, EnvironmentSource(unit))
	if count >= 20000 {
		gaps = append(gaps, Gap{Stage: "credentials", URL: unit.URL, Reason: "credential field limit"})
	}
	return out, gaps
}

func FindingEvent(task string, f Finding) ([]byte, error) {
	data, err := json.Marshal(struct {
		TaskID  string  `json:"task_id,omitempty"`
		Finding Finding `json:"finding"`
	}{task, f})
	if err != nil {
		return nil, err
	}
	var out strings.Builder
	for _, r := range string(data) {
		if r < 0x7f {
			out.WriteRune(r)
		} else if r <= 0xffff {
			fmt.Fprintf(&out, "\\u%04x", r)
		} else {
			hi, lo := utf16.EncodeRune(r)
			fmt.Fprintf(&out, "\\u%04x\\u%04x", hi, lo)
		}
	}
	return []byte(out.String()), nil
}

func CredentialSummary(findings []Finding) string {
	var out strings.Builder
	for _, f := range findings {
		if f.Kind != "secret-candidate" || f.Value == "" {
			continue
		}
		data, err := FindingEvent("", f)
		if err != nil || out.Len()+len(data) > 199900 {
			out.WriteString("Credential preview limit; additional findings remain in the store.\n")
			break
		}
		out.Write(data)
		out.WriteByte('\n')
	}
	return out.String()
}

func HTMLCredentials(unit SourceUnit, role string, body []byte) ([]Finding, []Gap) {
	out := []Finding{}
	gaps := []Gap{}
	if len(body) > MaxSource {
		return out, []Gap{{Stage: "credentials", URL: unit.URL, Reason: "credential body limit"}}
	}
	tokenizer := html.NewTokenizer(bytes.NewReader(body))
	offset, line := 0, 1
	for count := 0; count < 20000; count++ {
		kind := tokenizer.Next()
		if kind == html.ErrorToken {
			return out, gaps
		}
		token := tokenizer.Token()
		if (kind == html.StartTagToken || kind == html.SelfClosingTagToken) && token.Data == "input" {
			name, value, typ := "", "", ""
			for _, attr := range token.Attr {
				switch attr.Key {
				case "name":
					name = attr.Val
				case "value":
					value = attr.Val
				case "type":
					typ = attr.Val
				}
			}
			if value != "" && (secretType(name) != "" || strings.EqualFold(typ, "password")) {
				if len(value) > MaxCredentialValue {
					gaps = append(gaps, Gap{Stage: "credentials", URL: unit.URL, Reason: "credential value exceeds finding limit"})
				} else {
					if name == "" {
						name = "password"
					}
					f := credentialFinding(unit, role, "password-input", name, value, Location{Unit: unit.ID, Offset: unit.Offset + offset, Line: line})
					if strings.EqualFold(typ, "password") {
						f.CredentialType = "password"
					}
					out = append(out, f)
				}
			}
		}
		raw := tokenizer.Raw()
		offset += len(raw)
		line += bytes.Count(raw, []byte{'\n'})
	}
	gaps = append(gaps, Gap{Stage: "credentials", URL: unit.URL, Reason: "credential token limit"})
	return out, gaps
}
