package webanalysis

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

var secretCamel = regexp.MustCompile(`([a-z0-9])([A-Z])`)
var secretAcronym = regexp.MustCompile(`([A-Z]+)([A-Z][a-z])`)

func secretWords(name string) string {
	name = secretAcronym.ReplaceAllString(name, "${1}_${2}")
	name = secretCamel.ReplaceAllString(name, "${1}_${2}")
	return strings.Join(strings.FieldsFunc(strings.ToLower(strings.Trim(name, "\"'`")), func(r rune) bool { return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9') }), " ")
}

func secretType(name string) string {
	if PasswordName(name) {
		return "password"
	}
	words := " " + secretWords(name) + " "
	for _, rule := range []struct{ phrase, kind string }{
		{"private key", "private-key"}, {"signing key", "signing-key"}, {"encryption key", "encryption-key"},
		{"api key", "api-key"}, {"apikey", "api-key"}, {"access key", "access-key"},
		{"connection string", "connection-string"}, {"database url", "connection-string"}, {"db url", "connection-string"}, {"redis url", "connection-string"}, {"dsn", "connection-string"},
		{"jwt", "token"}, {"otp", "one-time-code"}, {"passcode", "one-time-code"}, {"token", "token"}, {"authorization", "authorization"}, {"bearer", "token"}, {"cookie", "cookie"}, {"session", "session"},
		{"csrf", "csrf-token"}, {"signature", "signature"}, {"secret", "secret"}, {"credential", "secret"},
	} {
		if strings.Contains(words, " "+rule.phrase+" ") {
			return rule.kind
		}
	}
	return ""
}

func environmentName(name string) bool {
	switch secretWords(name) {
	case "env", "environment", "environment variables", "env vars", "envvars":
		return true
	}
	return false
}

func EnvironmentSource(unit SourceUnit) bool {
	if unit.Language == "env" || environmentName(unit.Name) {
		return true
	}
	u, err := url.Parse(unit.URL)
	if err != nil {
		return false
	}
	name := path.Base(u.Path)
	return name == ".env" || strings.HasPrefix(name, ".env.") || environmentName(name)
}

var configAssignment = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_.-]{0,255})[ \t]*(=|:)(.*)$`)
var privateKeyStart = regexp.MustCompile(`-----BEGIN ([A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?)-----`)

func TextCredentials(unit SourceUnit, role string, body []byte) ([]Finding, []Gap) {
	findings := []Finding{}
	gaps := []Gap{}
	if json.Valid(body) {
		return findings, gaps
	}
	if len(body) > MaxSource {
		return findings, []Gap{{Stage: "credentials", URL: unit.URL, Reason: "credential body limit"}}
	}
	for _, match := range privateKeyStart.FindAllSubmatchIndex(body, 1001) {
		if len(findings) >= 1000 {
			gaps = append(gaps, Gap{Stage: "credentials", URL: unit.URL, Reason: "credential finding limit"})
			break
		}
		label := string(body[match[2]:match[3]])
		end := bytes.Index(body[match[1]:], []byte("-----END "+label+"-----"))
		if end < 0 {
			gaps = append(gaps, Gap{Stage: "credentials", URL: unit.URL, Reason: "private key block incomplete"})
			continue
		}
		end += match[1] + len("-----END "+label+"-----")
		if end-match[0] > MaxCredentialValue {
			gaps = append(gaps, Gap{Stage: "credentials", URL: unit.URL, Reason: "credential value exceeds finding limit"})
			continue
		}
		value := string(body[match[0]:end])
		f := credentialFinding(unit, role, "private-key-block", label, value, Location{Unit: unit.ID, Offset: unit.Offset + match[0], Line: bytes.Count(body[:match[0]], []byte{'\n'}) + 1})
		f.CredentialType = "private-key"
		findings = append(findings, f)
	}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 4096), MaxCredentialValue+4096)
	env := EnvironmentSource(unit)
	offset, line := 0, 0
	for scanner.Scan() {
		raw := scanner.Text()
		line++
		if line > 20000 || len(findings) >= 1000 {
			gaps = append(gaps, Gap{Stage: "credentials", URL: unit.URL, Reason: "credential line or finding limit"})
			break
		}
		location := Location{Unit: unit.ID, Offset: unit.Offset + offset, Line: line}
		offset += len(raw) + 1
		if !utf8.ValidString(raw) {
			gaps = append(gaps, Gap{Stage: "credentials", URL: unit.URL, Reason: "configuration line encoding unsupported"})
			continue
		}
		raw = strings.TrimSpace(raw)
		if strings.HasPrefix(raw, "export ") {
			raw = strings.TrimSpace(strings.TrimPrefix(raw, "export "))
		}
		match := configAssignment.FindStringSubmatch(raw)
		if match == nil || !env && secretType(match[1]) == "" {
			continue
		}
		expression := match[3]
		value := strings.TrimSpace(expression)
		if value == "" {
			continue
		}
		if value[0] == '\'' || value[0] == '"' {
			quote := value[0]
			if len(value) < 2 || value[len(value)-1] != quote {
				gaps = append(gaps, Gap{Stage: "credentials", URL: unit.URL, Reason: "configuration value is incomplete or multiline"})
				continue
			}
			if quote == '\'' {
				value = value[1 : len(value)-1]
			} else {
				decoded, err := strconv.Unquote(value)
				if err != nil {
					gaps = append(gaps, Gap{Stage: "credentials", URL: unit.URL, Reason: "configuration value needs runtime decoding"})
					continue
				}
				value = decoded
			}
		}
		if strings.Contains(value, "${") || strings.Contains(value, "$(") || strings.Contains(value, "process.env.") {
			gaps = append(gaps, Gap{Stage: "credentials", URL: unit.URL, Reason: "configuration value requires runtime resolution: " + match[1]})
			continue
		}
		if len(value) > MaxCredentialValue {
			gaps = append(gaps, Gap{Stage: "credentials", URL: unit.URL, Reason: "credential value exceeds finding limit"})
			continue
		}
		if value == "" {
			continue
		}
		f := credentialFinding(unit, role, "configuration-assignment", match[1], value, location)
		f.Expression = expression
		f.EnvironmentVariable = env
		if env && secretType(match[1]) == "" {
			f.CredentialType = "environment-variable"
		}
		findings = append(findings, f)
	}
	if scanner.Err() != nil {
		gaps = append(gaps, Gap{Stage: "credentials", URL: unit.URL, Reason: "credential configuration line limit"})
	}
	return findings, gaps
}

func HeaderCredentials(unit SourceUnit, role string, headers http.Header) ([]Finding, []Gap) {
	findings := []Finding{}
	gaps := []Gap{}
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if secretType(name) == "" {
			continue
		}
		for _, value := range headers[name] {
			if value == "" {
				continue
			}
			if len(value) > MaxCredentialValue || len(findings) >= 1000 {
				gaps = append(gaps, Gap{Stage: "credentials", URL: unit.URL, Reason: "credential header value or finding limit"})
				continue
			}
			f := credentialFinding(unit, role, "response-header", name, value, Location{Unit: unit.ID})
			findings = append(findings, f)
		}
	}
	return findings, gaps
}
