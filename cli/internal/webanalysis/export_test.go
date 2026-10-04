package webanalysis

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestCurlQuotingCredentialsAndProtocols(t *testing.T) {
	o := Operation{ID: ID("operation"), Method: "POST", Origin: "https://fixture.test", Path: "/api/x'$(touch /tmp/never)", Protocol: "http", ContentType: "application/json", Parameters: []Parameter{{Name: "amount", Field: "body.amount", Unresolved: true}}, Examples: []RequestExample{{Headers: http.Header{"Authorization": []string{"Bearer private"}, "X-Note": []string{"quote'$(touch /tmp/never)"}}}}}
	v, e := CurlTemplate(o)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(v.Command, "private") || !strings.Contains(v.Command, `'"'"'`) || !strings.Contains(v.Command, `"${BLK_WEB_AUTHORIZATION}"`) || v.Replayable || strings.Contains(v.Body, "private") {
		t.Fatal(v)
	}
	o.Path = "/x\n--output=/etc/passwd"
	if _, e = CurlTemplate(o); e == nil {
		t.Fatal("control injection")
	}
	o.Protocol = "websocket"
	v, e = CurlTemplate(o)
	if e != nil || v.Command != "" || v.Replayable {
		t.Fatal(v)
	}
}
func TestObservedTemplateJoiningAndValidation(t *testing.T) {
	a := Operation{ID: ID("static"), Origin: "https://fixture.test", Path: "/api/users/{id}", Method: "GET", Protocol: "http", Discoveries: []string{"historical"}, Validation: "unvalidated"}
	b, e := FromObserved(RequestExample{URL: "https://fixture.test/api/users/42", Method: "GET", Status: 403, Role: "reader"})
	if e != nil || !MatchesObserved(a, b) {
		t.Fatal(e, a, b)
	}
	a = MergeOperation(a, b)
	if a.Validation != "access-response" || len(a.Discoveries) != 2 {
		t.Fatal(a)
	}
	a = MergeOperation(a, Operation{Validation: "attempted"})
	if a.Validation != "access-response" {
		t.Fatal("status regressed")
	}
}
func TestPinnedRetireRangesAndUnknownVersion(t *testing.T) {
	repo := []byte(`{"fixture-lib":{"extractors":{"filecontent":["FixtureLib v(\u00a7\u00a7version\u00a7\u00a7)"]},"vulnerabilities":[{"atOrAbove":"1.0.0","below":"2.0.0","identifiers":{"CVE":["CVE-2000-0001"],"summary":"test advisory"}}]}}`)
	f, g, e := ScanRetire(context.Background(), SourceUnit{ID: ID("unit")}, []byte("/*! FixtureLib v1.2.3 */"), repo, "2026-10-03 pinned")
	if e != nil || len(g) != 0 || len(f) != 2 {
		t.Fatal(f, g, e)
	}
	if f[1].Kind != "library-vulnerability" || f[1].Snapshot == "" {
		t.Fatal(f)
	}
	f, _, e = ScanRetire(context.Background(), SourceUnit{ID: ID("unit")}, []byte("/*! FixtureLib */"), repo, "snapshot")
	if e != nil || len(f) != 0 {
		t.Fatal("invented version")
	}
	_, _ = json.Marshal(f)
}

func TestDisplayPreservesExactOperationRecords(t *testing.T) {
	op := Operation{ID: ID("exact-operation"), Query: "token=fixture-value", Parameters: []Parameter{{Name: "token", Field: "header.Authorization", Expression: "fixture-value"}}, Examples: []RequestExample{{Headers: http.Header{"Authorization": []string{"fixture-value"}, "Cookie": []string{"session=fixture-cookie"}}, Body: `{"password":"fixture-body"}`}}}
	s := Snapshot{Operations: []Operation{op}, Requests: op.Examples}
	shown := Display(s)
	if shown.Operations[0].Parameters[0].Expression != "fixture-value" || shown.Operations[0].Examples[0].Headers.Get("Cookie") != "session=fixture-cookie" || shown.Operations[0].Examples[0].Body != op.Examples[0].Body || shown.Requests[0].Body != op.Examples[0].Body {
		t.Fatal("operation values changed", shown)
	}
}

func TestUnsupportedObservedBodyCannotProduceEmptyReplayTemplate(t *testing.T) {
	for _, body := range []string{`[1,2]`, `"text"`, `true`, `null`, `{}`, `opaque-text`} {
		op, err := FromObserved(RequestExample{URL: "https://fixture.test/write", Method: "POST", Body: body, Headers: http.Header{"Content-Type": []string{"application/json"}}})
		if err != nil {
			t.Fatal(err)
		}
		if len(op.Unresolved) == 0 || op.Examples[0].Body != body {
			t.Fatal("unsupported body not retained and flagged", op)
		}
		template, err := CurlTemplate(op)
		if err != nil || template.Replayable || template.Command != "" {
			t.Fatal("unsupported body exported as empty request", template, err)
		}
		op.Unresolved = nil
		template, err = CurlTemplate(op)
		if err != nil || template.Replayable || template.Command != "" {
			t.Fatal("older unsupported record exported as empty request", template, err)
		}
	}
	op, err := FromObserved(RequestExample{URL: "https://fixture.test/write", Method: "POST", Body: `{"count":2}`, Headers: http.Header{"Content-Type": []string{"application/json"}}})
	if err != nil || len(op.Unresolved) != 0 {
		t.Fatal(op, err)
	}
	template, err := CurlTemplate(op)
	if err != nil || !strings.Contains(template.Command, "--data-binary") {
		t.Fatal(template, err)
	}
}

func TestMixedCaseFormBodyHasReplayFields(t *testing.T) {
	op, err := FromObserved(RequestExample{URL: "https://fixture.test/write", Method: "POST", Body: "a=1", Headers: http.Header{"Content-Type": []string{"APPLICATION/X-WWW-FORM-URLENCODED; charset=UTF-8"}}})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range op.Parameters {
		found = found || p.Field == "body.a"
	}
	template, err := CurlTemplate(op)
	if !found || err != nil || template.Body == "" || !strings.Contains(template.Command, "--data-binary") {
		t.Fatal(op, template, err)
	}
}
