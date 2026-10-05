package webanalysis

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestExactBodyAdaptersPreserveWireBytes(t *testing.T) {
	cases := []struct{ kind, mime, body string }{
		{"json", "application/json", " [1, {\"a\":true}] \n"},
		{"json", "application/json", "{}"},
		{"json", "application/problem+json", "null"},
		{"text", "text/plain", "text\r\nexact\x00"},
		{"form", "application/x-www-form-urlencoded", "a=1&a=2&b=%2f+"},
		{"multipart", "multipart/form-data; boundary=fixture", "--fixture\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"x.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n\x00\xff\r\n--fixture--\r\n"},
		{"binary", "application/octet-stream", "\x00\xff\xfe"},
		{"opaque", "application/xml", "<request id=\"1\"/>\r\n"},
	}
	for _, c := range cases {
		t.Run(c.kind+c.mime, func(t *testing.T) {
			e := RequestExample{Headers: http.Header{"Content-Type": []string{c.mime}}}
			SetRequestBody(&e, []byte(c.body))
			data, err := json.Marshal(e)
			if err != nil {
				t.Fatal(err)
			}
			var stored RequestExample
			if err = json.Unmarshal(data, &stored); err != nil {
				t.Fatal(err)
			}
			kind, body, err := ReplayBody(stored)
			if err != nil || kind != c.kind || !bytes.Equal(body, []byte(c.body)) {
				t.Fatalf("kind=%s body=%q err=%v", kind, body, err)
			}
		})
	}
}
func TestExactBodyAdaptersFailClosed(t *testing.T) {
	for _, e := range []RequestExample{
		{Body: "secret", BodyOmitted: true},
		{Body: "%%%", BodyEncoding: "base64"},
		{Body: "a", BodyEncoding: "unknown"},
		{Body: "bad", Headers: http.Header{"Content-Type": []string{"application/json"}}},
		{Body: "--missing", Headers: http.Header{"Content-Type": []string{"multipart/form-data"}}},
		{Body: strings.Repeat("x", MaxReplayBody+1)},
	} {
		if _, _, err := ReplayBody(e); err == nil {
			t.Fatal("invalid body accepted")
		}
	}
}
func TestWebSocketEvidenceSeparatesHandshakeMessagesAndDenials(t *testing.T) {
	e := RequestExample{URL: "wss://fixture.test/socket", Method: "GET", Status: 101}
	op, err := FromObserved(e)
	if err != nil || op.Validation != "handshake-observed" || OperationEvidence(op).Grade != "handshake-observed" {
		t.Fatal(op, err)
	}
	e.Direction = "sent"
	e.Denied = true
	denied, _ := FromObserved(e)
	if denied.Validation != "attempted" || OperationEvidence(denied).Grade != "discovered" {
		t.Fatal(denied)
	}
	e.Denied = false
	message, _ := FromObserved(e)
	if message.Validation != "message-observed" || OperationEvidence(message).Grade != "message-observed" {
		t.Fatal(message)
	}
	template, err := CurlTemplate(message)
	if err != nil || template.Replayable || template.Command != "" {
		t.Fatal(template, err)
	}
}

func TestEvidenceGradesNormalizeStoredWebSocketLabels(t *testing.T) {
	s := GradeSnapshot(Snapshot{Operations: []Operation{{Protocol: "websocket", Validation: "response-observed", Examples: []RequestExample{{Status: 101}}}}, Findings: []Finding{{Kind: "secret-candidate", Confidence: "high"}}})
	if s.Operations[0].Validation != "handshake-observed" || s.Operations[0].Evidence.Grade != "handshake-observed" || s.Findings[0].Evidence.Grade != "detected" {
		t.Fatal(s)
	}
	for _, grade := range []EvidenceGrade{s.Operations[0].Evidence, s.Findings[0].Evidence} {
		if grade.Explanation == "" || strings.Contains(grade.Explanation, "%") {
			t.Fatal(grade)
		}
	}
}
