package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestActionTranscriptWritesSQLiteStore(t *testing.T) {
	ws, _ := fixtureStoreWorkspace(t, t.TempDir())
	defer ws.Close()
	trace := newActionTranscript(ws.Dir, "off", "fixture-runner", 10, 65536, nil)
	trace.onStore = func(data []byte) error { return ws.Store.RecordActionDocument(context.Background(), data) }
	if err := trace.record(actionRecord{Task: "network-task", Kind: "command", Command: "fixture", Status: "complete", ExitCode: 0, Stdout: "fixture banner"}); err != nil {
		t.Fatal(err)
	}
	page, err := ws.Store.Records(context.Background(), "action", "network", 0, 10)
	if err != nil || page.Total != 1 || len(page.Records) != 1 {
		t.Fatalf("live action missing from SQLite: %+v %v", page, err)
	}
	summaries, err := ws.Store.RecentActions(context.Background(), "network", 10)
	if err != nil || len(summaries) != 1 || summaries[0].Stdout != "fixture banner" {
		t.Fatalf("action summary missing output: %+v %v", summaries, err)
	}
	if err := os.Remove(filepath.Join(ws.Dir, "actions.jsonl")); err != nil {
		t.Fatal(err)
	}
	page, err = ws.Store.Records(context.Background(), "action", "network", 0, 10)
	if err != nil || page.Total != 1 {
		t.Fatalf("SQLite action depended on transcript file: %+v %v", page, err)
	}
}

func TestEngageTerminalRejectsControlSequences(t *testing.T) {
	input := "ok\x1b[31m red\x1b[0m\x1b]52;c;c2VjcmV0\x07\nnext\r\x00"
	got := terminalSafe(input)
	if strings.ContainsAny(got, "\x1b\x07\r\x00") || !strings.Contains(got, "ok red\nnext") {
		t.Fatalf("unsafe or lost text: %q", got)
	}
}

func TestEngageTranscriptKeepsExactEvidenceAndSafeDisplay(t *testing.T) {
	for _, mode := range []string{"off", "important", "full"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			var out bytes.Buffer
			trace := newActionTranscript(dir, mode, "worker", 10, 65536, &out)
			raw := "password=private-value\x1b[31m\n" + strings.Repeat("line\n", 30)
			if err := trace.record(actionRecord{Command: "curl token=private-value", Stdout: raw, Status: "complete"}); err != nil {
				t.Fatal(err)
			}
			saved, err := os.ReadFile(filepath.Join(dir, "actions.jsonl"))
			if err != nil || !strings.Contains(string(saved), "private-value") || !strings.Contains(string(saved), `\u001b[31m`) {
				t.Fatalf("exact evidence missing: %q %v", saved, err)
			}
			if strings.Contains(out.String(), "private-value") || strings.Contains(out.String(), "\x1b") {
				t.Fatalf("unsafe terminal output: %q", out.String())
			}
			switch mode {
			case "off":
				if out.Len() != 0 {
					t.Fatalf("off displayed an action: %q", out.String())
				}
			case "important":
				if !strings.Contains(out.String(), "preview truncated") {
					t.Fatalf("important did not truncate preview: %q", out.String())
				}
			case "full":
				if strings.Contains(out.String(), "preview truncated") || strings.Count(out.String(), "line") != 30 {
					t.Fatalf("full omitted output: %q", out.String())
				}
			}
		})
	}
}

func TestEngageTranscriptCheckpointFailureStopsRecord(t *testing.T) {
	trace := newActionTranscript(t.TempDir(), "full", "worker", 10, 1024, nil)
	trace.onPersist = func() error { return errors.New("checkpoint write failed") }
	if err := trace.record(actionRecord{Status: "denied"}); err == nil || !strings.Contains(err.Error(), "checkpoint write failed") {
		t.Fatalf("checkpoint failure was hidden: %v", err)
	}
}

func TestEngageTranscriptRejectsDuplicateJSONFields(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "actions.jsonl"), []byte(`{"id":"a-000001","id":"a-000002"}`+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	trace := newActionTranscript(dir, "off", "worker", 10, 1024, nil)
	if err := trace.restore(); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate transcript key accepted: %v", err)
	}
}

// TestTranscriptKeepsToolCredentialsAndRedactsOperatorSecrets pins a deliberate
// asymmetry in what the transcript shows.
//
// The credential-bearing target operands of the AD tools are left intact, in the
// argv and in the recorded command: impacket and smbclient take them on the
// command line by design, the audit record in toolaudit.go states that they stay
// visible, and an engagement transcript is expected to show exactly what ran.
// That behavior currently holds only because no redaction pattern happens to
// match a user:password@host operand, so a plausible hardening of RedactText
// would silently remove evidence the operator depends on and make that audit
// record false.
//
// The operator's own secrets are the other half: a bearer token, a key=value
// secret, and private key material must not survive into the rendered
// transcript, whichever side of the engagement they came from.
func TestTranscriptKeepsToolCredentialsAndRedactsOperatorSecrets(t *testing.T) {
	kept := []struct{ name, text string }{
		{"impacket domain user password host", "secretsdump.py ACME/svc:Winter2026@dc01.acme.test"},
		{"impacket password containing at", "secretsdump.py ACME/svc:Win@2026@dc01.acme.test"},
		{"impacket hashes pair", "secretsdump.py -hashes aad3b435b51404ee:31d6cfe0d16ae931 ACME/svc@dc01.acme.test"},
		{"smbclient percent form", `smbclient -U ACME/svc%Winter2026 //dc01.acme.test/C$`},
		{"kerberos principal", "kinit svc@ACME.TEST"},
	}
	for _, tc := range kept {
		t.Run("keeps "+tc.name, func(t *testing.T) {
			if got := redactEngageText(tc.text); got != tc.text {
				t.Errorf("the recorded command lost evidence\n got: %s\nwant: %s", got, tc.text)
			}
		})
	}

	removed := []struct{ name, text, secret string }{
		{"bearer token", "curl -H 'Authorization: Bearer abc123def456ghi' https://10.0.0.1/", "abc123def456ghi"},
		{"password assignment", "app --password=Winter2026", "Winter2026"},
		{"api key assignment", "app --api_key: sk-operator-value", "sk-operator-value"},
		{"openssh private key", "-----BEGIN OPENSSH PRIVATE KEY-----", "BEGIN OPENSSH PRIVATE KEY"},
		{"aws access key id", "env AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"},
	}
	for _, tc := range removed {
		t.Run("redacts "+tc.name, func(t *testing.T) {
			got := redactEngageText(tc.text)
			if strings.Contains(got, tc.secret) {
				t.Errorf("the transcript leaked %q: %s", tc.secret, got)
			}
			if !strings.Contains(got, "REDACTED") {
				t.Errorf("no redaction marker in %q", got)
			}
		})
	}
}
