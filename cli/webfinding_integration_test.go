package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/engreport"
	"blkchain/cli/internal/webacquire"
	"blkchain/cli/internal/webanalysis"
	"blkchain/cli/internal/webcollect"
)

func TestDiscoveredCredentialReachesStdoutLogAndReports(t *testing.T) {
	password := "fixture p@ss'`word\nline"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app.js" {
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, "const password="+strconv.Quote(password)+";")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"password": password})
	}))
	defer target.Close()
	ws, err := engagement.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	if _, err = ws.Store.Apply(engagement.Delta{Kind: "fixture", Upserts: []engagement.Task{{ID: "credential-task", Status: engagement.StatusActive, Surface: engagement.SurfaceWeb}}}); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	remove := subscribeWebFindingOutput(context.Background(), ws.Store, &stdout)
	defer remove()
	writer := newReportWriter(ws.Store, ws.Dir, "fixture goal", target.URL, "safe")
	stop := writer.Start()
	defer stop()
	svc := webcollect.New(ws.Store, &webacquire.Broker{Policy: webacquire.Policy{Authorize: func(_ context.Context, r webacquire.Request) error {
		if !strings.HasPrefix(r.URL, target.URL+"/") {
			return fmt.Errorf("outside fixture")
		}
		return nil
	}, IPAllowed: func(ip net.IP) bool { return ip.IsLoopback() }}}, nil)
	svc.SetTask("credential-task")
	svc.DiscoveryAllowed = func(raw string) bool { return strings.HasPrefix(raw, target.URL+"/") }
	if _, err = svc.Collect(context.Background(), []string{target.URL + "/app.js", target.URL + "/api/password"}, webcollect.Options{Role: "reader"}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := ws.Store.WebSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	credentials := 0
	for _, finding := range webanalysis.Display(snapshot).Findings {
		if finding.Value == password {
			credentials++
			if finding.SourceURL == "" || finding.Artifact == "" || finding.Role != "reader" || finding.Preview != strconv.Quote(password) || finding.CredentialType != "password" {
				t.Fatal("credential provenance missing", finding)
			}
		}
	}
	if credentials != 2 {
		t.Fatalf("got %d credential findings; want script and response", credentials)
	}
	for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		var event struct {
			TaskID  string              `json:"task_id"`
			Finding webanalysis.Finding `json:"finding"`
		}
		if err = json.Unmarshal([]byte(line), &event); err != nil || event.TaskID != "credential-task" || event.Finding.Value != password {
			t.Fatalf("stdout lost credential: %q %v", line, err)
		}
	}
	if strings.Count(stdout.String(), "\n") != credentials {
		t.Fatal("stdout did not emit each credential")
	}
	logPath := filepath.Join(ws.EvidenceDir(), "web", "findings.jsonl")
	logged, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(logged, stdout.Bytes()) {
		t.Fatal("live stdout and log records differ")
	}
	st, err := os.Stat(logPath)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("finding log mode", err)
	}
	reportJSON := filepath.Join(ws.Dir, "report.json")
	deadline := time.Now().Add(3 * time.Second)
	var report engreport.Model
	for time.Now().Before(deadline) {
		data, e := os.ReadFile(reportJSON)
		if e == nil && json.Unmarshal(data, &report) == nil && report.Web != nil && len(report.Web.Findings) >= credentials {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if report.Web == nil {
		t.Fatal("live report did not update on finding discovery")
	}
	reportValues := 0
	for _, f := range report.Web.Findings {
		if f.Value == password {
			reportValues++
		}
	}
	if reportValues != credentials {
		t.Fatal("JSON report lost credential values", report.Web.Findings)
	}
	markdown, err := os.ReadFile(filepath.Join(ws.Dir, "report.md"))
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(password)
	if !strings.Contains(string(markdown), "### Discovered credential") || strings.Contains(string(markdown), "None yet.") {
		t.Fatal("credential omitted from report findings while its task was active")
	}
	if !bytes.Contains(markdown, append([]byte(`"value":`), encoded...)) {
		t.Fatal("Markdown report lost exact encoded credential")
	}
	if !strings.Contains(webView(snapshot, "findings", false, 90), strconv.Quote(password)) {
		t.Fatal("finding view redacted credential")
	}
	preview := webModelPreview("api-observation", "200\n\nfixture body", snapshot.Findings)
	if !strings.Contains(preview, string(encoded)) {
		t.Fatal("model never received discovered credential")
	}
}

func TestCredentialFindingTUIEventKeepsEngagementRunning(t *testing.T) {
	data, err := webanalysis.FindingEvent("credential-task", webanalysis.Finding{Kind: "secret-candidate", Value: "fixture-password", CredentialType: "password"})
	if err != nil {
		t.Fatal(err)
	}
	m := newKeyModel(t)
	m.working = true
	next, cmd := m.Update(webFindingMsg{Data: string(data)})
	if !next.(model).working || cmd == nil {
		t.Fatal("finding event interrupted engagement")
	}
	if output := fmt.Sprint(cmd()); !strings.Contains(output, "fixture-password") {
		t.Fatal("TUI credential output missing", output)
	}
}

func TestCredentialFindingFromRealCLIAndParserWorker(t *testing.T) {
	password := "fixture-cli-password"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, "const password="+strconv.Quote(password)+";")
	}))
	defer server.Close()
	root := t.TempDir()
	binary := filepath.Join(root, "blk")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("fixture binary build failed: %s %v", output, err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".blkchain"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".blkchain", "config.yaml"), []byte("allowed_binaries:\n  - web-api:GET\n"), 0600); err != nil {
		t.Fatal(err)
	}
	scopeFile := filepath.Join(root, "scope.txt")
	if err := os.WriteFile(scopeFile, []byte("127.0.0.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, asJSON := range []bool{false, true} {
		workspace := filepath.Join(root, fmt.Sprintf("workspace-%t", asJSON))
		args := []string{"web", "collect", server.URL + "/app.js", "--workspace", workspace, "--scope", scopeFile, "--auto", "--no-rdns"}
		if asJSON {
			args = append(args, "--json")
		}
		command := exec.CommandContext(ctx, binary, args...)
		command.Dir = root
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("CLI collection failed: %s %v", output, err)
		}
		if asJSON {
			var snapshot webanalysis.Snapshot
			if err = json.Unmarshal(output, &snapshot); err != nil {
				t.Fatalf("streamed findings corrupted JSON output: %v", err)
			}
			found := false
			for _, finding := range snapshot.Findings {
				found = found || finding.Value == password
			}
			if !found {
				t.Fatal("CLI JSON lost credential")
			}
		} else {
			found := false
			for _, line := range strings.Split(string(output), "\n") {
				var event struct {
					Finding webanalysis.Finding `json:"finding"`
				}
				if json.Unmarshal([]byte(line), &event) == nil && event.Finding.Value == password {
					found = true
				}
			}
			if !found {
				t.Fatal("real CLI never emitted the discovered password")
			}
		}
		logged, err := os.ReadFile(filepath.Join(workspace, "evidence", "web", "findings.jsonl"))
		if err != nil || !strings.Contains(string(logged), `"value":"`+password+`"`) {
			t.Fatal("real CLI finding log lost credential", err)
		}
	}
}

func TestAPIKeysEnvironmentAndOtherSecretsReachAllOutputs(t *testing.T) {
	key := "-----BEGIN PRIVATE KEY-----\nZml4dHVyZQ==\n-----END PRIVATE KEY-----"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/secrets":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Set-Cookie", "session=fixture-cookie; HttpOnly")
			_ = json.NewEncoder(w).Encode(map[string]string{"api_key": "fixture-key", "client_secret": "fixture-client-secret", "access_token": "fixture-token", "database_url": "postgres://fixture:fixture@db.test/db"})
		case "/config/env":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "API_KEY=fixture-env-key\nPORT=8000\n")
		case "/key.pem":
			w.Header().Set("Content-Type", "application/x-pem-file")
			fmt.Fprint(w, key)
		default:
			http.NotFound(w, r)
		}
	}))
	defer target.Close()
	ws, err := engagement.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	var output bytes.Buffer
	remove := subscribeWebFindingOutput(context.Background(), ws.Store, &output)
	defer remove()
	broker := &webacquire.Broker{Policy: webacquire.Policy{Authorize: func(_ context.Context, r webacquire.Request) error {
		if !strings.HasPrefix(r.URL, target.URL+"/") {
			return fmt.Errorf("outside fixture")
		}
		return nil
	}, IPAllowed: func(ip net.IP) bool { return ip.IsLoopback() }}}
	svc := webcollect.New(ws.Store, broker, nil)
	svc.DiscoveryAllowed = func(raw string) bool { return strings.HasPrefix(raw, target.URL+"/") }
	if _, err = svc.Collect(context.Background(), []string{target.URL + "/api/secrets", target.URL + "/config/env", target.URL + "/key.pem"}, webcollect.Options{Role: "reader"}); err != nil {
		t.Fatal(err)
	}
	writer := newReportWriter(ws.Store, ws.Dir, "secret exposure fixture", target.URL, "safe")
	if err = writer.Flush("in-progress"); err != nil {
		t.Fatal(err)
	}
	logged, err := os.ReadFile(filepath.Join(ws.EvidenceDir(), "web", "findings.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(logged, output.Bytes()) {
		t.Fatal("stdout and log differ")
	}
	reportBytes, err := os.ReadFile(filepath.Join(ws.Dir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report engreport.Model
	if err = json.Unmarshal(reportBytes, &report); err != nil || report.Web == nil {
		t.Fatal("structured report missing", err)
	}
	markdown, err := os.ReadFile(filepath.Join(ws.Dir, "report.md"))
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{"fixture-key", "fixture-client-secret", "fixture-token", "postgres://fixture:fixture@db.test/db", "fixture-env-key", "8000", key, "session=fixture-cookie; HttpOnly"}
	for _, value := range expected {
		found := false
		for _, finding := range report.Web.Findings {
			found = found || finding.Value == value
		}
		if !found {
			t.Fatal("structured report lost a sensitive value", value)
		}
		encoded, _ := json.Marshal(value)
		if !bytes.Contains(output.Bytes(), append([]byte(`"value":`), encoded...)) || !bytes.Contains(markdown, append([]byte(`"value":`), encoded...)) {
			t.Fatal("stdout or Markdown masked a sensitive value", value)
		}
	}
}
