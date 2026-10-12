package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"blkchain/cli/internal/secgate"
	"github.com/vmihailenco/msgpack/v5"
)

func TestMSFRPCCommandShellFixture(t *testing.T) {
	var secret [16]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	password := hex.EncodeToString(secret[:])
	t.Setenv("BLKCHAIN_MSF_FIXTURE_PASSWORD", password)
	var mu sync.Mutex
	var shellOutput string
	var sequence int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/1.0" || r.Header.Get("Content-Type") != "binary/message-pack" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var request []any
		if msgpack.Unmarshal(body, &request) != nil || len(request) < 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		response := map[string]any{}
		switch request[0] {
		case "auth.login":
			if len(request) == 3 && request[1] == "fixture" && request[2] == password {
				response["result"], response["token"] = "success", "fixture-token"
			} else {
				response["error"] = true
			}
		case "session.list":
			response["7"] = map[string]any{"type": "shell", "tunnel_peer": "127.0.0.1:4444"}
		case "session.shell_write":
			if len(request) != 4 || request[1] != "fixture-token" || request[2] != "7" {
				response["error"] = true
				break
			}
			command := request[3].(string)
			out, err := exec.Command("/bin/sh", "-c", command).CombinedOutput()
			if err != nil {
				response["error"] = true
				break
			}
			mu.Lock()
			shellOutput = string(out)
			sequence++
			mu.Unlock()
			response["write_count"] = len(command)
		case "session.shell_read":
			mu.Lock()
			if request[3] == "0" {
				response["seq"], response["data"] = "1", ""
			} else {
				response["seq"], response["data"] = "2", shellOutput
			}
			mu.Unlock()
		default:
			response["error"] = true
		}
		encoded, _ := msgpack.Marshal(response)
		w.Header().Set("Content-Type", "binary/message-pack")
		_, _ = w.Write(encoded)
	}))
	defer server.Close()
	f, err := secgate.ParseFoothold("127.0.0.1 transport=msf-rpc rpc=" + server.URL + "/api/1.0 session=7 user=fixture passenv=BLKCHAIN_MSF_FIXTURE_PASSWORD surfaces=local,network,ad,container,cloud-aws,cloud-gcp")
	if err != nil {
		t.Fatal(err)
	}
	carrier, err := newFootholdTransport(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := carrier.msf.active(context.Background()); err != nil {
		t.Fatal(err)
	}
	wrong := &msfRPCTransport{endpoint: carrier.msf.endpoint, user: carrier.msf.user, password: carrier.msf.password,
		session: carrier.msf.session, host: "127.0.0.2", client: carrier.msf.client}
	if err := wrong.active(context.Background()); err == nil {
		t.Fatal("Metasploit session with a different peer was accepted")
	}
	result, outputs := runMSFRPCStages(context.Background(), carrier.msf, []pipelineStage{{Binary: "printf", Args: []string{"through-msf"}}}, 4096, 5*time.Second)
	if result.Err != nil || result.ExitCode != 0 || !strings.Contains(result.Output, "through-msf") || len(outputs) != 1 {
		t.Fatalf("Metasploit RPC command: result=%+v outputs=%+v", result, outputs)
	}
	scope, err := secgate.ParseScope(strings.NewReader("127.0.0.1\n"))
	if err != nil {
		t.Fatal(err)
	}
	policy := secgate.DefaultPolicy()
	policy.Foothold = f
	gate := &secgate.Gate{Mode: secgate.Auto, Scope: scope, Policy: policy, Allow: secgate.NewAllowlist()}
	if err := gate.Start(); err != nil {
		t.Fatal(err)
	}
	workspace := t.TempDir()
	trace := newActionTranscript(workspace, "off", policy.RunnerID, 10, 65536, nil)
	if err := os.WriteFile(filepath.Join(workspace, "actions.jsonl"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	runner := &engageRunner{foothold: carrier, workers: map[string]string{}}
	ctx := context.WithValue(context.Background(), engageRuntimeKey{}, &engageRuntime{runner: runner, trace: trace, policy: policy, cancel: func() {}})
	result = runAuthorized(ctx, gate, "printf", []string{"dispatched-msf"}, "fixture", 4096, 5*time.Second,
		actionOrigin{TaskID: "fixture", Surface: secgate.SurfaceLocal})
	if result.Err != nil || result.Output != "dispatched-msf" {
		t.Fatalf("Metasploit RPC dispatch=%+v", result)
	}
	mu.Lock()
	defer mu.Unlock()
	if sequence != 2 {
		t.Fatalf("shell writes=%d, want two", sequence)
	}
}

func TestMSFRPCDoesNotFollowRedirect(t *testing.T) {
	requests := 0
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
	}))
	defer destination.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", destination.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	var secret [16]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BLKCHAIN_MSF_FIXTURE_PASSWORD", hex.EncodeToString(secret[:]))
	f, err := secgate.ParseFoothold("127.0.0.1 transport=msf-rpc rpc=" + origin.URL + "/api/1.0 session=1 user=fixture passenv=BLKCHAIN_MSF_FIXTURE_PASSWORD")
	if err != nil {
		t.Fatal(err)
	}
	carrier, err := newFootholdTransport(f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := carrier.msf.login(context.Background()); err == nil || requests != 0 {
		t.Fatalf("Metasploit RPC redirect forwarded credentials: requests=%d err=%v", requests, err)
	}
}
