package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"blkchain/cli/internal/askuser"
	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/secgate"
	"github.com/tmc/langchaingo/llms"
)

type convergenceLiveModel struct {
	model     toolLoopModel
	forceTool string
	stages    []string
	models    []string
}

func (m *convergenceLiveModel) GenerateContent(ctx context.Context, msgs []llms.MessageContent, opts ...llms.CallOption) (*llms.ContentResponse, error) {
	var settings llms.CallOptions
	for _, opt := range opts {
		opt(&settings)
	}
	stage, _ := ctx.Value(stageKey{}).(string)
	m.stages = append(m.stages, stage)
	m.models = append(m.models, settings.Model)
	if len(settings.Tools) > 0 && m.forceTool != "" {
		opts = append(opts, llms.WithToolChoice(llms.ToolChoice{Type: "function", Function: &llms.FunctionReference{Name: m.forceTool}}))
	}
	return m.model.GenerateContent(ctx, msgs, opts...)
}

func TestEngageConvergenceLocalLLM(t *testing.T) {
	if os.Getenv("BLKCHAIN_ENGAGE_LLM_E2E") != "1" {
		t.Skip("requires the local LLM and retrieval stack")
	}
	t.Setenv("BLK_ENABLE_THINKING", "0")
	cfg := ragconfig.Load()
	modelID := resolveModel(cfg)
	base, err := newOMLX(cfg, modelID)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := newRetrievalClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	results, err := rc.Search(ctx, "HTTP response fingerprinting headers", 3, nil)
	if err != nil || len(results) == 0 {
		t.Fatalf("live retrieval: results=%d err=%v", len(results), err)
	}
	t.Logf("retrieval: %d corpus results through embed, Qdrant, and rerank", len(results))
	t.Setenv("BLKCHAIN_ENGAGE_ORCHESTRATOR_MODEL", modelID)
	for _, tc := range []struct {
		name, tool, goal, reason string
		rounds, calls, idle      string
	}{
		{"round-cap", "plan_add", "Create one web inspection task for 192.0.2.1, then stop. Do not complete it or claim findings.", "round cap", "1", "20", "3"},
		{"call-cap", "plan_add", "Create one web inspection task for 192.0.2.1, then stop. Do not complete it or claim findings.", "tool call cap", "20", "1", "3"},
		{"no-progress", "ask_user", "Ask the operator which goal to use. If clarification is suppressed, ask again. Do not create tasks or claim findings.", "no-progress", "20", "20", "2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("BLKCHAIN_ENGAGE_MAX_ROUNDS", tc.rounds)
			t.Setenv("BLKCHAIN_ENGAGE_MAX_CALLS", tc.calls)
			t.Setenv("BLKCHAIN_ENGAGE_NO_PROGRESS_ROUNDS", tc.idle)
			m := &convergenceLiveModel{model: base, forceTool: tc.tool}
			d := testDeps(t, m)
			d.Cfg, d.RC = cfg, rc
			out, err := runOrchestrator(ctx, d, tc.goal)
			if err != nil || !strings.Contains(out, tc.reason) || strings.Contains(out, "Final synthesis unavailable") || len(out) < 100 {
				t.Fatalf("out=%q stages=%v err=%v", out, m.stages, err)
			}
			if m.stages[len(m.stages)-1] != "engagement_synthesis" {
				t.Fatalf("stages=%v", m.stages)
			}
			for _, id := range m.models {
				if id != modelID {
					t.Fatalf("model override=%q want=%q", id, modelID)
				}
			}
			t.Logf("model=%s stages=%v report:\n%s", modelID, m.stages, out)
		})
	}
	t.Run("repl-executor", func(t *testing.T) {
		t.Setenv("BLKCHAIN_ENGAGE_MAX_ROUNDS", "2")
		t.Setenv("BLKCHAIN_ENGAGE_MAX_CALLS", "64")
		t.Setenv("BLKCHAIN_ENGAGE_NO_PROGRESS_ROUNDS", "3")
		var requests atomic.Int32
		fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			w.Header().Set("Server", "blk-convergence-fixture")
			fmt.Fprint(w, "convergence-fixture-ok")
		}))
		defer fixture.Close()
		cwd, wsDir := t.TempDir(), t.TempDir()
		if err := os.WriteFile(filepath.Join(cwd, "ROE.md"), []byte("## In Scope\n127.0.0.1\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(cwd, ".blkchain"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(cwd, ".blkchain", "config.yaml"), []byte("allowed_binaries:\n  - curl\n"), 0600); err != nil {
			t.Fatal(err)
		}
		goal := "Create one web task for " + fixture.URL + ". Dispatch that task. Use only curl with --max-time 5 to fetch the HTTP response. Record exact response evidence, complete the task, and return a report. Do not scan ports or add follow-on tasks."
		out, err := runReplEngage(ctx, wsDir, cwd, secgate.Auto, false, base, rc, cfg, modelPrefs{}, nil, nil, askuser.AutoAsker{}, nil, goal, nil)
		if err != nil {
			t.Fatalf("REPL: %v; report=%q", err, out)
		}
		ws, err := engagement.OpenWorkspace(wsDir)
		if err != nil {
			t.Fatal(err)
		}
		defer ws.Close()
		ev, err := ws.Store.AllEvidence()
		if err != nil {
			t.Fatal(err)
		}
		captured := false
		for _, quotes := range ev {
			for _, quote := range quotes {
				if strings.Contains(quote, "convergence-fixture-ok") {
					captured = true
				}
			}
		}
		if requests.Load() == 0 || !captured || !strings.Contains(out, "convergence-fixture-ok") || !strings.Contains(out, "Engagement paused: round cap") {
			t.Fatalf("requests=%d captured=%v report=%q", requests.Load(), captured, out)
		}
		t.Logf("REPL local fixture: %d HTTP requests; report:\n%s", requests.Load(), out)
	})
	t.Run("cli-round-cap", func(t *testing.T) {
		t.Setenv("BLKCHAIN_ENGAGE_MAX_ROUNDS", "1")
		t.Setenv("BLKCHAIN_ENGAGE_MAX_CALLS", "20")
		t.Setenv("XDG_CONFIG_HOME", t.TempDir())
		binary, err := filepath.Abs("blk")
		if err != nil {
			t.Fatal(err)
		}
		cwd, wsDir := t.TempDir(), t.TempDir()
		scope := filepath.Join(cwd, "scope.txt")
		if err := os.WriteFile(scope, []byte("192.0.2.1\n"), 0600); err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(ctx, binary, "engage", "--auto", "--scope", scope, "--workspace", wsDir, "--model", modelID,
			"Create one web inspection task for 192.0.2.1. Create the task first. Do not dispatch it or claim findings.")
		command.Dir = cwd
		output, err := command.CombinedOutput()
		if err != nil || !strings.Contains(string(output), "Engagement paused: round cap") || strings.Contains(string(output), "Final synthesis unavailable") {
			t.Fatalf("CLI err=%v output=%s", err, output)
		}
		for _, name := range []string{"report.md", "report.json"} {
			if _, err := os.Stat(filepath.Join(wsDir, name)); err != nil {
				t.Fatal(err)
			}
		}
		reportData, err := os.ReadFile(filepath.Join(wsDir, "report.json"))
		if err != nil {
			t.Fatal(err)
		}
		var persisted struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(reportData, &persisted); err != nil {
			t.Fatal(err)
		}
		if persisted.Status != "paused" {
			t.Fatalf("persisted report status=%q", persisted.Status)
		}
		t.Logf("CLI round-cap report:\n%s", output)
	})
}
