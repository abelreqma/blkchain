package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"blkchain/cli/internal/engagement"

	"github.com/tmc/langchaingo/llms"
)

// runCall builds one run_command tool call with a bare binary and literal args.
func runCall(id, binary string, args ...string) llms.ToolCall {
	a, _ := json.Marshal(struct {
		Binary string   `json:"binary"`
		Args   []string `json:"args,omitempty"`
	}{Binary: binary, Args: args})
	return llms.ToolCall{ID: id, Type: "function", FunctionCall: &llms.FunctionCall{Name: "run_command", Arguments: string(a)}}
}

// TestTargetAnalysisExecutorReadOnlySequence drives a single target-analysis
// executor against a temp fixture standing in for an executable. The stubbed
// model emits the read-only inspection sequence; the test captures every
// run_command and asserts each is a non-destructive inspection of the fixture
// path, that the fixture is never executed (never the binary) and never written,
// and that its bytes are unchanged afterward.
func TestTargetAnalysisExecutorReadOnlySequence(t *testing.T) {
	d := testDeps(t, nil)

	// A plain regular file standing in for the target executable.
	fixture := filepath.Join(t.TempDir(), "target.bin")
	before := []byte("\x7fELF fixture bytes")
	if err := os.WriteFile(fixture, before, 0o755); err != nil {
		t.Fatal(err)
	}

	name, active := "eng", "t1"
	stage := engagement.Stage{Label: "dispatch", Tool: "target-analysis"}
	if _, err := d.Store.Apply(engagement.Delta{
		Upserts: []engagement.Task{{ID: "t1", Kind: "target-analysis", Target: fixture, Objective: "assess as privesc vector", Status: engagement.StatusActive}},
		SetName: &name, SetActiveID: &active, SetStage: &stage, Kind: "init",
	}); err != nil {
		t.Fatal(err)
	}
	// LOCAL profile: no binary allowlist, human confirms every command.
	d.Gate = safeLocalGate(t, &countingConfirmer{ok: true})
	d.Runs = NewRunOutputs()

	var mu sync.Mutex
	var got [][]string
	withStubExec(t, func(ctx context.Context, bin string, args []string, dir string, capBytes int, timeout time.Duration) runResult {
		mu.Lock()
		got = append(got, append([]string{bin}, args...))
		mu.Unlock()
		return runResult{Output: "inspection output for " + bin}
	})

	// The read-only inspection sequence, emitted as one round of tool calls.
	d.Model = &scriptModel{resps: []*llms.ContentResponse{
		{Choices: []*llms.ContentChoice{{ToolCalls: []llms.ToolCall{
			runCall("c1", "file", fixture),
			runCall("c2", "stat", fixture),
			runCall("c3", "getcap", fixture),
			runCall("c4", "ldd", fixture),
			runCall("c5", "strings", fixture),
			runCall("c6", "readelf", "-a", fixture),
		}}}},
		finalResp("verdict: not a privesc vector"),
	}}

	if _, err := runExecutor(context.Background(), d, "t1"); err != nil {
		t.Fatal(err)
	}

	if len(got) != 6 {
		t.Fatalf("captured %d commands, want 6:\n%v", len(got), got)
	}

	// readOnly is the set of inspection binaries this executor may run. Anything
	// outside it would be an unexpected (possibly mutating) command.
	readOnly := map[string]bool{
		"file": true, "ldd": true, "strings": true, "readelf": true,
		"nm": true, "objdump": true, "getcap": true, "stat": true, "ls": true,
	}
	for _, cmd := range got {
		bin := cmd[0]
		if !readOnly[bin] {
			t.Errorf("unexpected non-inspection binary %q in %v", bin, cmd)
		}
		if bin == fixture {
			t.Errorf("fixture executed as a command: %v", cmd)
		}
		// The fixture must appear only as an argument to be inspected, never as
		// the executable, and no arg may be a write/redirect of it.
		sawFixtureArg := false
		for _, a := range cmd[1:] {
			if a == fixture {
				sawFixtureArg = true
			}
			if a == ">" || a == ">>" || a == "-o" || a == "--output" {
				t.Errorf("write/redirect flag %q in %v", a, cmd)
			}
		}
		if !sawFixtureArg {
			t.Errorf("command does not inspect the fixture path: %v", cmd)
		}
	}

	// Non-destructive: the fixture's bytes are unchanged.
	after, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("fixture gone after inspection: %v", err)
	}
	if string(after) != string(before) {
		t.Errorf("fixture bytes changed: before %q after %q", before, after)
	}
}
