package main

import (
	"encoding/json"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	eng "blkchain/cli/internal/engagement"
)

// TestKgCommandRegistered asserts the PRODUCTION command registry dispatches
// `blk kg` to runKg, so removing the kg entry from commandSpecs (making the
// command unreachable) fails the suite.
func TestKgCommandRegistered(t *testing.T) {
	c, ok := lookupCommand("kg")
	if !ok {
		t.Fatal("kg is not registered in commandSpecs(); blk kg cannot dispatch")
	}
	if c.run == nil {
		t.Fatal("kg command has no run function")
	}
	if reflect.ValueOf(c.run).Pointer() != reflect.ValueOf(runKg).Pointer() {
		t.Fatal("kg command run is not runKg")
	}
	if c.group != hgEngage {
		t.Fatalf("kg group = %q, want %q", c.group, hgEngage)
	}
}

// seedKGWorkspace creates an engagement workspace at dir and seeds one recon
// task targeting an asset, with one evidence quote.
func seedKGWorkspace(t *testing.T, dir string) {
	t.Helper()
	ws, err := eng.OpenWorkspace(dir)
	if err != nil {
		t.Fatalf("OpenWorkspace: %v", err)
	}
	defer ws.Close()
	if _, err := ws.Store.Apply(eng.Delta{
		Upserts: []eng.Task{{ID: "a", Kind: "recon", Target: "10.0.0.1", Status: eng.StatusTodo}},
		Kind:    "seed",
	}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, err := ws.Store.RecordEvidence("a", "open 22/tcp"); err != nil {
		t.Fatalf("RecordEvidence: %v", err)
	}
}

func TestEngageGraphReadsWorkspace(t *testing.T) {
	dir := t.TempDir()
	seedKGWorkspace(t, dir)
	v, err := engageGraph(dir, eng.GraphQuery{})
	if err != nil {
		t.Fatalf("engageGraph: %v", err)
	}
	ids := map[string]bool{}
	for _, n := range v.Result.Nodes {
		ids[n.ID] = true
	}
	if !ids["task:a"] || !ids["asset:10.0.0.1"] {
		t.Fatalf("missing derived nodes; got %v", ids)
	}
	foundTargets := false
	for _, e := range v.Result.Edges {
		if e.Src == "task:a" && e.Rel == eng.RelTargets && e.Dst == "asset:10.0.0.1" {
			foundTargets = true
		}
	}
	if !foundTargets {
		t.Fatalf("missing targets edge; got %v", v.Result.Edges)
	}
	if v.Revision == 0 {
		t.Fatalf("revision should be non-zero after seeding")
	}
}

func TestFormatGraphTextWholeGraph(t *testing.T) {
	res := eng.GraphResult{
		Nodes: []eng.GraphNode{
			{ID: "asset:10.0.0.1", Type: eng.NodeAsset, Label: "10.0.0.1", Attrs: map[string]string{"surface": "network", "covered_dims": "3"}},
			{ID: "task:a", Type: eng.NodeTask, Label: "enumerate host", Attrs: map[string]string{"kind": "recon", "status": "done"}},
		},
		Edges: []eng.GraphEdge{{Src: "task:a", Dst: "asset:10.0.0.1", Rel: eng.RelTargets}},
	}
	out := formatGraphText(res, "")
	for _, want := range []string{"nodes", "edges", "task:a", "asset:10.0.0.1", eng.RelTargets} {
		if !strings.Contains(out, want) {
			t.Fatalf("whole-graph text missing %q:\n%s", want, out)
		}
	}
}

func TestFormatGraphTextNeighborhood(t *testing.T) {
	res := eng.GraphResult{
		Nodes: []eng.GraphNode{
			{ID: "asset:10.0.0.1", Type: eng.NodeAsset, Label: "10.0.0.1", Attrs: map[string]string{"surface": "network"}},
			{ID: "task:a", Type: eng.NodeTask, Label: "enumerate host"},
		},
		Edges: []eng.GraphEdge{{Src: "task:a", Dst: "asset:10.0.0.1", Rel: eng.RelTargets}},
	}
	out := formatGraphText(res, "asset:10.0.0.1")
	if !strings.Contains(out, "asset:10.0.0.1") || !strings.Contains(out, "task:a") || !strings.Contains(out, eng.RelTargets) {
		t.Fatalf("neighborhood text missing focal/edge:\n%s", out)
	}
}

func TestRunKgJSON(t *testing.T) {
	dir := t.TempDir()
	seedKGWorkspace(t, dir)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	prev := os.Stdout
	os.Stdout = w
	runErr := runKg([]string{"--workspace", dir, "--json"})
	w.Close()
	os.Stdout = prev
	outBytes, _ := io.ReadAll(r)
	if runErr != nil {
		t.Fatalf("runKg: %v", runErr)
	}

	var got struct {
		Nodes []eng.GraphNode `json:"nodes"`
		Edges []eng.GraphEdge `json:"edges"`
	}
	if err := json.Unmarshal(outBytes, &got); err != nil {
		t.Fatalf("runKg --json emitted invalid JSON: %v\n%s", err, outBytes)
	}
	if len(got.Nodes) == 0 {
		t.Fatalf("runKg --json returned no nodes:\n%s", outBytes)
	}
}
