package main

import (
	"errors"
	"strings"
	"testing"

	"blkchain/cli/internal/engagement"
)

func TestParseKgArgs(t *testing.T) {
	cases := []struct {
		in      string
		want    engagement.GraphQuery
		wantErr bool
	}{
		{"", engagement.GraphQuery{}, false},
		{"  ", engagement.GraphQuery{}, false},
		{"node task:1", engagement.GraphQuery{Node: "task:1"}, false},
		{"node asset:10.0.0.5", engagement.GraphQuery{Node: "asset:10.0.0.5"}, false},
		{"type task", engagement.GraphQuery{Type: engagement.NodeTask}, false},
		{"type asset", engagement.GraphQuery{Type: engagement.NodeAsset}, false},
		{"type evidence", engagement.GraphQuery{Type: engagement.NodeEvidence}, false},
		{"type bogus", engagement.GraphQuery{}, true},
		{"node", engagement.GraphQuery{}, true},
		{"node a b", engagement.GraphQuery{}, true},
		{"type", engagement.GraphQuery{}, true},
		{"garbage", engagement.GraphQuery{}, true},
	}
	for _, c := range cases {
		got, err := parseKgArgs(c.in)
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("parseKgArgs(%q) = (%+v, %v), want (%+v, err=%v)", c.in, got, err, c.want, c.wantErr)
		}
	}
}

// setKgSource registers a graph source for the test and clears it after.
func setKgSource(t *testing.T, fn func(q engagement.GraphQuery) (kgView, error)) {
	t.Helper()
	SetEngageGraphSource(fn)
	t.Cleanup(func() { SetEngageGraphSource(nil) })
}

func sampleGraph() engagement.GraphResult {
	return engagement.GraphResult{
		Nodes: []engagement.GraphNode{
			{ID: "task:1", Type: engagement.NodeTask, Label: "recon the target", Attrs: map[string]string{"kind": "recon", "status": "done"}},
			{ID: "asset:10.0.0.5", Type: engagement.NodeAsset, Attrs: map[string]string{"surface": "web"}},
			{ID: "evidence:1", Type: engagement.NodeEvidence, Label: "sqlmap dump"},
		},
		Edges: []engagement.GraphEdge{
			{Src: "task:1", Dst: "asset:10.0.0.5", Rel: "targets"},
			{Src: "evidence:1", Dst: "task:1", Rel: "evidenced_by"},
		},
	}
}

func TestKgBlockNoEngagement(t *testing.T) {
	noColor(t)
	setKgSource(t, nil)
	if got := kgBlock(""); !strings.Contains(got, "no engagement") {
		t.Errorf("kgBlock with no source = %q, want a no-engagement message", got)
	}
}

func TestKgBlockWholeGraph(t *testing.T) {
	noColor(t)
	res := sampleGraph()
	setKgSource(t, func(q engagement.GraphQuery) (kgView, error) {
		return kgView{Name: "acme", Revision: 7, Nodes: res.Nodes, Edges: res.Edges, Result: res}, nil
	})
	got := kgBlock("")
	for _, want := range []string{"engagement: acme", "rev 7", "nodes 3", "edges 2", "task:1", "asset:10.0.0.5", "evidence:1", "targets", "evidenced_by"} {
		if !strings.Contains(got, want) {
			t.Errorf("kgBlock whole graph missing %q:\n%s", want, got)
		}
	}
}

func TestKgBlockNodeFocus(t *testing.T) {
	noColor(t)
	res := sampleGraph()
	var gotQ engagement.GraphQuery
	setKgSource(t, func(q engagement.GraphQuery) (kgView, error) {
		gotQ = q
		return kgView{Name: "acme", Revision: 7, Nodes: res.Nodes, Edges: res.Edges, Result: res}, nil
	})
	got := kgBlock("node task:1")
	if gotQ.Node != "task:1" || gotQ.Type != "" {
		t.Errorf("kgBlock(node) built query %+v, want Node=task:1", gotQ)
	}
	// focus mode renders the focal node and its incident edges with arrows, not
	// the whole-graph "nodes N  edges M" header.
	for _, want := range []string{"task:1", "->", "<-", "asset:10.0.0.5", "evidence:1"} {
		if !strings.Contains(got, want) {
			t.Errorf("kgBlock focus missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "nodes 3  edges") {
		t.Errorf("focus mode should not print the whole-graph header:\n%s", got)
	}
}

func TestKgBlockTypeFilterBuildsQuery(t *testing.T) {
	noColor(t)
	res := sampleGraph()
	var gotQ engagement.GraphQuery
	setKgSource(t, func(q engagement.GraphQuery) (kgView, error) {
		gotQ = q
		return kgView{Name: "acme", Revision: 7, Result: res}, nil
	})
	kgBlock("type asset")
	if gotQ.Type != engagement.NodeAsset || gotQ.Node != "" {
		t.Errorf("kgBlock(type asset) built query %+v, want Type=asset", gotQ)
	}
}

func TestKgBlockBadArgsShortCircuits(t *testing.T) {
	noColor(t)
	called := false
	setKgSource(t, func(q engagement.GraphQuery) (kgView, error) {
		called = true
		return kgView{}, nil
	})
	got := kgBlock("type bogus")
	if called {
		t.Error("a parse error must not reach the graph source")
	}
	if !strings.Contains(got, "task") || !strings.Contains(got, "asset") || !strings.Contains(got, "evidence") {
		t.Errorf("bad-type error should name the valid types: %q", got)
	}
}

func TestKgBlockQueryError(t *testing.T) {
	noColor(t)
	setKgSource(t, func(q engagement.GraphQuery) (kgView, error) {
		return kgView{}, errors.New("kg: query: boom")
	})
	if got := kgBlock(""); !strings.Contains(got, "boom") {
		t.Errorf("kgBlock query error = %q, want the error surfaced", got)
	}
}

func TestKgBlockSanitizesLabels(t *testing.T) {
	noColor(t)
	res := engagement.GraphResult{
		Nodes: []engagement.GraphNode{
			{ID: "evidence:1", Type: engagement.NodeEvidence, Label: "red\x1b[31mtext"},
		},
	}
	setKgSource(t, func(q engagement.GraphQuery) (kgView, error) {
		return kgView{Name: "acme", Revision: 1, Result: res}, nil
	})
	got := kgBlock("")
	if strings.Contains(got, "\x1b") {
		t.Errorf("escape sequence from a node label was not sanitized:\n%q", got)
	}
	if !strings.Contains(got, "evidence:1") {
		t.Errorf("sanitized output dropped the node id:\n%s", got)
	}
}

// /kg has a dispatch case and prints in both the no-engagement and active states.
func TestKgCommandDispatches(t *testing.T) {
	m := newTestModel(t)
	setKgSource(t, nil)
	if _, cmd := m.dispatchInput("/kg"); cmd == nil {
		t.Fatalf("/kg with no engagement should still print something")
	}
	setKgSource(t, func(q engagement.GraphQuery) (kgView, error) {
		return kgView{Name: "acme", Revision: 1, Result: sampleGraph()}, nil
	})
	if _, cmd := m.dispatchInput("/kg node task:1"); cmd == nil {
		t.Fatalf("/kg node with an engagement should print the neighborhood")
	}
}
