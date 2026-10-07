package engagement

import (
	"context"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"testing"
)

// graphNodeIDs returns every node id in the store, sorted.
func graphNodeIDs(t *testing.T, s *Store) []string {
	t.Helper()
	rows, err := s.db.Query(`SELECT id FROM graph_node ORDER BY id`)
	if err != nil {
		t.Fatalf("query nodes: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan node: %v", err)
		}
		out = append(out, id)
	}
	return out
}

// graphEdgeKeys returns every edge as "src|rel|dst", sorted.
func graphEdgeKeys(t *testing.T, s *Store) []string {
	t.Helper()
	rows, err := s.db.Query(`SELECT src, rel, dst FROM graph_edge`)
	if err != nil {
		t.Fatalf("query edges: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var src, rel, dst string
		if err := rows.Scan(&src, &rel, &dst); err != nil {
			t.Fatalf("scan edge: %v", err)
		}
		out = append(out, src+"|"+rel+"|"+dst)
	}
	sort.Strings(out)
	return out
}

// hasEdge reports whether the "src|rel|dst" key is present.
func hasEdge(t *testing.T, s *Store, key string) bool {
	t.Helper()
	for _, e := range graphEdgeKeys(t, s) {
		if e == key {
			return true
		}
	}
	return false
}

// hasNode reports whether a node id exists.
func hasNode(t *testing.T, s *Store, id string) bool {
	t.Helper()
	for _, n := range graphNodeIDs(t, s) {
		if n == id {
			return true
		}
	}
	return false
}

func TestGraphProjectionRetainsUnchangedIsolatedTask(t *testing.T) {
	s := openGraphStore(t)
	e := Engagement{Revision: 2, Tasks: []Task{{ID: "fixture", Objective: "Offline review", CreatedRev: 1, UpdatedRev: 1}}}
	if err := s.PopulateGraph(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if !hasNode(t, s, "task:fixture") {
		t.Fatal("current isolated task was removed as stale")
	}
}

// populateFromSnapshot snapshots the store and populates the graph from it.
func populateFromSnapshot(t *testing.T, s *Store) {
	t.Helper()
	e, err := s.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if err := s.PopulateGraph(context.Background(), e); err != nil {
		t.Fatalf("PopulateGraph: %v", err)
	}
}

// hasTable reports whether a table of the given name exists in the store.
func hasTable(t *testing.T, s *Store, name string) bool {
	t.Helper()
	var got string
	err := s.db.QueryRow(
		`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, name).Scan(&got)
	if err != nil {
		return false
	}
	return got == name
}

// openGraphStore opens a fresh store for graph tests.
func openGraphStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "e.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestMigrateCreatesGraphTables(t *testing.T) {
	s := openGraphStore(t)
	if !hasTable(t, s, "graph_node") {
		t.Errorf("graph_node table missing")
	}
	if !hasTable(t, s, "graph_edge") {
		t.Errorf("graph_edge table missing")
	}
}

func TestPopulateDerivesTaskAndAssetNodes(t *testing.T) {
	s := openGraphStore(t)
	if _, err := s.Apply(Delta{Upserts: []Task{
		{ID: "a", Kind: "recon", Target: "10.0.0.1", Status: StatusTodo},
	}, Kind: "seed"}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	populateFromSnapshot(t, s)
	if !hasNode(t, s, "task:a") {
		t.Errorf("task:a node missing; have %v", graphNodeIDs(t, s))
	}
	if !hasNode(t, s, "asset:10.0.0.1") {
		t.Errorf("asset:10.0.0.1 node missing; have %v", graphNodeIDs(t, s))
	}
	if !hasEdge(t, s, "task:a|"+RelTargets+"|asset:10.0.0.1") {
		t.Errorf("targets edge missing; have %v", graphEdgeKeys(t, s))
	}
}

func TestPopulateEmptyTargetNoAssetNode(t *testing.T) {
	s := openGraphStore(t)
	if _, err := s.Apply(Delta{Upserts: []Task{
		{ID: "a", Kind: "recon", Target: "", Status: StatusTodo},
	}, Kind: "seed"}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	populateFromSnapshot(t, s)
	for _, id := range graphNodeIDs(t, s) {
		if id == "asset:" {
			t.Fatalf("empty-target produced a bogus asset node")
		}
	}
	if len(graphEdgeKeys(t, s)) != 0 {
		t.Fatalf("empty-target produced edges: %v", graphEdgeKeys(t, s))
	}
}

func TestPopulateBasisDerivedFromEdge(t *testing.T) {
	s := openGraphStore(t)
	if _, err := s.Apply(Delta{Upserts: []Task{
		{ID: "a", Kind: "recon", Status: StatusDone},
	}, Kind: "seed"}); err != nil {
		t.Fatalf("Apply a: %v", err)
	}
	if _, err := s.Apply(Delta{Upserts: []Task{
		{ID: "b", Kind: "exploit-dev", Status: StatusTodo, BasisIDs: []string{"a"}},
	}, Kind: "candidate"}); err != nil {
		t.Fatalf("Apply b: %v", err)
	}
	populateFromSnapshot(t, s)
	if !hasEdge(t, s, "task:b|"+RelDerivedFrom+"|task:a") {
		t.Errorf("derived_from edge missing; have %v", graphEdgeKeys(t, s))
	}
}

func TestPopulateEvidenceNodeBounded(t *testing.T) {
	s := openGraphStore(t)
	if _, err := s.Apply(Delta{Upserts: []Task{
		{ID: "a", Kind: "recon", Status: StatusTodo},
	}, Kind: "seed"}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	long := make([]byte, EvidenceCap+500)
	for i := range long {
		long[i] = 'x'
	}
	if _, err := s.RecordEvidence("a", string(long)); err != nil {
		t.Fatalf("RecordEvidence: %v", err)
	}
	populateFromSnapshot(t, s)
	var evNode string
	for _, id := range graphNodeIDs(t, s) {
		if len(id) > len("evidence:") && id[:len("evidence:")] == "evidence:" {
			evNode = id
		}
	}
	if evNode == "" {
		t.Fatalf("no evidence node; have %v", graphNodeIDs(t, s))
	}
	var label string
	if err := s.db.QueryRow(`SELECT label FROM graph_node WHERE id = ?`, evNode).Scan(&label); err != nil {
		t.Fatalf("read evidence label: %v", err)
	}
	if len([]rune(label)) > EvidenceCap+len(truncatedMarker) {
		t.Fatalf("evidence label length %d exceeds bound %d", len([]rune(label)), EvidenceCap+len(truncatedMarker))
	}
	if !hasEdge(t, s, "task:a|"+RelEvidencedBy+"|"+evNode) {
		t.Errorf("evidenced_by edge missing; have %v", graphEdgeKeys(t, s))
	}
}

func TestPopulateCorrelatesTargetAndReconAsset(t *testing.T) {
	s := openGraphStore(t)
	if _, err := s.Apply(Delta{
		Upserts:      []Task{{ID: "a", Kind: "recon", Target: "10.0.0.1", Status: StatusTodo}},
		ReconUpserts: []ReconCoverage{{Surface: SurfaceNetwork, Asset: "10.0.0.1", Dimensions: map[string]ReconDimStatus{"ports": ReconCovered}}},
		Kind:         "seed",
	}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	populateFromSnapshot(t, s)
	count := 0
	for _, id := range graphNodeIDs(t, s) {
		if id == "asset:10.0.0.1" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("asset:10.0.0.1 appears %d times, want exactly 1 (target and recon coverage must correlate to one node)", count)
	}
}

func TestPopulateIdempotent(t *testing.T) {
	s := openGraphStore(t)
	if _, err := s.Apply(Delta{
		Upserts:      []Task{{ID: "a", Kind: "recon", Target: "10.0.0.1", Status: StatusTodo}},
		ReconUpserts: []ReconCoverage{{Surface: SurfaceNetwork, Asset: "10.0.0.1", Dimensions: map[string]ReconDimStatus{"ports": ReconCovered}}},
		Kind:         "seed",
	}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, err := s.RecordEvidence("a", "open 22/tcp"); err != nil {
		t.Fatalf("RecordEvidence: %v", err)
	}
	populateFromSnapshot(t, s)
	nodes1 := graphNodeIDs(t, s)
	edges1 := graphEdgeKeys(t, s)
	populateFromSnapshot(t, s)
	nodes2 := graphNodeIDs(t, s)
	edges2 := graphEdgeKeys(t, s)
	if len(nodes1) != len(nodes2) || len(edges1) != len(edges2) {
		t.Fatalf("populate not idempotent: nodes %d->%d edges %d->%d", len(nodes1), len(nodes2), len(edges1), len(edges2))
	}
}

func TestPopulateConcurrentWithApply(t *testing.T) {
	s := openGraphStore(t)
	const n = 40
	var wg sync.WaitGroup
	errs := make(chan error, n+8)

	// Writer: apply n task upserts.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			id := "t" + strconv.Itoa(i)
			if _, err := s.Apply(Delta{Upserts: []Task{{ID: id, Kind: "recon", Target: "h" + strconv.Itoa(i), Status: StatusTodo}}, Kind: "add"}); err != nil {
				errs <- err
				return
			}
		}
	}()

	// Populators: repeatedly snapshot and populate the graph while writes land.
	for p := 0; p < 4; p++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				e, err := s.Snapshot(context.Background())
				if err != nil {
					errs <- err
					return
				}
				if err := s.PopulateGraph(context.Background(), e); err != nil {
					errs <- err
					return
				}
			}
		}()
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent populate/apply error: %v", err)
	}

	// Final reconcile: one more populate, then every task is a node.
	populateFromSnapshot(t, s)
	res, err := s.QueryGraph(GraphQuery{Type: NodeTask})
	if err != nil {
		t.Fatalf("QueryGraph: %v", err)
	}
	if len(res.Nodes) != n {
		t.Fatalf("got %d task nodes, want %d", len(res.Nodes), n)
	}
}

// seedGraphFixture applies one recon task targeting an asset with coverage and
// one evidence quote, then populates the graph.
func seedGraphFixture(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.Apply(Delta{
		Upserts:      []Task{{ID: "a", Kind: "recon", Target: "10.0.0.1", Status: StatusTodo}},
		ReconUpserts: []ReconCoverage{{Surface: SurfaceNetwork, Asset: "10.0.0.1", Dimensions: map[string]ReconDimStatus{"ports": ReconCovered}}},
		Kind:         "seed",
	}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, err := s.RecordEvidence("a", "open 22/tcp"); err != nil {
		t.Fatalf("RecordEvidence: %v", err)
	}
	populateFromSnapshot(t, s)
}

func TestQueryGraphAll(t *testing.T) {
	s := openGraphStore(t)
	seedGraphFixture(t, s)
	res, err := s.QueryGraph(GraphQuery{})
	if err != nil {
		t.Fatalf("QueryGraph: %v", err)
	}
	// task:a, asset:10.0.0.1, one evidence node.
	if len(res.Nodes) != 3 {
		t.Fatalf("got %d nodes, want 3: %+v", len(res.Nodes), res.Nodes)
	}
	// targets edge + evidenced_by edge.
	if len(res.Edges) != 2 {
		t.Fatalf("got %d edges, want 2: %+v", len(res.Edges), res.Edges)
	}
	// Deterministic node ordering by id.
	if res.Nodes[0].ID != "asset:10.0.0.1" {
		t.Fatalf("nodes not ordered by id; first = %q", res.Nodes[0].ID)
	}
	// Asset node carries merged coverage attrs.
	for _, n := range res.Nodes {
		if n.ID == "asset:10.0.0.1" {
			if n.Attrs["surface"] != string(SurfaceNetwork) || n.Attrs["covered_dims"] != "1" {
				t.Fatalf("asset attrs not merged: %+v", n.Attrs)
			}
		}
	}
}

func TestQueryGraphByType(t *testing.T) {
	s := openGraphStore(t)
	seedGraphFixture(t, s)
	res, err := s.QueryGraph(GraphQuery{Type: NodeAsset})
	if err != nil {
		t.Fatalf("QueryGraph: %v", err)
	}
	if len(res.Nodes) != 1 || res.Nodes[0].Type != NodeAsset {
		t.Fatalf("type filter returned %+v, want one asset node", res.Nodes)
	}
	// No asset-to-asset edges, so edges among the type set is empty (non-nil).
	if res.Edges == nil {
		t.Fatalf("Edges must be non-nil")
	}
	if len(res.Edges) != 0 {
		t.Fatalf("got %d edges among assets, want 0", len(res.Edges))
	}
}

func TestQueryGraphNodeNeighbors(t *testing.T) {
	s := openGraphStore(t)
	seedGraphFixture(t, s)
	res, err := s.QueryGraph(GraphQuery{Node: "asset:10.0.0.1"})
	if err != nil {
		t.Fatalf("QueryGraph: %v", err)
	}
	// The asset plus its one neighbor (task:a).
	ids := map[string]bool{}
	for _, n := range res.Nodes {
		ids[n.ID] = true
	}
	if !ids["asset:10.0.0.1"] || !ids["task:a"] {
		t.Fatalf("neighbors missing; got %v", ids)
	}
	if len(res.Nodes) != 2 {
		t.Fatalf("got %d nodes, want 2 (self + 1 neighbor): %+v", len(res.Nodes), res.Nodes)
	}
	if len(res.Edges) != 1 || res.Edges[0].Rel != RelTargets {
		t.Fatalf("got edges %+v, want one targets edge", res.Edges)
	}
}

func TestQueryGraphMissingNode(t *testing.T) {
	s := openGraphStore(t)
	seedGraphFixture(t, s)
	res, err := s.QueryGraph(GraphQuery{Node: "asset:does-not-exist"})
	if err != nil {
		t.Fatalf("QueryGraph: %v", err)
	}
	if len(res.Nodes) != 0 || len(res.Edges) != 0 {
		t.Fatalf("missing node should yield empty result, got %+v", res)
	}
}

func TestUpsertGraphRoundTrip(t *testing.T) {
	s := openGraphStore(t)
	nodes := []GraphNode{
		{ID: "task:a", Type: NodeTask, Label: "recon a", Attrs: map[string]string{"status": "todo"}, CreatedRev: 1, UpdatedRev: 1},
		{ID: "asset:10.0.0.1", Type: NodeAsset, Label: "10.0.0.1", CreatedRev: 1, UpdatedRev: 1},
	}
	edges := []GraphEdge{{Src: "task:a", Dst: "asset:10.0.0.1", Rel: RelTargets, UpdatedRev: 1}}
	if err := s.UpsertGraph(nodes, edges); err != nil {
		t.Fatalf("UpsertGraph: %v", err)
	}
	var nc, ec int
	if err := s.db.QueryRow(`SELECT count(*) FROM graph_node`).Scan(&nc); err != nil {
		t.Fatalf("count nodes: %v", err)
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM graph_edge`).Scan(&ec); err != nil {
		t.Fatalf("count edges: %v", err)
	}
	if nc != 2 || ec != 1 {
		t.Fatalf("got %d nodes %d edges, want 2 nodes 1 edge", nc, ec)
	}
	// Re-upsert the same node with a changed label and later rev: it updates in
	// place (no duplicate) and preserves created_rev.
	nodes[0].Label = "recon a v2"
	nodes[0].UpdatedRev = 3
	if err := s.UpsertGraph(nodes[:1], nil); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	var label string
	var created, updated int64
	if err := s.db.QueryRow(`SELECT label, created_rev, updated_rev FROM graph_node WHERE id = ?`, "task:a").
		Scan(&label, &created, &updated); err != nil {
		t.Fatalf("read node: %v", err)
	}
	if label != "recon a v2" || created != 1 || updated != 3 {
		t.Fatalf("got label=%q created=%d updated=%d, want label=recon a v2 created=1 updated=3", label, created, updated)
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM graph_node`).Scan(&nc); err != nil {
		t.Fatalf("recount nodes: %v", err)
	}
	if nc != 2 {
		t.Fatalf("after re-upsert got %d nodes, want 2 (no duplicate)", nc)
	}
}

func TestGraphProjectionDropsOldRelationsAndRejectsStaleSnapshot(t *testing.T) {
	store := openGraphStore(t)
	task := Task{ID: "task", Kind: "recon", Target: "first.invalid", Status: StatusTodo,
		DependsOn: []string{"first"}, BasisIDs: []string{"first"}}
	_, err := store.Apply(Delta{Upserts: []Task{
		{ID: "first", Status: StatusTodo}, {ID: "second", Status: StatusTodo}, task,
	}, Kind: "seed"})
	if err != nil {
		t.Fatal(err)
	}
	old, err := store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	populateFromSnapshot(t, store)
	task.Target, task.DependsOn, task.BasisIDs = "second.invalid", []string{"second"}, []string{"second"}
	if _, err := store.Apply(Delta{Upserts: []Task{task}, Kind: "plan_update"}); err != nil {
		t.Fatal(err)
	}
	populateFromSnapshot(t, store)
	for _, relation := range []string{
		"task:task|targets|asset:first.invalid", "task:task|depends_on|task:first", "task:task|derived_from|task:first",
	} {
		if hasEdge(t, store, relation) {
			t.Errorf("superseded relation retained: %s", relation)
		}
	}
	if hasNode(t, store, "asset:first.invalid") {
		t.Error("orphan target retained")
	}
	if err := store.PopulateGraph(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	if hasEdge(t, store, "task:task|targets|asset:first.invalid") {
		t.Fatal("stale snapshot restored old target")
	}
}
