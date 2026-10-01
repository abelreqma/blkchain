package engagement

import (
	"context"
	"database/sql"
	"encoding/json"
	"sort"
	"strconv"
)

// graph.go is the engagement knowledge graph: two additive SQLite tables that
// hold a pure projection of the store (tasks, their targets, evidence rows,
// recon coverage, and the depends_on/basis_ids/citation relationships) as nodes
// and edges, so tasks/assets/evidence correlate across an engagement.
//
// The graph is derived, never authoritative: PopulateGraph rebuilds it from
// current store state as an idempotent upsert (the store is append-only for
// tasks/evidence/assets, and a task status change is an upsert), so a query can
// populate-then-read and always reflect the store. Graph writes take the store
// write lock and never go through Apply, so they never fire the Apply listeners
// and never recurse.

// graphSchema creates the node and edge tables and their lookup indexes. It is
// run once from migrate() alongside the core schema and is idempotent.
const graphSchema = `
CREATE TABLE IF NOT EXISTS graph_node (
	id TEXT PRIMARY KEY,
	type TEXT NOT NULL,
	label TEXT,
	attrs TEXT,
	created_rev INTEGER,
	updated_rev INTEGER
);
CREATE TABLE IF NOT EXISTS graph_edge (
	src TEXT NOT NULL,
	dst TEXT NOT NULL,
	rel TEXT NOT NULL,
	updated_rev INTEGER,
	PRIMARY KEY (src, dst, rel)
);
CREATE INDEX IF NOT EXISTS graph_edge_src ON graph_edge(src);
CREATE INDEX IF NOT EXISTS graph_edge_dst ON graph_edge(dst);
CREATE INDEX IF NOT EXISTS graph_node_type ON graph_node(type);
`

// Node type values. A node's id is namespaced by type ("task:<id>",
// "asset:<value>", "evidence:<rowid>") so the three derivations never collide.
const (
	NodeTask     = "task"
	NodeAsset    = "asset"
	NodeEvidence = "evidence"
)

// Edge relation values. Every edge points from a task to the thing it relates
// to, so the graph reads as "this task targets/depends on/derives from/is
// evidenced by that".
const (
	RelTargets     = "targets"      // task -> asset (Task.Target)
	RelDependsOn   = "depends_on"   // task -> task  (Task.DependsOn)
	RelDerivedFrom = "derived_from" // task -> task  (Task.BasisIDs provenance)
	RelEvidencedBy = "evidenced_by" // task -> evidence (stored evidence row)
)

// GraphNode is one entity in the engagement knowledge graph.
type GraphNode struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"`
	Label      string            `json:"label"`
	Attrs      map[string]string `json:"attrs,omitempty"`
	CreatedRev int64             `json:"created_rev"`
	UpdatedRev int64             `json:"updated_rev"`
}

// GraphEdge is one directed relationship between two nodes.
type GraphEdge struct {
	Src        string `json:"src"`
	Dst        string `json:"dst"`
	Rel        string `json:"rel"`
	UpdatedRev int64  `json:"updated_rev"`
}

// marshalAttrs encodes a node attribute map as JSON text; nil and empty give "".
// encoding/json sorts map keys, so the text is deterministic.
func marshalAttrs(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	b, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	return string(b)
}

// unmarshalAttrs decodes node attribute JSON text into a map; "" gives an empty
// (non-nil) map.
func unmarshalAttrs(s string) (map[string]string, error) {
	if s == "" {
		return map[string]string{}, nil
	}
	out := map[string]string{}
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GraphQuery selects part of the knowledge graph. With Node set it returns that
// node and its one-hop neighborhood; otherwise with Type set it returns all
// nodes of that type and the edges between them; otherwise it returns the whole
// graph. Node takes precedence over Type.
type GraphQuery struct {
	Node string
	Type string
}

// GraphResult is a set of nodes and edges, ordered deterministically (nodes by
// id, edges by src then dst then rel). Both slices are non-nil.
type GraphResult struct {
	Nodes []GraphNode
	Edges []GraphEdge
}

// scanNodeRows reads node rows into a slice.
func scanNodeRows(rows *sql.Rows) ([]GraphNode, error) {
	out := []GraphNode{}
	for rows.Next() {
		var (
			n     GraphNode
			attrs sql.NullString
		)
		if err := rows.Scan(&n.ID, &n.Type, &n.Label, &attrs, &n.CreatedRev, &n.UpdatedRev); err != nil {
			return nil, err
		}
		a, err := unmarshalAttrs(attrs.String)
		if err != nil {
			return nil, err
		}
		n.Attrs = a
		out = append(out, n)
	}
	return out, rows.Err()
}

// scanEdgeRows reads edge rows into a slice.
func scanEdgeRows(rows *sql.Rows) ([]GraphEdge, error) {
	out := []GraphEdge{}
	for rows.Next() {
		var e GraphEdge
		if err := rows.Scan(&e.Src, &e.Dst, &e.Rel, &e.UpdatedRev); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// nodeByID returns one node, or ok=false when absent.
func (s *Store) nodeByID(id string) (GraphNode, bool, error) {
	rows, err := s.db.Query(
		`SELECT id, type, label, attrs, created_rev, updated_rev FROM graph_node WHERE id = ?`, id)
	if err != nil {
		return GraphNode{}, false, err
	}
	defer rows.Close()
	ns, err := scanNodeRows(rows)
	if err != nil {
		return GraphNode{}, false, err
	}
	if len(ns) == 0 {
		return GraphNode{}, false, nil
	}
	return ns[0], true, nil
}

// QueryGraph runs q against the graph tables. Reads are lock-free under WAL.
func (s *Store) QueryGraph(q GraphQuery) (GraphResult, error) {
	res := GraphResult{Nodes: []GraphNode{}, Edges: []GraphEdge{}}
	switch {
	case q.Node != "":
		rows, err := s.db.Query(
			`SELECT src, dst, rel, updated_rev FROM graph_edge WHERE src = ? OR dst = ? ORDER BY src, dst, rel`,
			q.Node, q.Node)
		if err != nil {
			return res, err
		}
		edges, err := scanEdgeRows(rows)
		rows.Close()
		if err != nil {
			return res, err
		}
		res.Edges = edges
		// The neighborhood is q.Node (if it exists) plus every endpoint of its
		// incident edges. Edges are already restricted to those touching q.Node, so
		// each endpoint is q.Node or a direct neighbor.
		idset := map[string]bool{}
		for _, e := range edges {
			idset[e.Src] = true
			idset[e.Dst] = true
		}
		if _, ok, err := s.nodeByID(q.Node); err != nil {
			return res, err
		} else if ok {
			idset[q.Node] = true
		}
		ids := make([]string, 0, len(idset))
		for id := range idset {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			n, ok, err := s.nodeByID(id)
			if err != nil {
				return res, err
			}
			if ok {
				res.Nodes = append(res.Nodes, n)
			}
		}
		return res, nil
	case q.Type != "":
		rows, err := s.db.Query(
			`SELECT id, type, label, attrs, created_rev, updated_rev FROM graph_node WHERE type = ? ORDER BY id`, q.Type)
		if err != nil {
			return res, err
		}
		nodes, err := scanNodeRows(rows)
		rows.Close()
		if err != nil {
			return res, err
		}
		res.Nodes = nodes
		inSet := map[string]bool{}
		for _, n := range nodes {
			inSet[n.ID] = true
		}
		erows, err := s.db.Query(`SELECT src, dst, rel, updated_rev FROM graph_edge ORDER BY src, dst, rel`)
		if err != nil {
			return res, err
		}
		allEdges, err := scanEdgeRows(erows)
		erows.Close()
		if err != nil {
			return res, err
		}
		for _, e := range allEdges {
			if inSet[e.Src] && inSet[e.Dst] {
				res.Edges = append(res.Edges, e)
			}
		}
		return res, nil
	default:
		rows, err := s.db.Query(
			`SELECT id, type, label, attrs, created_rev, updated_rev FROM graph_node ORDER BY id`)
		if err != nil {
			return res, err
		}
		nodes, err := scanNodeRows(rows)
		rows.Close()
		if err != nil {
			return res, err
		}
		res.Nodes = nodes
		erows, err := s.db.Query(`SELECT src, dst, rel, updated_rev FROM graph_edge ORDER BY src, dst, rel`)
		if err != nil {
			return res, err
		}
		edges, err := scanEdgeRows(erows)
		erows.Close()
		if err != nil {
			return res, err
		}
		res.Edges = edges
		return res, nil
	}
}

// firstNonEmpty returns the first non-empty string, or "".
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// PopulateGraph rebuilds the knowledge graph from current store state as an
// idempotent upsert: a task node per task, an asset node per distinct task
// Target and per recon-coverage asset (correlated by value so a target and a
// coverage row for the same value are one node), and an evidence node per stored
// evidence quote. Edges carry the task relationships: targets (task -> asset),
// depends_on and derived_from (task -> task, the latter from basis_ids
// provenance), and evidenced_by (task -> evidence). The task Citation is folded
// into the task node as provenance attributes.
//
// It reads evidence and recon-coverage rows through the store; those reads and
// the snapshot e are separate points, which is acceptable for a derived
// projection (the next populate reconciles any skew). It never calls Apply.
func (s *Store) PopulateGraph(ctx context.Context, e Engagement) error {
	rev := e.Revision
	var nodes []GraphNode
	var edges []GraphEdge

	// Asset attributes accumulate across tasks and recon coverage so each asset
	// value becomes exactly one node with merged attributes.
	assetAttrs := map[string]map[string]string{}
	ensureAsset := func(value string) {
		if value == "" {
			return
		}
		if _, ok := assetAttrs[value]; !ok {
			assetAttrs[value] = map[string]string{}
		}
	}

	for _, t := range e.Tasks {
		attrs := map[string]string{
			"kind":    t.Kind,
			"status":  string(t.Status),
			"phase":   string(t.Phase),
			"surface": string(t.Surface),
		}
		if t.Capability != "" {
			attrs["capability"] = string(t.Capability)
		}
		if t.Armed {
			attrs["armed"] = "true"
		}
		if t.Citation.Source != "" {
			attrs["cite_source"] = t.Citation.Source
		}
		if t.Citation.Path != "" {
			attrs["cite_path"] = t.Citation.Path
		}
		if t.Citation.Section != "" {
			attrs["cite_section"] = t.Citation.Section
		}
		if t.Citation.CWEClass != "" {
			attrs["cwe_class"] = t.Citation.CWEClass
		}
		if t.Citation.Origin != "" {
			attrs["cite_origin"] = t.Citation.Origin
		}
		nodes = append(nodes, GraphNode{
			ID:         "task:" + t.ID,
			Type:       NodeTask,
			Label:      firstNonEmpty(t.Objective, t.Kind, t.ID),
			Attrs:      attrs,
			CreatedRev: t.CreatedRev,
			UpdatedRev: t.UpdatedRev,
		})
		if t.Target != "" {
			ensureAsset(t.Target)
			edges = append(edges, GraphEdge{Src: "task:" + t.ID, Dst: "asset:" + t.Target, Rel: RelTargets, UpdatedRev: rev})
		}
		for _, dep := range t.DependsOn {
			edges = append(edges, GraphEdge{Src: "task:" + t.ID, Dst: "task:" + dep, Rel: RelDependsOn, UpdatedRev: rev})
		}
		for _, b := range t.BasisIDs {
			edges = append(edges, GraphEdge{Src: "task:" + t.ID, Dst: "task:" + b, Rel: RelDerivedFrom, UpdatedRev: rev})
		}
		rows, err := s.EvidenceRowsFor(t.ID)
		if err != nil {
			return err
		}
		for _, r := range rows {
			evID := "evidence:" + strconv.FormatInt(r.ID, 10)
			nodes = append(nodes, GraphNode{
				ID:         evID,
				Type:       NodeEvidence,
				Label:      r.Quote,
				CreatedRev: rev,
				UpdatedRev: rev,
			})
			edges = append(edges, GraphEdge{Src: "task:" + t.ID, Dst: evID, Rel: RelEvidencedBy, UpdatedRev: rev})
		}
	}

	cov, err := s.AllReconCoverage()
	if err != nil {
		return err
	}
	for _, c := range cov {
		ensureAsset(c.Asset)
		a := assetAttrs[c.Asset]
		a["surface"] = string(c.Surface)
		a["iteration_count"] = strconv.Itoa(c.IterationCount)
		covered := 0
		for _, st := range c.Dimensions {
			if st == ReconCovered {
				covered++
			}
		}
		a["covered_dims"] = strconv.Itoa(covered)
	}

	for value, attrs := range assetAttrs {
		nodes = append(nodes, GraphNode{
			ID:         "asset:" + value,
			Type:       NodeAsset,
			Label:      value,
			Attrs:      attrs,
			CreatedRev: rev,
			UpdatedRev: rev,
		})
	}

	return s.UpsertGraph(nodes, edges)
}

// UpsertGraph writes nodes and edges in one transaction. A node update preserves
// created_rev and refreshes type/label/attrs/updated_rev only when the incoming
// updated_rev is at least the stored one; a stale update (lower rev, as can
// arrive from an out-of-order listener) is ignored, so the graph stays monotonic.
// Edges carry no payload beyond their revision, so their update is unconditional.
//
// It takes the store write lock and runs on its own connection, never through
// Apply, so it does not fire the Apply listeners and cannot recurse.
func (s *Store) UpsertGraph(nodes []GraphNode, edges []GraphEdge) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	ctx := context.Background()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()
	for _, n := range nodes {
		if _, err := conn.ExecContext(ctx,
			`INSERT INTO graph_node (id, type, label, attrs, created_rev, updated_rev)
			 VALUES (?, ?, ?, ?, ?, ?)
			 ON CONFLICT(id) DO UPDATE SET
			   type = excluded.type,
			   label = excluded.label,
			   attrs = excluded.attrs,
			   updated_rev = excluded.updated_rev
			 WHERE excluded.updated_rev >= graph_node.updated_rev`,
			n.ID, n.Type, n.Label, marshalAttrs(n.Attrs), n.CreatedRev, n.UpdatedRev); err != nil {
			return err
		}
	}
	for _, e := range edges {
		if _, err := conn.ExecContext(ctx,
			`INSERT INTO graph_edge (src, dst, rel, updated_rev)
			 VALUES (?, ?, ?, ?)
			 ON CONFLICT(src, dst, rel) DO UPDATE SET updated_rev = excluded.updated_rev`,
			e.Src, e.Dst, e.Rel, e.UpdatedRev); err != nil {
			return err
		}
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return err
	}
	committed = true
	return nil
}
