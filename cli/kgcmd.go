package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"blkchain/cli/internal/engagement"
)

// kgcmd.go implements `blk kg`, the read-only engagement knowledge-graph query.
// The graph is a pure projection of the engagement store, so this command opens
// the workspace, refreshes the graph from current store state (idempotent), then
// queries it. engageGraph is the shared accessor the MCP kg_query tool and the
// REPL /kg path reuse, so all three surfaces return the identical GraphResult.

// kgView is a graph query result plus the engagement name and revision it was
// read at, for a header line and JSON output.
type kgView struct {
	Name     string                 `json:"name"`
	Revision int64                  `json:"revision"`
	Nodes    []engagement.GraphNode `json:"nodes"`
	Edges    []engagement.GraphEdge `json:"edges"`
	Result   engagement.GraphResult `json:"-"`
}

// engageGraph opens the engagement workspace at wsDir and runs q against its
// knowledge graph (refreshed from current store state). The CLI and MCP surfaces
// use it; it delegates to engageGraphOnStore, which the REPL source also uses on
// the already-open live store.
func engageGraph(wsDir string, q engagement.GraphQuery) (kgView, error) {
	ws, err := engagement.OpenWorkspace(wsDir)
	if err != nil {
		return kgView{}, fmt.Errorf("kg: cannot open workspace %s: %w", wsDir, err)
	}
	defer ws.Close()
	return engageGraphOnStore(ws.Store, q)
}

// typeTag is the short, fixed-width node-type label for the text view.
func typeTag(t string) string {
	switch t {
	case engagement.NodeEvidence:
		return "evid "
	case engagement.NodeAsset:
		return "asset"
	case engagement.NodeTask:
		return "task "
	default:
		return t
	}
}

// graphNodeSummary renders a node's salient attributes for the text view.
func graphNodeSummary(n engagement.GraphNode) string {
	switch n.Type {
	case engagement.NodeTask:
		kind := n.Attrs["kind"]
		status := n.Attrs["status"]
		s := kind + "/" + status
		if n.Label != "" {
			s += " \"" + n.Label + "\""
		}
		if n.Attrs["armed"] == "true" {
			s += " armed"
		}
		return s
	case engagement.NodeAsset:
		parts := []string{}
		if sf := n.Attrs["surface"]; sf != "" {
			parts = append(parts, sf)
		}
		if cd := n.Attrs["covered_dims"]; cd != "" {
			parts = append(parts, "covered_dims="+cd)
		}
		return strings.Join(parts, " ")
	default:
		if n.Label != "" {
			return "\"" + n.Label + "\""
		}
		return ""
	}
}

// formatGraphText renders a GraphResult as plain text. With focus set it renders
// that node and its incident edges (-> outgoing, <- incoming); otherwise it lists
// every node then every edge.
func formatGraphText(res engagement.GraphResult, focus string) string {
	var b strings.Builder
	if focus != "" {
		for _, n := range res.Nodes {
			if n.ID == focus {
				sum := graphNodeSummary(n)
				if sum != "" {
					fmt.Fprintf(&b, "%s  (%s)\n", n.ID, sum)
				} else {
					fmt.Fprintf(&b, "%s\n", n.ID)
				}
			}
		}
		for _, e := range res.Edges {
			switch {
			case e.Src == focus:
				fmt.Fprintf(&b, "  -> %s  %s\n", e.Dst, e.Rel)
			case e.Dst == focus:
				fmt.Fprintf(&b, "  <- %s  %s\n", e.Src, e.Rel)
			}
		}
		return b.String()
	}
	fmt.Fprintf(&b, "nodes %d  edges %d\n\nnodes\n", len(res.Nodes), len(res.Edges))
	for _, n := range res.Nodes {
		sum := graphNodeSummary(n)
		if sum != "" {
			fmt.Fprintf(&b, "  %s  %s  %s\n", typeTag(n.Type), n.ID, sum)
		} else {
			fmt.Fprintf(&b, "  %s  %s\n", typeTag(n.Type), n.ID)
		}
	}
	fmt.Fprintf(&b, "edges\n")
	for _, e := range res.Edges {
		fmt.Fprintf(&b, "  %s  %s  %s\n", e.Src, e.Rel, e.Dst)
	}
	return b.String()
}

// kgOpts holds the `blk kg` flags, shared between runKg and the help registry
// (commandSpecs) so the two never drift.
type kgOpts struct {
	workspace string
	node      string
	typ       string
	asJSON    bool
}

// defineKgFlags registers the `blk kg` flags on fs. The help renderer and runKg
// both call it.
func defineKgFlags(fs *flag.FlagSet, o *kgOpts) {
	fs.StringVar(&o.workspace, "workspace", "", "engagement workspace directory (default: the most recent engagement)")
	fs.StringVar(&o.node, "node", "", "query one node's neighborhood by id (e.g. asset:10.0.0.1)")
	fs.StringVar(&o.typ, "type", "", "filter to one node type: task, asset, or evidence")
	fs.BoolVar(&o.asJSON, "json", false, "emit JSON")
}

// runKg implements `blk kg [--workspace <dir>] [--node <id>] [--type <t>] [--json]`.
// With no --workspace it reads the most recent engagement. --node queries one
// node's neighborhood; --type filters to one node type; neither gives the whole
// graph.
func runKg(args []string) error {
	fs := newFlagSet("kg")
	var o kgOpts
	defineKgFlags(fs, &o)
	if err := parseFlags(fs, reorder(args, map[string]bool{"workspace": true, "node": true, "type": true})); err != nil {
		return err
	}
	wsDir := o.workspace
	if wsDir == "" {
		latest, err := latestEngagementDir()
		if err != nil {
			return fmt.Errorf("kg: %w", err)
		}
		wsDir = latest
	}
	v, err := engageGraph(wsDir, engagement.GraphQuery{Node: o.node, Type: o.typ})
	if err != nil {
		return err
	}
	if o.asJSON {
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("kg: marshal: %w", err)
		}
		fmt.Fprintln(os.Stdout, string(b))
		return nil
	}
	if v.Name != "" {
		fmt.Fprintf(os.Stdout, "engagement: %s  rev %d\n", v.Name, v.Revision)
	} else {
		fmt.Fprintf(os.Stdout, "rev %d\n", v.Revision)
	}
	fmt.Fprint(os.Stdout, formatGraphText(v.Result, o.node))
	return nil
}
