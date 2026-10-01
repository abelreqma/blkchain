package main

import (
	"fmt"
	"strings"

	"blkchain/cli/internal/engagement"
)

// kgview.go is the REPL /kg view: a read-only query of the current engagement's
// knowledge graph (tasks, assets, and evidence as nodes and edges). It is the
// analog of evidenceview.go, reading on demand through the bounded accessor
// EngageGraphQuery (engagegraph.go, the source is registered for the engagement's
// lifetime by runReplEngage). It reuses formatGraphText (the CLI blk kg renderer)
// so /kg, blk kg, and the MCP kg_query print identical text. The rendered text is
// sanitized before display because node labels and attributes are engagement data.

// parseKgArgs turns the /kg argument into a GraphQuery: no arg is the whole graph,
// "node <id>" one node's neighborhood, "type <task|asset|evidence>" a type filter.
func parseKgArgs(arg string) (engagement.GraphQuery, error) {
	fields := strings.Fields(arg)
	switch {
	case len(fields) == 0:
		return engagement.GraphQuery{}, nil
	case fields[0] == "node" && len(fields) == 2:
		return engagement.GraphQuery{Node: fields[1]}, nil
	case fields[0] == "type" && len(fields) == 2:
		t := fields[1]
		if t != engagement.NodeTask && t != engagement.NodeAsset && t != engagement.NodeEvidence {
			return engagement.GraphQuery{}, fmt.Errorf("kg: unknown type %q; use task, asset, or evidence", t)
		}
		return engagement.GraphQuery{Type: t}, nil
	default:
		return engagement.GraphQuery{}, fmt.Errorf("kg: usage: /kg [node <id> | type <task|asset|evidence>]")
	}
}

// kgBlock renders /kg for the current engagement: a header (engagement name and
// revision) then the graph text from formatGraphText. With no engagement active
// it says so; a bad argument or a query error is surfaced. The graph text is
// sanitized because node labels and attributes come from engagement data.
func kgBlock(arg string) string {
	q, err := parseKgArgs(arg)
	if err != nil {
		return styleErr(err)
	}
	v, active, qerr := EngageGraphQuery(q)
	if !active {
		return "   " + Meta.Render("no engagement running - start one with /engage")
	}
	if qerr != nil {
		return styleErr(qerr)
	}
	var b strings.Builder
	if v.Name != "" {
		fmt.Fprintf(&b, "engagement: %s  rev %d\n", vizSanitizeLabel(v.Name), v.Revision)
	} else {
		fmt.Fprintf(&b, "rev %d\n", v.Revision)
	}
	b.WriteString(sanitizeTerminal(formatGraphText(v.Result, q.Node)))
	return strings.TrimRight(b.String(), "\n")
}
