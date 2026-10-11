package webanalysis

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

const astSource = `const base = "/api/v2";
async function load(id) {
  const r = await fetch(base + "/items/" + id, {method: "GET"});
  return r.json();
}
`

func analyzeWithAST(t *testing.T, source string, language string) Result {
	t.Helper()
	out, err := analyzeAST(t, source, language)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// analyzeAST returns the result and any error, for the cases where the analyzer's own traversal limit stops the walk after the tree is serialized.
func analyzeAST(t *testing.T, source string, language string) (Result, error) {
	t.Helper()
	out, err := Analyze(context.Background(), Input{
		Unit: SourceUnit{
			ID: "u1", Language: language, Hash: Hash([]byte(source)),
			URL: "https://example.com/app.js", Kind: "script",
		},
		Source:  []byte(source),
		KeepAST: true,
	})
	if out.AST == nil {
		t.Fatalf("no syntax tree was serialized (analysis error: %v)", err)
	}
	return out, err
}

func TestAnalyzeKeepsTheSyntaxTreeItRanOn(t *testing.T) {
	out := analyzeWithAST(t, astSource, "javascript")
	tree := out.AST
	if tree.Unit != "u1" || tree.Language != "javascript" {
		t.Errorf("tree does not name its unit: %+v", tree)
	}
	if tree.Hash != Hash([]byte(astSource)) {
		t.Errorf("tree hash %q does not match the source it was parsed from", tree.Hash)
	}
	root, ok := tree.Root()
	if !ok {
		t.Fatal("the tree has no root")
	}
	if root.Type != "program" {
		t.Errorf("root type = %q, want program", root.Type)
	}
	if root.Parent != -1 {
		t.Errorf("root parent = %d, want -1", root.Parent)
	}
	if tree.Truncated {
		t.Errorf("a small unit was truncated: %q", tree.Gap)
	}
	// The tree holds the constructs the analysis read.
	counts := tree.NodeCounts()
	for _, want := range []string{"function_declaration", "call_expression", "string", "identifier"} {
		if counts[want] == 0 {
			t.Errorf("no %s node in the tree: %v", want, tree.NodeTypes())
		}
	}
}

func TestASTIsAWellFormedTree(t *testing.T) {
	tree := analyzeWithAST(t, astSource, "javascript").AST
	if len(tree.Nodes) < 10 {
		t.Fatalf("the tree holds %d nodes, want the whole unit", len(tree.Nodes))
	}
	seenAsChild := map[int]bool{}
	for i, n := range tree.Nodes {
		if n.Parent < -1 || n.Parent >= len(tree.Nodes) {
			t.Errorf("node %d has parent %d, outside the node list", i, n.Parent)
		}
		if i > 0 && n.Parent < 0 {
			t.Errorf("node %d has no parent but is not the root", i)
		}
		for _, c := range n.Children {
			if c <= i || c >= len(tree.Nodes) {
				t.Errorf("node %d names child %d, which is not a later node", i, c)
				continue
			}
			if tree.Nodes[c].Parent != i {
				t.Errorf("node %d names child %d, whose parent is %d", i, c, tree.Nodes[c].Parent)
			}
			if seenAsChild[c] {
				t.Errorf("node %d is a child of two parents", c)
			}
			seenAsChild[c] = true
		}
		if n.EndByte < n.StartByte {
			t.Errorf("node %d spans backwards: %d to %d", i, n.StartByte, n.EndByte)
		}
		if n.EndByte > len(astSource) {
			t.Errorf("node %d ends at %d, past the source", i, n.EndByte)
		}
		// Text is carried by a node whose children are all punctuation, so the tree does not hold any source twice.
		if n.Text != "" {
			for _, c := range n.Children {
				if tree.Nodes[c].Named {
					t.Errorf("node %d has a named child and text %q", i, n.Text)
					break
				}
			}
		}
		if len(n.Text) > MaxASTText {
			t.Errorf("node %d text is %d bytes, past the bound", i, len(n.Text))
		}
	}
	// Every node but the root is some parent's child.
	for i := 1; i < len(tree.Nodes); i++ {
		if !seenAsChild[i] {
			t.Errorf("node %d is not in any parent's child list", i)
		}
	}
}

func TestASTChildrenAreInSourceOrder(t *testing.T) {
	tree := analyzeWithAST(t, astSource, "javascript").AST
	for i, n := range tree.Nodes {
		for k := 1; k < len(n.Children); k++ {
			prev := tree.Nodes[n.Children[k-1]]
			cur := tree.Nodes[n.Children[k]]
			if cur.StartByte < prev.StartByte {
				t.Errorf("node %d children are out of source order: %d then %d",
					i, prev.StartByte, cur.StartByte)
			}
		}
	}
}

func TestASTRecordsFieldNames(t *testing.T) {
	tree := analyzeWithAST(t, astSource, "javascript").AST
	// A function declaration names its own parts, which is what makes a tree query able to ask for the name rather than the first identifier.
	for _, i := range tree.Find("function_declaration") {
		fields := map[string]string{}
		for _, c := range tree.Nodes[i].Children {
			if f := tree.Nodes[c].Field; f != "" {
				fields[f] = tree.Nodes[c].Type
			}
		}
		if fields["name"] != "identifier" {
			t.Errorf("function declaration has no name field: %v", fields)
		}
		if fields["body"] != "statement_block" {
			t.Errorf("function declaration has no body field: %v", fields)
		}
		if fields["parameters"] == "" {
			t.Errorf("function declaration has no parameters field: %v", fields)
		}
	}
}

// A leaf over the text bound keeps the bounded prefix, so one long literal cannot carry the whole source into the tree.
func TestASTLeafTextIsBounded(t *testing.T) {
	long := strings.Repeat("x", MaxASTText*3)
	source := `const s = "` + long + `";`
	tree := analyzeWithAST(t, source, "javascript").AST
	found := false
	for _, n := range tree.Nodes {
		if n.Text == "" || n.EndByte-n.StartByte <= MaxASTText {
			continue
		}
		found = true
		if len(n.Text) != MaxASTText {
			t.Errorf("a %d-byte node kept %d bytes of text, want the bound %d",
				n.EndByte-n.StartByte, len(n.Text), MaxASTText)
		}
		if !strings.HasPrefix(source[n.StartByte:], n.Text) {
			t.Errorf("the kept text is not the node's prefix: %.40q", n.Text)
		}
	}
	if !found {
		t.Fatalf("no node past the text bound carried text: %v", tree.NodeTypes())
	}
	// The literal's content is in the tree, which is what makes the tree usable without the source.
	joined := ""
	for _, n := range tree.Nodes {
		joined += n.Text
	}
	if !strings.Contains(joined, strings.Repeat("x", MaxASTText-1)) {
		t.Error("the literal's content is absent from every node's text")
	}
	_ = long
}

func TestASTLeafTextIsTheSource(t *testing.T) {
	tree := analyzeWithAST(t, astSource, "javascript").AST
	checked := 0
	for _, n := range tree.Nodes {
		if len(n.Children) > 0 || n.Text == "" {
			continue
		}
		if n.EndByte-n.StartByte > MaxASTText {
			continue
		}
		want := astSource[n.StartByte:n.EndByte]
		if n.Text != SafeText(want) {
			t.Errorf("leaf text %q does not match the source %q", n.Text, want)
		}
		checked++
	}
	if checked == 0 {
		t.Error("no leaf carried text")
	}
}

func TestASTPathNamesTheAncestry(t *testing.T) {
	tree := analyzeWithAST(t, astSource, "javascript").AST
	calls := tree.Find("call_expression")
	if len(calls) == 0 {
		t.Fatal("no call expression in the tree")
	}
	path := tree.Path(calls[0])
	if len(path) < 2 {
		t.Fatalf("path = %v, want the ancestry from the root", path)
	}
	if path[0] != "program" {
		t.Errorf("path starts at %q, want program", path[0])
	}
	if path[len(path)-1] != "call_expression" {
		t.Errorf("path ends at %q, want the node itself", path[len(path)-1])
	}
	if tree.Path(-1) != nil || tree.Path(len(tree.Nodes)) != nil {
		t.Error("an out-of-range index returned a path")
	}
}

func TestASTIsAbsentUnlessAsked(t *testing.T) {
	out, err := Analyze(context.Background(), Input{
		Unit:   SourceUnit{ID: "u1", Language: "javascript"},
		Source: []byte(astSource),
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.AST != nil {
		t.Error("a syntax tree was serialized without KeepAST")
	}
}

func TestASTRecordsParserErrors(t *testing.T) {
	out := analyzeWithAST(t, "function broken( { const x = ;", "javascript")
	tree := out.AST
	errors := 0
	for _, n := range tree.Nodes {
		if n.Error || n.Missing {
			errors++
		}
	}
	if errors == 0 {
		t.Errorf("unparsable source produced no error or missing node: %v", tree.NodeTypes())
	}
	// The unit itself records the partial parse, so a reader of the tree knows not to treat it as complete coverage.
	if out.Units[0].Parse != "partial" {
		t.Errorf("unit parse = %q, want partial", out.Units[0].Parse)
	}
}

// A tree past the node bound is recorded truncated with the reason, so a shortened tree is never read as a complete one.
func TestASTTruncationIsRecorded(t *testing.T) {
	var b strings.Builder
	b.WriteString("const xs = [")
	for i := 0; i < MaxASTNodes; i++ {
		b.WriteString("1,")
	}
	b.WriteString("];")
	// The analyzer's own traversal limit also stops the walk here; the tree is serialized first, so the truncation it records is what is checked.
	out, _ := analyzeAST(t, b.String(), "javascript")
	tree := out.AST
	if !tree.Truncated {
		t.Fatalf("a tree of %d nodes was not truncated", len(tree.Nodes))
	}
	if len(tree.Nodes) > MaxASTNodes {
		t.Errorf("the tree holds %d nodes, past the bound of %d", len(tree.Nodes), MaxASTNodes)
	}
	if !strings.Contains(tree.Gap, "node bound") {
		t.Errorf("Gap = %q, want the node bound named", tree.Gap)
	}
	// The truncation is also a gap on the result, so a report carries it.
	found := false
	for _, g := range out.Gaps {
		if strings.Contains(g.Reason, "node bound") {
			found = true
		}
	}
	if !found {
		t.Errorf("the truncation is not among the result's gaps: %+v", out.Gaps)
	}
}

func TestASTDepthBoundIsRecorded(t *testing.T) {
	// Nested parentheses add one tree level each, so this exceeds the depth bound well before the node bound.
	depth := MaxASTDepth + 50
	source := "const x = " + strings.Repeat("(", depth) + "1" + strings.Repeat(")", depth) + ";"
	out, _ := analyzeAST(t, source, "javascript")
	tree := out.AST
	if !tree.Truncated {
		t.Fatal("a tree past the depth bound was not truncated")
	}
	if !strings.Contains(tree.Gap, "depth bound") {
		t.Errorf("Gap = %q, want the depth bound named", tree.Gap)
	}
}

func TestASTRoundTripsThroughJSON(t *testing.T) {
	tree := analyzeWithAST(t, astSource, "javascript").AST
	raw, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	var back AST
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.Nodes) != len(tree.Nodes) {
		t.Fatalf("round trip changed the node count from %d to %d", len(tree.Nodes), len(back.Nodes))
	}
	for i := range tree.Nodes {
		a, b := tree.Nodes[i], back.Nodes[i]
		if a.Type != b.Type || a.Parent != b.Parent || a.StartByte != b.StartByte || a.Field != b.Field {
			t.Fatalf("node %d changed: %+v then %+v", i, a, b)
		}
	}
	if root, _ := back.Root(); root.Type != "program" {
		t.Errorf("the decoded root is %q", root.Type)
	}
}

func TestASTHandlesEveryLanguageTheAnalyzerParses(t *testing.T) {
	for _, tc := range []struct{ language, source string }{
		{"javascript", "const a = fetch('/x');"},
		{"typescript", "const a: string = await fetch('/x').then(r => r.text());"},
		{"tsx", "const A = () => <div onClick={() => fetch('/x')}>hi</div>;"},
		{"jsx", "const A = () => <div>hi</div>;"},
	} {
		out, err := Analyze(context.Background(), Input{
			Unit:    SourceUnit{ID: "u1", Language: tc.language, Hash: Hash([]byte(tc.source))},
			Source:  []byte(tc.source),
			KeepAST: true,
		})
		if err != nil {
			t.Errorf("%s: %v", tc.language, err)
			continue
		}
		if out.AST == nil || len(out.AST.Nodes) == 0 {
			t.Errorf("%s: no tree serialized", tc.language)
			continue
		}
		if out.AST.Language != tc.language {
			t.Errorf("%s: tree names language %q", tc.language, out.AST.Language)
		}
		if root, _ := out.AST.Root(); root.Type != "program" {
			t.Errorf("%s: root is %q", tc.language, root.Type)
		}
	}
}

func TestSerializeASTRejectsNoTree(t *testing.T) {
	if _, err := SerializeAST(SourceUnit{ID: "u1"}, nil, nil); err == nil {
		t.Error("a nil root was accepted")
	}
}

func TestASTFindAndCounts(t *testing.T) {
	tree := analyzeWithAST(t, astSource, "javascript").AST
	counts := tree.NodeCounts()
	for _, nodeType := range tree.NodeTypes() {
		found := tree.Find(nodeType)
		if len(found) != counts[nodeType] {
			t.Errorf("Find(%q) returned %d, NodeCounts says %d", nodeType, len(found), counts[nodeType])
		}
		for k := 1; k < len(found); k++ {
			if found[k] <= found[k-1] {
				t.Errorf("Find(%q) is not in order: %v", nodeType, found)
				break
			}
		}
	}
	if len(tree.Find("no_such_node")) != 0 {
		t.Error("Find returned nodes for an absent type")
	}
	var empty AST
	if _, ok := empty.Root(); ok {
		t.Error("an empty tree reported a root")
	}
	if len(empty.NodeTypes()) != 0 || len(empty.Find("program")) != 0 {
		t.Error("an empty tree reported nodes")
	}
}
