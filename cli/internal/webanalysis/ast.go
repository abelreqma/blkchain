package webanalysis

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// ast.go serializes one unit's syntax tree so a later query reads the tree the analysis ran on, bounded by node count and depth.

// MaxASTNodes bounds one serialized tree, low enough that a result carrying one fits the analysis worker's output limit.
const MaxASTNodes = 60000

// MaxASTDepth bounds how deep a serialized tree goes.
const MaxASTDepth = 512

// MaxASTText bounds the source text kept on a leaf.
const MaxASTText = 256

// MaxASTBytes bounds a tree before compression and after decompression.
const MaxASTBytes = 32 << 20

// ASTNode is one node of a serialized tree; children are indices into the flat node list.
type ASTNode struct {
	// Type is the grammar's name for the node.
	Type string `json:"type"`
	// Field is the parent's field name for this child, when it has one.
	Field string `json:"field,omitempty"`
	// Named distinguishes a grammar rule from an anonymous token.
	Named bool `json:"named"`
	// Error marks a node the parser produced from unparsable input.
	Error bool `json:"error,omitempty"`
	// Missing marks a node the parser inserted to recover.
	Missing bool `json:"missing,omitempty"`
	// StartByte and EndByte locate the node in the unit's source.
	StartByte int `json:"start_byte"`
	EndByte   int `json:"end_byte"`
	// StartRow and StartColumn are the node's zero-based position.
	StartRow    int `json:"start_row"`
	StartColumn int `json:"start_column"`
	EndRow      int `json:"end_row"`
	EndColumn   int `json:"end_column"`
	// Text is the source the node covers, kept only for a leaf and bounded.
	Text string `json:"text,omitempty"`
	// Parent is the index of this node's parent, or -1 for the root.
	Parent int `json:"parent"`
	// Children are the indices of this node's children, in source order.
	Children []int `json:"children,omitempty"`
}

// AST is the serialized syntax tree of one source unit.
type AST struct {
	Unit     string    `json:"unit"`
	Language string    `json:"language"`
	Hash     string    `json:"sha256"`
	Nodes    []ASTNode `json:"nodes"`
	RawBytes int       `json:"-"`
	// Truncated reports that the tree is incomplete, and Gap says why.
	Truncated bool   `json:"truncated,omitempty"`
	Gap       string `json:"gap,omitempty"`
}

// Root returns the tree's root node, and false for an empty tree.
func (t AST) Root() (ASTNode, bool) {
	if len(t.Nodes) == 0 {
		return ASTNode{}, false
	}
	return t.Nodes[0], true
}

// NodeCounts returns how many nodes of each type the tree holds.
func (t AST) NodeCounts() map[string]int {
	out := map[string]int{}
	for _, n := range t.Nodes {
		out[n.Type]++
	}
	return out
}

// NodeTypes returns the distinct node types in the tree, sorted.
func (t AST) NodeTypes() []string {
	counts := t.NodeCounts()
	out := make([]string, 0, len(counts))
	for k := range counts {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Find returns the indices of every node of the given type, in source order.
func (t AST) Find(nodeType string) []int {
	var out []int
	for i, n := range t.Nodes {
		if n.Type == nodeType {
			out = append(out, i)
		}
	}
	return out
}

// Path returns the node types from the root down to i.
func (t AST) Path(i int) []string {
	if i < 0 || i >= len(t.Nodes) {
		return nil
	}
	var reversed []string
	for at := i; at >= 0 && at < len(t.Nodes); {
		reversed = append(reversed, t.Nodes[at].Type)
		parent := t.Nodes[at].Parent
		if parent == at || parent < 0 {
			break
		}
		at = parent
	}
	for l, r := 0, len(reversed)-1; l < r; l, r = l+1, r-1 {
		reversed[l], reversed[r] = reversed[r], reversed[l]
	}
	return reversed
}

// SerializeAST walks the parsed tree into a flat node list, stopping at the node and depth bounds.
func SerializeAST(unit SourceUnit, source []byte, root *sitter.Node) (AST, error) {
	if root == nil {
		return AST{}, errors.New("no syntax tree to serialize")
	}
	out := AST{Unit: unit.ID, Language: unit.Language, Hash: unit.Hash}
	type frame struct {
		node   *sitter.Node
		field  string
		parent int
		depth  int
	}
	stack := []frame{{node: root, field: "", parent: -1, depth: 0}}
	for len(stack) > 0 {
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if len(out.Nodes) >= MaxASTNodes {
			out.Truncated = true
			out.Gap = "tree exceeds the node bound; the rest of it was not serialized"
			break
		}
		if f.depth > MaxASTDepth {
			out.Truncated = true
			out.Gap = "tree exceeds the depth bound; the deeper nodes were not serialized"
			continue
		}
		index := len(out.Nodes)
		n := ASTNode{
			Type:        f.node.Type(),
			Field:       f.field,
			Named:       f.node.IsNamed(),
			Error:       f.node.IsError(),
			Missing:     f.node.IsMissing(),
			StartByte:   int(f.node.StartByte()),
			EndByte:     int(f.node.EndByte()),
			StartRow:    int(f.node.StartPoint().Row),
			StartColumn: int(f.node.StartPoint().Column),
			EndRow:      int(f.node.EndPoint().Row),
			EndColumn:   int(f.node.EndPoint().Column),
			Parent:      f.parent,
		}
		count := int(f.node.ChildCount())
		// A node whose children are all punctuation holds its own content, as a string literal does, so it carries text the way a leaf does.
		if count == 0 || !hasNamedChild(f.node, count) {
			n.Text = astText(source, n.StartByte, n.EndByte)
		}
		out.Nodes = append(out.Nodes, n)
		if f.parent >= 0 {
			out.Nodes[f.parent].Children = append(out.Nodes[f.parent].Children, index)
		}
		// Children are pushed in reverse so they are visited, and indexed, in source order.
		for i := count - 1; i >= 0; i-- {
			child := f.node.Child(i)
			if child == nil {
				continue
			}
			stack = append(stack, frame{
				node:   child,
				field:  f.node.FieldNameForChild(i),
				parent: index,
				depth:  f.depth + 1,
			})
		}
	}
	return out, nil
}

// hasNamedChild reports whether any of n's children is a grammar rule rather than a punctuation token.
func hasNamedChild(n *sitter.Node, count int) bool {
	for i := 0; i < count; i++ {
		if c := n.Child(i); c != nil && c.IsNamed() {
			return true
		}
	}
	return false
}

// astText returns the bounded source a leaf covers, with control characters replaced.
func astText(source []byte, start, end int) string {
	if start < 0 || end > len(source) || start >= end {
		return ""
	}
	if end-start > MaxASTText {
		end = start + MaxASTText
	}
	return SafeText(strings.ToValidUTF8(string(source[start:end]), ""))
}

// ASTArtifactKind is the artifact kind under which a serialized tree is stored.
const ASTArtifactKind = "syntax-tree"

// MarshalAST renders a tree as the gzipped JSON an artifact body holds.
func MarshalAST(t AST) ([]byte, error) {
	raw, err := json.Marshal(t)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxASTBytes {
		return nil, errors.New("serialized syntax tree exceeds the size limit")
	}
	out, err := gzipBytes(raw)
	if err != nil {
		return nil, err
	}
	if len(out) > MaxSource {
		return nil, errors.New("serialized syntax tree exceeds the artifact body limit")
	}
	return out, nil
}

// UnmarshalAST reads a tree from an artifact body.
func UnmarshalAST(body []byte) (AST, error) {
	raw, err := gunzipBounded(body, MaxASTBytes)
	if err != nil {
		return AST{}, err
	}
	var out AST
	if err := json.Unmarshal(raw, &out); err != nil {
		return AST{}, err
	}
	out.RawBytes = len(raw)
	return out, nil
}
