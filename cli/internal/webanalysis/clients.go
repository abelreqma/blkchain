package webanalysis

import (
	sitter "github.com/smacker/go-tree-sitter"
	"strings"
)

func (a *analyzer) importBindings(n *sitter.Node, e *lexical) {
	source := a.eval(field(n, "source"), e, 0).text
	var visit func(*sitter.Node, int)
	visit = func(n *sitter.Node, depth int) {
		if n == nil || depth > 8 {
			return
		}
		switch n.Type() {
		case "import_specifier":
			name := field(n, "alias")
			if name == nil {
				name = field(n, "name")
			}
			e.vars[a.text(name)] = &symbol{v: value{kind: "import"}}
			return
		case "identifier":
			v := value{kind: "import"}
			if source == "axios" {
				v = value{kind: "axios", fields: map[string]value{}}
			}
			e.vars[a.text(n)] = &symbol{v: v}
			return
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			c := n.NamedChild(i)
			if c.Type() != "string" {
				visit(c, depth+1)
			}
		}
	}
	visit(n, 0)
}

func (a *analyzer) interceptor(n *sitter.Node, s *symbol, e *lexical) bool {
	if n == nil || n.Type() != "arrow_function" && n.Type() != "function_expression" {
		return false
	}
	p := field(n, "parameter")
	if p == nil {
		p = child(field(n, "parameters"), 0)
	}
	name := a.text(p)
	if name == "" || p.Type() != "identifier" {
		return false
	}
	body := field(n, "body")
	known := true
	var scan func(*sitter.Node, int)
	scan = func(n *sitter.Node, depth int) {
		if n == nil || depth > 16 {
			known = false
			return
		}
		if n.Type() == "if_statement" || n.Type() == "call_expression" || n.Type() == "for_statement" || n.Type() == "while_statement" || n.Type() == "conditional_expression" {
			known = false
			return
		}
		if n.Type() == "return_statement" && a.text(child(n, 0)) != name {
			known = false
			return
		}
		if n.Type() == "assignment_expression" {
			path := strings.TrimPrefix(a.text(field(n, "left")), name+".")
			if path == a.text(field(n, "left")) {
				known = false
				return
			}
			v := a.eval(field(n, "right"), e, 0)
			if !v.known {
				known = false
				return
			}
			switch {
			case path == "baseURL":
				s.v.fields[path] = v
			case path == "headers":
				s.v.fields[path] = v
			case strings.HasPrefix(path, "headers."):
				h := s.v.fields["headers"]
				if h.fields == nil {
					h = value{kind: "object", known: true, fields: map[string]value{}}
				}
				h.fields[strings.TrimPrefix(path, "headers.")] = v
				s.v.fields["headers"] = h
			default:
				known = false
			}
			return
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			scan(n.NamedChild(i), depth+1)
		}
	}
	scan(body, 0)
	return known
}

func (a *analyzer) viteChunks(n *sitter.Node, e *lexical) {
	var visit func(*sitter.Node, int)
	visit = func(n *sitter.Node, depth int) {
		if n == nil || depth > 24 {
			return
		}
		if n.Type() == "array" {
			v := a.eval(n, e, 0)
			for i, item := range v.items {
				if i >= 200 {
					a.gap("Vite chunk table limit")
					break
				}
				if item.known && strings.HasSuffix(item.text, ".js") {
					a.out.Dependencies = append(a.out.Dependencies, Dependency{URL: item.text, Kind: "vite-chunk", Location: a.loc(n)})
				}
			}
			return
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			visit(n.NamedChild(i), depth+1)
		}
	}
	visit(n, 0)
}
