package webanalysis

import (
	"errors"
	sitter "github.com/smacker/go-tree-sitter"
)

func (e *lexical) variableScope() *lexical {
	for e.parent != nil && !e.functionScope {
		e = e.parent
	}
	return e
}
func (a *analyzer) bindPattern(n *sitter.Node, e *lexical, depth int) {
	if n == nil || depth > 128 {
		return
	}
	switch n.Type() {
	case "identifier", "shorthand_property_identifier_pattern":
		name := a.text(n)
		if _, exists := e.vars[name]; !exists {
			e.vars[name] = &symbol{}
		}
	case "pair_pattern":
		a.bindPattern(field(n, "value"), e, depth+1)
	case "assignment_pattern", "object_assignment_pattern":
		a.bindPattern(field(n, "left"), e, depth+1)
	case "required_parameter", "optional_parameter":
		a.bindPattern(field(n, "pattern"), e, depth+1)
	case "object_pattern", "array_pattern", "rest_pattern":
		for i := 0; i < int(n.NamedChildCount()); i++ {
			a.bindPattern(n.NamedChild(i), e, depth+1)
		}
	}
}
func (a *analyzer) hoistVariables(n *sitter.Node, e *lexical, depth int) error {
	if n == nil {
		return nil
	}
	a.nodes++
	if a.nodes > 100000 || depth > 128 {
		return errors.New("AST traversal limit")
	}
	if a.nodes%128 == 0 && a.ctx.Err() != nil {
		return a.ctx.Err()
	}
	switch n.Type() {
	case "function_declaration", "method_definition", "function_expression", "function", "arrow_function", "generator_function", "generator_function_declaration", "class_declaration", "class":
		return nil
	case "variable_declaration":
		for i := 0; i < int(n.NamedChildCount()); i++ {
			a.bindPattern(field(n.NamedChild(i), "name"), e, 0)
		}
	case "for_in_statement":
		if declarationKind(n) == "var" {
			a.bindPattern(field(n, "left"), e, 0)
		}
	}
	for i := 0; i < int(n.NamedChildCount()); i++ {
		if err := a.hoistVariables(n.NamedChild(i), e, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func declarationKind(n *sitter.Node) string {
	if kind := field(n, "kind"); kind != nil {
		return kind.Type()
	}
	for i := 0; i < int(n.ChildCount()); i++ {
		kind := n.Child(i).Type()
		if kind == "var" || kind == "let" || kind == "const" {
			return kind
		}
	}
	return ""
}
