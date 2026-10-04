package webanalysis

import (
	"fmt"
	sitter "github.com/smacker/go-tree-sitter"
	"strconv"
	"strings"
)

func (a *analyzer) bindParameter(p *sitter.Node, inner, e *lexical, index int) []Parameter {
	if p == nil {
		return nil
	}
	def := ""
	if p.Type() == "required_parameter" || p.Type() == "optional_parameter" {
		if v := field(p, "value"); v != nil {
			def = a.eval(v, e, 0).text
		}
		p = field(p, "pattern")
		if p == nil {
			return nil
		}
	}
	if p.Type() == "assignment_pattern" {
		def = a.eval(field(p, "right"), e, 0).text
		p = field(p, "left")
	}
	base := fmt.Sprintf("argument.%d", index)
	if p.Type() == "object_pattern" {
		out := []Parameter{}
		for i := 0; i < int(p.NamedChildCount()); i++ {
			c := p.NamedChild(i)
			key, alias := a.text(c), a.text(c)
			d := ""
			if c.Type() == "pair_pattern" {
				key = a.text(field(c, "key"))
				v := field(c, "value")
				alias = a.text(v)
				if v != nil && v.Type() == "assignment_pattern" {
					alias = a.text(field(v, "left"))
					d = a.eval(field(v, "right"), e, 0).text
				}
			}
			if c.Type() == "object_assignment_pattern" {
				key = a.text(field(c, "left"))
				alias = key
				d = a.eval(field(c, "right"), e, 0).text
			}
			if c.Type() == "rest_pattern" {
				a.gap("unresolved destructured rest parameter")
				continue
			}
			inner.vars[alias] = &symbol{v: value{text: "{" + alias + "}", kind: "parameter"}}
			out = append(out, Parameter{Name: alias, Field: base + "." + key, Expression: alias, Default: d, Unresolved: true})
		}
		return out
	}
	name := a.text(p)
	inner.vars[name] = &symbol{v: value{text: "{" + name + "}", kind: "parameter"}}
	return []Parameter{{Name: name, Field: base, Expression: name, Default: def, Unresolved: true}}
}
func argumentFor(p Parameter, args *sitter.Node, a *analyzer, e *lexical, fallback int) value {
	index := fallback
	binding := ""
	parts := strings.SplitN(p.Field, ".", 3)
	if len(parts) >= 2 && parts[0] == "argument" {
		if n, err := strconv.Atoi(parts[1]); err == nil {
			index = n
		}
		if len(parts) == 3 {
			binding = parts[2]
		}
	}
	v := a.eval(child(args, index), e, 0)
	if binding != "" {
		v = v.fields[binding]
	}
	if v.text == "" && p.Default != "" {
		v = value{text: p.Default, known: true, kind: "default"}
	}
	return v
}
