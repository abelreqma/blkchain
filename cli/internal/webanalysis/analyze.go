package webanalysis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BishopFox/jsluice"
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/javascript"
	"github.com/smacker/go-tree-sitter/typescript/tsx"
	"github.com/smacker/go-tree-sitter/typescript/typescript"
)

type Input struct {
	Unit       SourceUnit `json:"unit"`
	Source     []byte     `json:"source"`
	Role       string     `json:"role"`
	Historical bool       `json:"historical"`
}
type value struct {
	text   string
	known  bool
	fields map[string]value
	items  []value
	kind   string
	params []string
}
type symbol struct {
	v         value
	fn        *Function
	templates []Operation
}
type lexical struct {
	parent        *lexical
	vars          map[string]*symbol
	function      string
	conditions    []string
	functionScope bool
}

func (e *lexical) get(name string) *symbol {
	for e != nil {
		if v, ok := e.vars[name]; ok {
			return v
		}
		e = e.parent
	}
	return nil
}
func (e *lexical) child() *lexical {
	return &lexical{parent: e, vars: map[string]*symbol{}, function: e.function, conditions: append([]string(nil), e.conditions...)}
}

type analyzer struct {
	ctx         context.Context
	in          Input
	out         Result
	nodes       int
	operations  map[string]Operation
	publicPaths map[string]string
}

func Analyze(ctx context.Context, in Input) (Result, error) {
	if len(in.Source) > MaxSource {
		return Result{}, errors.New("source exceeds analysis limit")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	p := sitter.NewParser()
	defer p.Close()
	lang := javascript.GetLanguage()
	if in.Unit.Language == "typescript" {
		lang = typescript.GetLanguage()
	}
	if in.Unit.Language == "tsx" || in.Unit.Language == "jsx" {
		lang = tsx.GetLanguage()
	}
	p.SetLanguage(lang)
	tree, err := p.ParseCtx(ctx, nil, in.Source)
	if err != nil {
		return Result{}, err
	}
	defer tree.Close()
	in.Unit.Parse = "ok"
	if tree.RootNode().HasError() {
		in.Unit.Parse = "partial"
	}
	a := analyzer{ctx: ctx, in: in, operations: map[string]Operation{}, publicPaths: map[string]string{}}
	a.out.Units = []SourceUnit{in.Unit}
	a.out.Findings = Technology(in.Unit, in.Source, nil)
	if in.Unit.Parse == "partial" {
		a.gap("parser errors; partial syntax coverage")
	}
	env := &lexical{vars: map[string]*symbol{}, functionScope: true}
	if err = a.hoistVariables(tree.RootNode(), env, 0); err != nil {
		return a.out, err
	}
	if err = a.walk(tree.RootNode(), env, 0); err != nil {
		return a.out, err
	}
	keys := make([]string, 0, len(a.operations))
	for k := range a.operations {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		a.out.Operations = append(a.out.Operations, a.operations[k])
	}
	if in.Unit.Language == "javascript" || in.Unit.Language == "" {
		baseline := jsluice.NewAnalyzer(in.Source)
		for _, hit := range baseline.GetURLs() {
			if len(a.out.Dependencies) > 2000 {
				a.gap("JSluice match limit")
				break
			}
			if hit.Type == "stringLiteral" || hit.Type == "locationAssignment" || hit.Type == "window.open" {
				a.out.Dependencies = append(a.out.Dependencies, Dependency{URL: hit.URL, Kind: "url-lead", Expression: hit.Source})
			}
		}
		for _, hit := range baseline.GetSecrets() {
			b := fmt.Sprint(hit.Data)
			loc := Location{Unit: in.Unit.ID, Line: 1}
			data, err := json.Marshal(hit.Data)
			if err != nil || len(data) > MaxCredentialValue {
				a.gap("credential data exceeds finding limit")
				continue
			}
			value := string(data)
			if fields, ok := hit.Data.(map[string]string); ok && len(fields) == 1 {
				for _, entry := range fields {
					value = entry
				}
			}
			f := credentialFinding(in.Unit, in.Role, "jsluice:"+hit.Kind, hit.Kind, value, loc)
			f.ID = ID(in.Unit.ID, "jsluice", b)
			f.Confidence = "high"
			a.out.Findings = append(a.out.Findings, f)
		}
		if formatted, e := baseline.RootNode().Format(); e == nil && len(formatted) <= MaxSource {
			a.out.Formatted = []byte(formatted)
		}
	}
	return a.out, ctx.Err()
}
func (a *analyzer) text(n *sitter.Node) string {
	if n == nil {
		return ""
	}
	return n.Content(a.in.Source)
}
func field(n *sitter.Node, s string) *sitter.Node {
	if n == nil {
		return nil
	}
	return n.ChildByFieldName(s)
}
func child(n *sitter.Node, i int) *sitter.Node {
	if n == nil || i >= int(n.NamedChildCount()) {
		return nil
	}
	return n.NamedChild(i)
}
func (a *analyzer) loc(n *sitter.Node) Location {
	if n == nil {
		return Location{Unit: a.in.Unit.ID, Line: 1}
	}
	p := n.StartPoint()
	return Location{Unit: a.in.Unit.ID, Offset: int(n.StartByte()) + a.in.Unit.Offset, Line: int(p.Row) + 1, Column: int(p.Column)}
}
func (a *analyzer) gap(reason string) {
	if len(a.out.Gaps) < 100 {
		a.out.Gaps = append(a.out.Gaps, Gap{Stage: "analysis", URL: a.in.Unit.URL, Reason: reason})
	}
}
func (a *analyzer) eval(n *sitter.Node, e *lexical, depth int) value {
	if n == nil || depth > 32 {
		return value{}
	}
	text := a.text(n)
	switch n.Type() {
	case "string":
		return value{text: jsluice.DecodeString(text), known: true, kind: "string"}
	case "number", "true", "false", "null":
		return value{text: text, known: true, kind: n.Type()}
	case "undefined":
		return value{known: true, kind: "undefined"}
	case "identifier", "shorthand_property_identifier":
		if text == "undefined" && e.get(text) == nil {
			return value{known: true, kind: "undefined"}
		}
		if s := e.get(text); s != nil {
			return s.v
		}
		return value{text: "{" + text + "}", kind: "expression"}
	case "parenthesized_expression", "await_expression":
		return a.eval(child(n, 0), e, depth+1)
	case "binary_expression":
		l := a.eval(field(n, "left"), e, depth+1)
		r := a.eval(field(n, "right"), e, depth+1)
		if a.text(field(n, "operator")) == "+" && (l.kind == "string" || r.kind == "string") {
			return value{text: l.text + r.text, known: l.known && r.known, kind: "string"}
		}
	case "template_string":
		var b strings.Builder
		known := true
		for i := 0; i < int(n.NamedChildCount()); i++ {
			c := n.NamedChild(i)
			if c.Type() == "string_fragment" {
				b.WriteString(a.text(c))
			} else if c.Type() == "template_substitution" {
				v := a.eval(child(c, 0), e, depth+1)
				b.WriteString(v.text)
				known = known && v.known
			}
		}
		return value{text: b.String(), known: known, kind: "string"}
	case "object":
		v := value{fields: map[string]value{}, known: true, kind: "object"}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			c := n.NamedChild(i)
			switch c.Type() {
			case "pair":
				k := a.text(field(c, "key"))
				if field(c, "key").Type() == "string" {
					k = jsluice.DecodeString(k)
				}
				if field(c, "key").Type() == "computed_property_name" {
					for key, existing := range v.fields {
						existing.known = false
						v.fields[key] = existing
					}
					v.known = false
					continue
				}
				v.fields[k] = a.eval(field(c, "value"), e, depth+1)
			case "shorthand_property_identifier":
				v.fields[a.text(c)] = a.eval(c, e, depth+1)
			case "spread_element":
				x := a.eval(child(c, 0), e, depth+1)
				if x.fields == nil || !x.known {
					v.known = false
					for key, existing := range v.fields {
						existing.known = false
						v.fields[key] = existing
					}
				}
				if x.fields != nil {
					for k, f := range x.fields {
						v.fields[k] = f
					}
				}
			}
		}
		return v
	case "array":
		v := value{kind: "array", known: true}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			v.items = append(v.items, a.eval(n.NamedChild(i), e, depth+1))
		}
		return v
	case "member_expression":
		v := a.eval(field(n, "object"), e, depth+1)
		if x, ok := v.fields[a.text(field(n, "property"))]; ok {
			return x
		}
	case "subscript_expression":
		v := a.eval(field(n, "object"), e, depth+1)
		i := a.eval(field(n, "index"), e, depth+1)
		if i.known {
			if idx, err := strconv.Atoi(i.text); err == nil && idx >= 0 && idx < len(v.items) {
				return v.items[idx]
			}
			if x, ok := v.fields[i.text]; ok {
				return x
			}
		}
	case "call_expression", "new_expression":
		callee := a.text(field(n, "function"))
		if callee == "" {
			callee = a.text(field(n, "constructor"))
		}
		args := field(n, "arguments")
		if strings.HasSuffix(callee, ".create") {
			if sym := e.get(strings.TrimSuffix(callee, ".create")); sym != nil && sym.v.kind == "axios" {
				v := a.eval(child(args, 0), e, depth+1)
				v.kind = "axios"
				return v
			}
		}
		switch callee {
		case "JSON.stringify":
			if e.get("JSON") != nil {
				break
			}
			return a.eval(child(args, 0), e, depth+1)
		case "atob":
			if e.get("atob") != nil {
				break
			}
			v := a.eval(child(args, 0), e, depth+1)
			if v.known {
				if decoded, ok := decodeBase64(v.text); ok {
					return value{text: decoded, known: true, kind: "string"}
				}
			}
		case "decodeURIComponent":
			if e.get("decodeURIComponent") != nil {
				break
			}
			v := a.eval(child(args, 0), e, depth+1)
			if v.known {
				if x, err := url.PathUnescape(v.text); err == nil {
					return value{text: x, known: true, kind: "string"}
				}
			}
		case "axios.create":
			if sym := e.get("axios"); sym != nil && sym.v.kind != "axios" {
				break
			}
			v := a.eval(child(args, 0), e, depth+1)
			v.kind = "axios"
			return v
		case "XMLHttpRequest":
			if e.get("XMLHttpRequest") != nil {
				break
			}
			return value{kind: "xhr", fields: map[string]value{}}
		case "URL":
			if e.get("URL") != nil {
				break
			}
			v := a.eval(child(args, 0), e, depth+1)
			base := a.eval(child(args, 1), e, depth+1)
			if v.known && base.known {
				u, err := url.Parse(base.text)
				r, err2 := url.Parse(v.text)
				if err == nil && err2 == nil {
					return value{text: u.ResolveReference(r).String(), known: true, kind: "string"}
				}
			}
		}
	}
	return value{text: "{" + text + "}", kind: "expression"}
}
func (a *analyzer) declare(n *sitter.Node, e *lexical) {
	for i := 0; i < int(n.NamedChildCount()); i++ {
		c := n.NamedChild(i)
		switch c.Type() {
		case "import_statement":
			a.importBindings(c, e)
		case "class_declaration":
			a.bindPattern(field(c, "name"), e, 0)
		case "function_declaration", "generator_function_declaration":
			name := a.text(field(c, "name"))
			e.vars[name] = &symbol{}
		case "lexical_declaration", "variable_declaration":
			for j := 0; j < int(c.NamedChildCount()); j++ {
				d := c.NamedChild(j)
				name := field(d, "name")
				scope := e
				if c.Type() == "variable_declaration" {
					scope = e.variableScope()
				}
				a.bindPattern(name, scope, 0)
			}
		}
	}
}
func (a *analyzer) function(n *sitter.Node, e *lexical, name string, depth int) error {
	loc := a.loc(n)
	fn := Function{ID: ID(a.in.Unit.ID, fmt.Sprint(loc.Offset), "function"), Name: name, Enclosing: e.function, Location: loc}
	inner := e.child()
	inner.function = fn.ID
	inner.functionScope = true
	a.bindPattern(field(n, "name"), inner, 0)
	params := field(n, "parameters")
	if params == nil {
		params = field(n, "parameter")
	}
	var list []*sitter.Node
	if params != nil {
		if params.Type() == "identifier" {
			list = []*sitter.Node{params}
		} else {
			for i := 0; i < int(params.NamedChildCount()); i++ {
				list = append(list, params.NamedChild(i))
			}
		}
	}
	for i, p := range list {
		a.bindPattern(p, inner, 0)
		fn.Parameters = append(fn.Parameters, a.bindParameter(p, inner, e, i)...)
	}
	a.out.Functions = append(a.out.Functions, fn)
	s := e.vars[name]
	if s == nil {
		s = &symbol{}
		e.vars[name] = s
	}
	s.fn = &fn
	before := len(a.out.Relationships)
	if err := a.hoistVariables(field(n, "body"), inner, depth+1); err != nil {
		return err
	}
	if err := a.walk(field(n, "body"), inner, depth+1); err != nil {
		return err
	}
	for _, rel := range a.out.Relationships[before:] {
		if rel.Kind == "call-operation" {
			if op, ok := a.operations[rel.To]; ok {
				s.templates = append(s.templates, op)
			}
		}
	}
	return nil
}
func (a *analyzer) walk(n *sitter.Node, e *lexical, depth int) error {
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
	case "program", "statement_block":
		inner := e
		if n.Type() == "statement_block" {
			inner = e.child()
		}
		a.declare(n, inner)
		for i := 0; i < int(n.NamedChildCount()); i++ {
			c := n.NamedChild(i)
			if c.Type() == "lexical_declaration" || c.Type() == "variable_declaration" {
				for j := 0; j < int(c.NamedChildCount()); j++ {
					d := c.NamedChild(j)
					name := field(d, "name")
					if name != nil && name.Type() == "identifier" {
						inner.get(a.text(name)).v = a.eval(field(d, "value"), inner, 0)
					}
				}
			}
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			c := n.NamedChild(i)
			if c.Type() == "function_declaration" || c.Type() == "generator_function_declaration" {
				if err := a.function(c, inner, a.text(field(c, "name")), depth); err != nil {
					return err
				}
			}
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			c := n.NamedChild(i)
			if c.Type() != "function_declaration" && c.Type() != "generator_function_declaration" {
				if err := a.walk(c, inner, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	case "catch_clause":
		inner := e.child()
		a.bindPattern(field(n, "parameter"), inner, 0)
		return a.walk(field(n, "body"), inner, depth+1)
	case "for_statement", "for_in_statement":
		inner := e.child()
		a.declare(n, inner)
		if n.Type() == "for_in_statement" {
			scope := inner
			if declarationKind(n) == "var" {
				scope = e.variableScope()
			}
			a.bindPattern(field(n, "left"), scope, 0)
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			if err := a.walk(n.NamedChild(i), inner, depth+1); err != nil {
				return err
			}
		}
		return nil
	case "variable_declarator":
		if parent := n.Parent(); parent != nil && parent.Type() == "variable_declaration" {
			e = e.variableScope()
		}
		if strings.Contains(a.text(field(n, "name")), "__vite__mapDeps") {
			a.viteChunks(n, e)
		}
		name := field(n, "name")
		v := field(n, "value")
		if v != nil && strings.Contains(a.text(v), "process.env") && !a.eval(v, e, 0).known {
			a.gap("environment value unavailable at runtime: " + a.text(name))
		}
		if name != nil && name.Type() == "identifier" {
			s := &symbol{v: a.eval(v, e, 0)}
			e.vars[a.text(name)] = s
			if v != nil && (v.Type() == "arrow_function" || v.Type() == "function_expression" || v.Type() == "function" || v.Type() == "generator_function") {
				return a.function(v, e, a.text(name), depth)
			}
		} else if name != nil && name.Type() == "object_pattern" {
			v := a.eval(v, e, 0)
			for i := 0; i < int(name.NamedChildCount()); i++ {
				c := name.NamedChild(i)
				key := a.text(field(c, "key"))
				alias := a.text(field(c, "value"))
				if key == "" {
					key = a.text(c)
					alias = key
				}
				e.vars[alias] = &symbol{v: v.fields[key]}
			}
		}
	case "method_definition":
		return a.function(n, e.child(), a.text(field(n, "name")), depth)
	case "function_expression", "function", "generator_function", "arrow_function":
		return a.function(n, e, "anonymous", depth)
	case "if_statement":
		condition := a.text(field(n, "condition"))
		if err := a.walk(field(n, "condition"), e, depth+1); err != nil {
			return err
		}
		for _, branch := range []struct{ name, condition string }{{"consequence", condition}, {"alternative", "!(" + condition + ")"}} {
			inner := e.child()
			inner.conditions = append(inner.conditions, branch.condition)
			if err := a.walk(field(n, branch.name), inner, depth+1); err != nil {
				return err
			}
		}
		return nil
	case "import_statement", "export_statement":
		v := field(n, "source")
		if v != nil {
			x := a.eval(v, e, 0)
			a.out.Dependencies = append(a.out.Dependencies, Dependency{URL: x.text, Kind: "module", Location: a.loc(v)})
		}
	case "call_expression", "new_expression":
		a.call(n, e)
		if strings.Contains(a.text(n), "__vite__mapDeps") {
			a.viteChunks(n, e)
		}
		if v := a.eval(n, e, 0); v.known && (strings.HasPrefix(a.text(n), "atob(") || strings.HasPrefix(a.text(n), "decodeURIComponent(")) {
			a.out.Units[0].Transformations = AddUnique(a.out.Units[0].Transformations, fmt.Sprintf("static-string-decoding offset=%d", a.loc(n).Offset))
			a.secret(n, e)
		}
	case "binary_expression", "template_string", "subscript_expression":
		if v := a.eval(n, e, 0); v.known {
			a.out.Units[0].Transformations = AddUnique(a.out.Units[0].Transformations, fmt.Sprintf("static-%s offset=%d", n.Type(), a.loc(n).Offset))
			a.secret(n, e)
		}
	case "assignment_expression":
		a.assignment(n, e)
		l := a.text(field(n, "left"))
		parts := strings.Split(l, ".")
		if len(parts) >= 3 && parts[1] == "defaults" {
			if s := e.get(parts[0]); s != nil && s.v.kind == "axios" {
				v := a.eval(field(n, "right"), e, 0)
				if len(parts) == 3 {
					s.v.fields[parts[2]] = v
				} else if parts[2] == "headers" && len(parts) == 4 {
					h := s.v.fields["headers"]
					if h.fields == nil {
						h = value{fields: map[string]value{}, known: true, kind: "object"}
					}
					h.fields[parts[3]] = v
					s.v.fields["headers"] = h
				}
			}
		}
		left := field(n, "left")
		if left != nil && left.Type() == "identifier" {
			if s := e.get(a.text(left)); s != nil {
				s.v = value{kind: "expression", text: "{" + a.text(left) + "}"}
			}
		}
	case "string":
		a.secret(n, e)
	case "comment":
		a.comment(n)
	}
	for i := 0; i < int(n.NamedChildCount()); i++ {
		if err := a.walk(n.NamedChild(i), e, depth+1); err != nil {
			return err
		}
	}
	return nil
}
func (a *analyzer) call(n *sitter.Node, e *lexical) {
	callee := a.text(field(n, "function"))
	if callee == "" {
		callee = a.text(field(n, "constructor"))
	}
	args := field(n, "arguments")
	loc := a.loc(n)
	c := Call{ID: ID(a.in.Unit.ID, fmt.Sprint(loc.Offset), "call"), Function: e.function, Callee: callee, Location: loc, Conditions: e.conditions}
	if args != nil {
		for i := 0; i < int(args.NamedChildCount()); i++ {
			c.Arguments = append(c.Arguments, a.text(args.NamedChild(i)))
		}
	}
	if len(a.out.Calls) >= 5000 {
		a.gap("call limit")
		return
	}
	a.out.Calls = append(a.out.Calls, c)
	if callee == "import" {
		v := a.eval(child(args, 0), e, 0)
		d := Dependency{Kind: "dynamic-import", Location: loc}
		if v.known {
			d.URL = v.text
		} else {
			d.Expression = a.text(child(args, 0))
			a.gap("unresolved dynamic import: " + RedactText(d.Expression))
		}
		a.out.Dependencies = append(a.out.Dependencies, d)
		return
	}
	method := "GET"
	protocol := "http"
	var target value
	options := value{}
	supported := false
	baseName := strings.Split(callee, ".")[0]
	sym := e.get(baseName)
	switch {
	case (callee == "fetch" && sym == nil) || (callee == "window.fetch" || callee == "globalThis.fetch") && sym == nil:
		target = a.eval(child(args, 0), e, 0)
		options = a.eval(child(args, 1), e, 0)
		if child(args, 1) != nil && (!options.known || options.kind != "object" && options.kind != "null" && options.kind != "undefined") {
			options.kind = "unresolved-options"
			method = "UNKNOWN"
		}
		if m := options.fields["method"]; m.known {
			method = strings.ToUpper(m.text)
		} else if m.text != "" {
			method = "UNKNOWN"
		}
		supported = true
	case callee == "WebSocket" && sym == nil:
		target = a.eval(child(args, 0), e, 0)
		protocol = "websocket"
		supported = true
	case callee == "EventSource" && sym == nil:
		target = a.eval(child(args, 0), e, 0)
		protocol = "eventsource"
		supported = true
	case strings.HasSuffix(callee, ".setRequestHeader") && sym != nil && sym.v.kind == "xhr":
		key := a.eval(child(args, 0), e, 0)
		val := a.eval(child(args, 1), e, 0)
		headers := sym.v.fields["headers"]
		if headers.fields == nil {
			headers = value{fields: map[string]value{}, kind: "object", known: true}
		}
		if key.known {
			headers.fields[key.text] = val
		} else {
			headers.known = false
		}
		sym.v.fields["headers"] = headers
		return
	case strings.HasSuffix(callee, ".send") && sym != nil && sym.v.kind == "xhr":
		target = sym.v.fields["url"]
		method = sym.v.fields["method"].text
		options = value{fields: map[string]value{"headers": sym.v.fields["headers"], "body": a.eval(child(args, 0), e, 0)}}
		supported = target.text != ""
	case strings.HasSuffix(callee, ".open") && sym != nil && sym.v.kind == "xhr":
		m := a.eval(child(args, 0), e, 0)
		method = strings.ToUpper(m.text)
		target = a.eval(child(args, 1), e, 0)
		supported = m.known
		sym.v.fields["url"] = target
		sym.v.fields["method"] = m
	case strings.Contains(callee, ".interceptors.") && sym != nil && sym.v.kind == "axios":
		if !a.interceptor(child(args, 0), sym, e) {
			sym.v.fields["interceptor"] = value{text: "request interceptor requires runtime validation"}
			a.gap("request interceptor modifies defaults; runtime validation required")
		}
		return
	case baseName == "axios" && sym == nil || sym != nil && sym.v.kind == "axios":
		supported = true
		target = a.eval(child(args, 0), e, 0)
		parts := strings.Split(callee, ".")
		verb := parts[len(parts)-1]
		switch verb {
		case "get", "head", "options", "delete", "post", "put", "patch":
			method = strings.ToUpper(verb)
			options = a.eval(child(args, 1), e, 0)
			if method == "POST" || method == "PUT" || method == "PATCH" {
				config := a.eval(child(args, 2), e, 0)
				if config.fields == nil {
					config.fields = map[string]value{}
				}
				config.fields["body"] = options
				options = config
			}
		default:
			options = target
			target = options.fields["url"]
			if m := options.fields["method"]; m.known {
				method = strings.ToUpper(m.text)
			}
		}
		if sym != nil {
			base := sym.v.fields["baseURL"]
			if base.known && !strings.HasPrefix(target.text, "http") {
				target.text = strings.TrimRight(base.text, "/") + "/" + strings.TrimLeft(target.text, "/")
			}
			if options.fields == nil {
				options.fields = map[string]value{}
			}
			for k, v := range sym.v.fields {
				if _, ok := options.fields[k]; !ok {
					options.fields[k] = v
				}
			}
		}
	case sym != nil && sym.fn != nil && callee == baseName:
		for _, template := range sym.templates {
			op := template
			op.Parameters = append([]Parameter(nil), template.Parameters...)
			for i, p := range sym.fn.Parameters {
				v := argumentFor(p, args, a, e, i)
				if v.text != "" {
					op.Path = strings.ReplaceAll(op.Path, "{"+p.Name+"}", v.text)
					op.Query = strings.ReplaceAll(op.Query, "{"+p.Name+"}", v.text)
					for j := range op.Parameters {
						op.Parameters[j].Expression = strings.ReplaceAll(op.Parameters[j].Expression, "{"+p.Name+"}", v.text)
						if v.known && !strings.Contains(op.Parameters[j].Expression, "{") {
							op.Parameters[j].Unresolved = false
							op.Parameters[j].Type = v.kind
						}
					}
				}
			}
			remaining := []string{}
			for _, unresolved := range op.Unresolved {
				if strings.HasPrefix(unresolved, "URL expression:") && !strings.Contains(op.Path+op.Query, "{") {
					continue
				}
				remaining = append(remaining, unresolved)
			}
			op.Unresolved = remaining
			op.Calls = []string{c.ID}
			op.ID = OperationID(op)
			a.addOperation(op, c)
		}
		return
	}
	if supported {
		a.operation(c, target, method, protocol, options)
	}
	if callee == "eval" || callee == "Function" || callee == "setTimeout" || callee == "setInterval" || strings.HasSuffix(callee, ".insertAdjacentHTML") || callee == "Object.setPrototypeOf" || strings.HasSuffix(callee, ".addEventListener") && strings.Contains(a.text(child(args, 0)), "message") {
		a.out.Findings = append(a.out.Findings, Finding{ID: ID(c.ID, "sink"), Kind: "sink-lead", Detector: callee, Confidence: "medium", Location: loc, Preview: RedactText(a.text(n)), Version: Version})
	}
}
func OperationID(o Operation) string {
	return ID(o.Origin, o.Method, o.Path, o.Query, o.Protocol, o.GraphQL)
}
func (a *analyzer) operation(c Call, target value, method, protocol string, options value) {
	if target.text == "" {
		a.gap("unresolved request URL")
		return
	}
	op := Operation{Method: method, Protocol: protocol, Validation: "unvalidated", Calls: []string{c.ID}, Roles: []string{a.in.Role}, Discoveries: []string{"static"}}
	if a.in.Historical {
		op.Discoveries = []string{"historical"}
	}
	ref, err := url.Parse(target.text)
	baseURL := a.in.Unit.DocumentURL
	if baseURL == "" {
		baseURL = a.in.Unit.URL
	}
	base, be := url.Parse(baseURL)
	if err != nil || be != nil {
		a.gap("unresolved request URL")
		return
	}
	if ref.Scheme == "" {
		ref = base.ResolveReference(ref)
	}
	if ref.User != nil || ref.Host == "" || strings.Contains(ref.Host, "{") || (ref.Scheme != "http" && ref.Scheme != "https" && ref.Scheme != "ws" && ref.Scheme != "wss") {
		a.gap("unresolved request origin")
		return
	}
	op.Origin = ref.Scheme + "://" + ref.Host
	op.Path = ref.Path
	op.Query = ref.RawQuery
	for _, name := range placeholders(op.Path) {
		op.Parameters = append(op.Parameters, Parameter{Name: name, Field: "path." + name, Expression: "{" + name + "}", Unresolved: true})
	}
	for k, vs := range ref.Query() {
		for _, v := range vs {
			op.Parameters = append(op.Parameters, Parameter{Name: k, Field: "query." + k, Expression: v, Type: "string", Unresolved: strings.Contains(v, "{")})
		}
	}
	for key, prefix := range map[string]string{"params": "query", "headers": "header", "body": "body", "data": "body"} {
		v := options.fields[key]
		for _, k := range sortedValueKeys(v.fields) {
			x := v.fields[k]
			op.Parameters = append(op.Parameters, Parameter{Name: k, Field: prefix + "." + k, Expression: x.text, Type: x.kind, Unresolved: !x.known})
			if prefix == "query" {
				query, _ := url.ParseQuery(op.Query)
				query.Set(k, x.text)
				op.Query = query.Encode()
			}

			if prefix == "header" && strings.EqualFold(k, "Content-Type") {
				op.ContentType = x.text
			}
			if prefix == "body" && k == "query" && x.known {
				op.GraphQL = x.text
				op.Variables = graphqlVariables(x.text)
			}
		}
		if v.text != "" && v.fields == nil {
			op.Unresolved = append(op.Unresolved, key+": "+v.text)
		}
		if v.fields != nil && !v.known {
			op.Unresolved = append(op.Unresolved, key+": unknown spread or computed field")
		}
	}
	if !target.known {
		op.Unresolved = append(op.Unresolved, "URL expression: "+target.text)
	}
	if v := options.fields["interceptor"]; v.text != "" {
		op.Unresolved = append(op.Unresolved, v.text)
	}
	if options.kind == "unresolved-options" {
		op.Unresolved = append(op.Unresolved, "request options: unknown spread, computed property or runtime value")
		a.gap("unresolved request options")
	}
	op.Features = FeatureTags(op.Path + " " + c.Callee + " " + a.in.Unit.Name)
	op.ID = OperationID(op)
	a.addOperation(op, c)
}
func (a *analyzer) addOperation(op Operation, c Call) {
	if old, ok := a.operations[op.ID]; ok {
		op = MergeOperation(old, op)
	}
	a.operations[op.ID] = op
	a.out.Relationships = append(a.out.Relationships, Relationship{ID: ID(c.ID, op.ID), From: c.ID, To: op.ID, Kind: "call-operation"})
	for _, p := range op.Parameters {
		a.out.Relationships = append(a.out.Relationships, Relationship{ID: ID(c.ID, op.ID, p.Field, p.Expression), From: c.ID, To: op.ID, Kind: "parameter-field", Field: p.Field, Expression: p.Expression})
	}
}
func MergeOperation(a, b Operation) Operation {
	if b.Exchange != nil {
		a.Exchange = b.Exchange
	}
	if a.ContentType == "" {
		a.ContentType = b.ContentType
	}
	for _, v := range b.Variables {
		a.Variables = AddUnique(a.Variables, v)
	}
	for _, x := range b.Calls {
		a.Calls = AddUnique(a.Calls, x)
	}
	for _, x := range b.Discoveries {
		a.Discoveries = AddUnique(a.Discoveries, x)
	}
	for _, x := range b.Roles {
		a.Roles = AddUnique(a.Roles, x)
	}
	for _, x := range b.Features {
		a.Features = AddUnique(a.Features, x)
	}
	for _, x := range b.Unresolved {
		a.Unresolved = AddUnique(a.Unresolved, x)
	}
	rank := map[string]int{"": 0, "unvalidated": 0, "attempted": 1, "access-response": 2, "cache-response-observed": 2, "response-observed": 3, "handshake-observed": 2, "message-observed": 3, "application-exchange-validated": 4}
	if rank[b.Validation] > rank[a.Validation] {
		a.Validation = b.Validation
	}
	for _, s := range b.Statuses {
		found := false
		for _, v := range a.Statuses {
			if v == s {
				found = true
			}
		}
		if !found {
			a.Statuses = append(a.Statuses, s)
		}
	}
	for _, p := range b.Parameters {
		found := false
		for _, v := range a.Parameters {
			if v.Field == p.Field && v.Expression == p.Expression {
				found = true
			}
		}
		if !found && len(a.Parameters) < 500 {
			a.Parameters = append(a.Parameters, p)
		}
	}
	for _, ex := range b.Examples {
		if len(a.Examples) < 20 {
			a.Examples = append(a.Examples, ex)
		}
	}
	return a
}

var placeholderRE = regexp.MustCompile(`\{([^{}]+)\}`)

func placeholders(s string) []string {
	var out []string
	for _, m := range placeholderRE.FindAllStringSubmatch(s, 100) {
		out = AddUnique(out, m[1])
	}
	return out
}
func sortedValueKeys(v map[string]value) []string {
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

var gqlVarRE = regexp.MustCompile(`\$([A-Za-z_][A-Za-z0-9_]*)`)

func graphqlVariables(s string) []string {
	var out []string
	for _, m := range gqlVarRE.FindAllStringSubmatch(s, 100) {
		out = AddUnique(out, m[1])
	}
	return out
}
func FeatureTags(s string) []string {
	tokens := strings.Fields(strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + 32
		}
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		return ' '
	}, s))
	out := []string{}
	groups := []struct {
		name  string
		words []string
	}{{"authentication", []string{"auth", "login", "logout", "oauth", "signin"}}, {"profile", []string{"user", "users", "profile", "account"}}, {"admin", []string{"admin", "administrator"}}, {"billing", []string{"billing", "payment", "payments", "checkout", "invoice"}}, {"uploads", []string{"upload", "uploads", "file", "files"}}, {"reporting", []string{"report", "reports", "analytics"}}, {"search", []string{"search", "query"}}}
	for _, g := range groups {
		for _, t := range tokens {
			for _, w := range g.words {
				if t == w {
					out = AddUnique(out, g.name)
				}
			}
		}
	}
	if len(out) == 0 {
		out = []string{"uncategorized"}
	}
	return out
}
