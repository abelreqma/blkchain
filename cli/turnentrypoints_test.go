package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// This file ties the number of conversational surfaces to the number of parity
// adapters. surface_registry_test.go compares the tool registry each surface
// offers for one classified action, but it compares only the surfaces its own
// adapter list names. Nothing else connects that list to the surfaces the
// package actually has, so a sixth surface could call runNativeTurn with its
// tool registry compared against nothing and every gate would stay green.

// turnSurfaceEntryPoints maps each function that calls runNativeTurn to the
// paritySurfaces adapter that drives it. runNativeTurn is the one turn every
// conversational surface goes through, so a function that calls it is a
// surface.
var turnSurfaceEntryPoints = map[string]string{
	"askWithPreface": "blk ask",
	"plainAsk":       "plain REPL",
	"streamCmd":      "TUI",
	"mcpChatResult":  "MCP chat",
	"serveRunTurn":   "blk serve",
}

// turnEntryPointsInSource returns the name of every function in the package's
// non-test files that calls runNativeTurn, with the file it was found in. The
// declaration of runNativeTurn is not a call, so it does not appear.
func turnEntryPointsInSource(t *testing.T) map[string]string {
	t.Helper()
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob the package sources: %v", err)
	}
	found := map[string]string{}
	fset := token.NewFileSet()
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				id, ok := call.Fun.(*ast.Ident)
				if !ok || id.Name != "runNativeTurn" {
					return true
				}
				found[fn.Name.Name] = path
				return false
			})
		}
	}
	return found
}

func TestEveryTurnEntryPointHasAParityAdapter(t *testing.T) {
	found := turnEntryPointsInSource(t)
	if len(found) == 0 {
		t.Fatal("no function calls runNativeTurn: this test's own search is broken, not the package")
	}
	adapters := paritySurfaces(t)
	for name, path := range found {
		surface, mapped := turnSurfaceEntryPoints[name]
		if !mapped {
			t.Errorf("%s in %s calls runNativeTurn and has no entry in turnSurfaceEntryPoints: add one, "+
				"and add the paritySurfaces adapter that drives it, so "+
				"TestEverySurfaceOffersTheToolsOfTheClassifiedAction compares its tools against the other surfaces",
				name, path)
			continue
		}
		if !slices.ContainsFunc(adapters, func(s paritySurface) bool { return s.name == surface }) {
			t.Errorf("%s in %s maps to parity surface %q, which paritySurfaces does not define", name, path, surface)
		}
	}
	for name, surface := range turnSurfaceEntryPoints {
		if _, ok := found[name]; !ok {
			t.Errorf("turnSurfaceEntryPoints maps %s to %q, but no function of that name calls runNativeTurn: "+
				"drop the entry and its adapter, so a surface that is gone does not leave one claiming coverage",
				name, surface)
		}
	}
}
