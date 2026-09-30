package tooldef

import (
	"context"
	"reflect"
	"testing"
)

type fakeTool struct {
	name   string
	desc   string
	schema map[string]any
	call   func(ctx context.Context, argsJSON string) (string, error)
}

func (f fakeTool) Name() string           { return f.name }
func (f fakeTool) Description() string    { return f.desc }
func (f fakeTool) Schema() map[string]any { return f.schema }
func (f fakeTool) Call(ctx context.Context, argsJSON string) (string, error) {
	if f.call != nil {
		return f.call(ctx, argsJSON)
	}
	return "", nil
}

func newFake(name string) fakeTool {
	return fakeTool{
		name:   name,
		desc:   "desc of " + name,
		schema: map[string]any{"type": "object", "title": name},
	}
}

func TestRegisterAndGet(t *testing.T) {
	r := NewRegistry()
	for _, n := range []string{"beta", "alpha"} {
		if err := r.Register(newFake(n)); err != nil {
			t.Fatalf("register %s: %v", n, err)
		}
	}
	for _, n := range []string{"alpha", "beta"} {
		got, ok := r.Get(n)
		if !ok || got.Name() != n {
			t.Fatalf("Get(%q) = %v, %v", n, got, ok)
		}
	}
	if _, ok := r.Get("missing"); ok {
		t.Fatal("Get(missing) reported found")
	}
}

func TestRegisterDuplicateErrors(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(newFake("a")); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(newFake("a")); err == nil {
		t.Fatal("duplicate register returned nil error")
	}
}

func TestRegisterEmptyNameErrors(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(newFake("")); err == nil {
		t.Fatal("empty-name register returned nil error")
	}
}

func TestNamesSorted(t *testing.T) {
	r := NewRegistry()
	for _, n := range []string{"charlie", "alpha", "bravo"} {
		if err := r.Register(newFake(n)); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"alpha", "bravo", "charlie"}
	if got := r.Names(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Names() = %v, want %v", got, want)
	}
}

func TestSpecs(t *testing.T) {
	r := NewRegistry()
	for _, n := range []string{"zeta", "alpha"} {
		if err := r.Register(newFake(n)); err != nil {
			t.Fatal(err)
		}
	}
	specs := r.Specs()
	if len(specs) != 2 {
		t.Fatalf("len(Specs()) = %d, want 2", len(specs))
	}
	for i, n := range []string{"alpha", "zeta"} {
		s := specs[i]
		if s.Type != "function" || s.Function == nil {
			t.Fatalf("spec %d: bad type or nil function: %+v", i, s)
		}
		if s.Function.Name != n {
			t.Fatalf("spec %d name = %q, want %q", i, s.Function.Name, n)
		}
		if s.Function.Description != "desc of "+n {
			t.Fatalf("spec %d description = %q", i, s.Function.Description)
		}
		if !reflect.DeepEqual(s.Function.Parameters, map[string]any{"type": "object", "title": n}) {
			t.Fatalf("spec %d parameters = %v", i, s.Function.Parameters)
		}
	}
}
