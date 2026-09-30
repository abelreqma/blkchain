package tooldef

import (
	"context"
	"fmt"
	"sort"

	"github.com/tmc/langchaingo/llms"
)

// Tool is one callable capability the model can invoke.
type Tool interface {
	Name() string
	Description() string
	// Schema is the JSON schema of the tool arguments.
	Schema() map[string]any
	// Call runs the tool with the raw JSON arguments the model produced.
	Call(ctx context.Context, argsJSON string) (string, error)
}

// Registry holds tools by unique name.
type Registry struct {
	tools map[string]Tool
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{tools: map[string]Tool{}}
}

// Register adds t. It errors on an empty or duplicate name.
func (r *Registry) Register(t Tool) error {
	name := t.Name()
	if name == "" {
		return fmt.Errorf("tooldef: tool name is empty")
	}
	if _, ok := r.tools[name]; ok {
		return fmt.Errorf("tooldef: duplicate tool %q", name)
	}
	r.tools[name] = t
	return nil
}

// Get returns the tool registered under name.
func (r *Registry) Get(name string) (Tool, bool) {
	t, ok := r.tools[name]
	return t, ok
}

// Names returns the registered tool names in ascending order.
func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.tools))
	for n := range r.tools {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Specs returns one function tool definition per registered tool, ordered by name.
func (r *Registry) Specs() []llms.Tool {
	names := r.Names()
	specs := make([]llms.Tool, 0, len(names))
	for _, n := range names {
		t := r.tools[n]
		specs = append(specs, llms.Tool{
			Type: "function",
			Function: &llms.FunctionDefinition{
				Name:        t.Name(),
				Description: t.Description(),
				Parameters:  t.Schema(),
			},
		})
	}
	return specs
}
