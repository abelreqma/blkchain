package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/promptguard"
)

func TestUntrustedInputPromptFloor(t *testing.T) {
	guarded := map[string]string{
		"answerConstraints":              answerConstraints,
		"adviseMethodology":              adviseMethodology,
		"adviseSystemPrompt":             adviseSystemPrompt,
		"skipValidateSystemPrompt":       skipValidateSystemPrompt,
		"gradePromptTemplate":            gradePromptTemplate,
		"reconGradePrompt":               reconGradePrompt,
		"conversationSummaryInstruction": conversationSummaryInstruction,
		"orchestratorSystemPrompt":       orchestratorSystemPrompt,
		"executorPreamble":               executorPreamble,
		"exploitSystemPrompt":            exploitSystemPrompt,
		"reconSelectPrompt":              reconSelectPrompt,
		"exploitSelectPrompt":            exploitSelectPrompt,
		"summarizeInstruction":           summarizeInstruction,
		"aiSecDomainPrompt":              aiSecDomainPrompt,
		"containerPersonaPrompt":         containerPersonaPrompt,
		"personaPrompt":                  personaPrompt(""),
		"exploitSystemPromptForTask":     exploitSystemPromptForTask(engagement.Task{}),
	}
	for name, prompt := range guarded {
		if !strings.Contains(prompt, promptguard.UntrustedInputClause) {
			t.Errorf("%s is missing the shared clause", name)
		}
	}
	for _, name := range domainNames() {
		if prompt := domains[name].Prompt; !strings.Contains(prompt, promptguard.UntrustedInputClause) {
			t.Errorf("domain %q is missing the shared clause", name)
		}
	}

	// These prompts either receive no retrieved or observed content or inherit
	// the rule from the system prompt paired with their dynamic human message.
	exempt := map[string]string{
		"directAnswerSystemPrompt":  "the skip route receives no retrieved context",
		"routeSystemPrompt":         "the router receives only the user's question",
		"buildUserPrompt":           "this function encodes data under the paired answer system prompt",
		"genericTaskPrompt":         "the paired executor system prompt carries the clause",
		"reconTierPrompt":           "the paired executor system prompt carries the clause",
		"networkTierPrompt":         "the paired executor system prompt carries the clause",
		"containerTierPrompt":       "the paired executor system prompt carries the clause",
		"localTargetAnalysisPrompt": "the paired executor system prompt carries the clause",
		"Prompt":                    "UI style value, not LLM prompt text",
		"GlyphPrompt":               "UI glyph value, not LLM prompt text",
		"promptArm":                 "interactive confirmation UI text",
		"promptConfirm":             "interactive confirmation UI text",
		"promptEcho":                "interactive echo UI text",
		"replPrompt":                "REPL input prompt, not an LLM prompt",
	}
	declared := promptDeclarations(t)
	for name := range exempt {
		if !declared[name] {
			t.Errorf("exempt prompt %q is missing from production source", name)
		}
	}
	for name := range declared {
		if _, ok := guarded[name]; ok {
			continue
		}
		if _, ok := exempt[name]; ok {
			continue
		}
		t.Errorf("prompt declaration %q is missing from the prompt floor", name)
	}
}

func promptDeclarations(t *testing.T) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	names := make(map[string]bool)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := entry.Name()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				addPromptName(names, d.Name.Name)
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					values, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for _, name := range values.Names {
						addPromptName(names, name.Name)
					}
				}
			}
		}
	}
	return names
}

func addPromptName(names map[string]bool, name string) {
	lower := strings.ToLower(name)
	if strings.Contains(lower, "prompt") || strings.Contains(lower, "instruction") {
		names[name] = true
	}
}
