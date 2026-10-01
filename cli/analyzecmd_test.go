package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/structgen"

	"github.com/tmc/langchaingo/llms"
)

// fakeAnalyzeGen is a structgen.Generator that returns a fixed reply.
type fakeAnalyzeGen struct{ reply string }

func (f *fakeAnalyzeGen) GenerateContent(_ context.Context, _ []llms.MessageContent, _ ...llms.CallOption) (*llms.ContentResponse, error) {
	return &llms.ContentResponse{Choices: []*llms.ContentChoice{{Content: f.reply}}}, nil
}

func TestResolveSubjectPrecedence(t *testing.T) {
	// Positional wins over file and stdin.
	got, err := resolveSubject([]string{"a", "b"}, "", strings.NewReader("STDIN"), true, 1024)
	if err != nil || got != "a b" {
		t.Fatalf("positional: got %q err %v", got, err)
	}

	// File used when no positional.
	dir := t.TempDir()
	fp := filepath.Join(dir, "in.txt")
	if err := os.WriteFile(fp, []byte("FROMFILE"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = resolveSubject(nil, fp, strings.NewReader("STDIN"), true, 1024)
	if err != nil || got != "FROMFILE" {
		t.Fatalf("file: got %q err %v", got, err)
	}

	// Stdin used when piped and no positional/file.
	got, err = resolveSubject(nil, "", strings.NewReader("STDIN"), true, 1024)
	if err != nil || got != "STDIN" {
		t.Fatalf("stdin: got %q err %v", got, err)
	}
}

func TestResolveSubjectEmpty(t *testing.T) {
	_, err := resolveSubject(nil, "", strings.NewReader(""), false, 1024)
	if err == nil {
		t.Fatalf("expected usage error for no subject")
	}
	if exitCode(err) != 2 {
		t.Fatalf("exit code = %d, want 2", exitCode(err))
	}
}

func TestResolveSubjectTooLarge(t *testing.T) {
	_, err := resolveSubject([]string{strings.Repeat("x", 2000)}, "", nil, false, 1024)
	if err == nil {
		t.Fatalf("expected error for oversized positional subject")
	}
	_, err = resolveSubject(nil, "", strings.NewReader(strings.Repeat("x", 2000)), true, 1024)
	if err == nil {
		t.Fatalf("expected error for oversized stdin subject")
	}
}

func TestRunAnalyzeUnknownSchema(t *testing.T) {
	err := runAnalyze([]string{"--schema", "nope", "some subject"})
	if err == nil {
		t.Fatalf("expected usage error for unknown schema")
	}
	if exitCode(err) != 2 {
		t.Fatalf("exit code = %d, want 2", exitCode(err))
	}
	if !strings.Contains(err.Error(), "finding") {
		t.Fatalf("error should list valid schema names: %v", err)
	}
}

func TestAnalyzeMaxInputBytesEnv(t *testing.T) {
	// A positive value is honored; empty, unparsable, zero, and negative all fall
	// back to the default.
	cases := []struct {
		val  string
		want int
	}{
		{"", defaultAnalyzeMaxInputBytes},
		{"4096", 4096},
		{"  512  ", 512},
		{"not-a-number", defaultAnalyzeMaxInputBytes},
		{"0", defaultAnalyzeMaxInputBytes},
		{"-10", defaultAnalyzeMaxInputBytes},
	}
	for _, c := range cases {
		t.Setenv("BLKCHAIN_ANALYZE_MAX_INPUT_BYTES", c.val)
		if got := analyzeMaxInputBytes(); got != c.want {
			t.Fatalf("val=%q: analyzeMaxInputBytes = %d, want %d", c.val, got, c.want)
		}
	}
}

func TestReadCappedBoundary(t *testing.T) {
	// Exactly maxBytes is accepted; one more byte is rejected.
	got, err := readCapped(strings.NewReader(strings.Repeat("a", 10)), 10)
	if err != nil || got != strings.Repeat("a", 10) {
		t.Fatalf("exact cap: got %q err %v", got, err)
	}
	if _, err := readCapped(strings.NewReader(strings.Repeat("a", 11)), 10); err == nil {
		t.Fatalf("over cap accepted")
	}
}

func TestWriteIndentedJSONEscapesControlRunes(t *testing.T) {
	// A literal C1 control rune (U+009B) inside a JSON string must be escaped, not
	// written raw to the terminal.
	raw := json.RawMessage(`{"x":"a` + string(rune(0x9b)) + `b"}`)
	var buf bytes.Buffer
	if err := writeIndentedJSON(&buf, raw); err != nil {
		t.Fatalf("writeIndentedJSON: %v", err)
	}
	out := buf.String()
	if strings.ContainsRune(out, 0x9b) {
		t.Fatalf("output still contains the literal C1 control rune: %q", out)
	}
	if !strings.Contains(out, `\u009b`) {
		t.Fatalf("output missing escaped control rune: %q", out)
	}
}

func TestAnalyzeRunPropagatesGroundingError(t *testing.T) {
	restore := analyzeGen
	analyzeGen = func(_ ragconfig.Config, _ string) (structgen.Generator, error) {
		return &fakeAnalyzeGen{reply: `{}`}, nil
	}
	defer func() { analyzeGen = restore }()

	boom := errors.New("qdrant down")
	restoreG := analyzeGrounding
	analyzeGrounding = func(_ context.Context, _ ragconfig.Config, _ string, _ int) (string, int, error) {
		return "", 0, boom
	}
	defer func() { analyzeGrounding = restoreG }()

	schema, _ := structgen.Lookup("finding")
	var out, errBuf bytes.Buffer
	o := analyzeOpts{schema: "finding", model: "m", retrieve: true}
	err := analyzeRun(context.Background(), ragconfig.Config{}, o, schema, "subject", 5, &out, &errBuf)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the grounding error", err)
	}
	if out.Len() != 0 {
		t.Fatalf("no JSON should be written when grounding fails: %q", out.String())
	}
}

func TestAnalyzeRunHappyPath(t *testing.T) {
	restore := analyzeGen
	analyzeGen = func(_ ragconfig.Config, _ string) (structgen.Generator, error) {
		return &fakeAnalyzeGen{reply: `{"title":"XSS","severity":"high","affected":"/q","description":"reflected"}`}, nil
	}
	defer func() { analyzeGen = restore }()

	groundingCalled := false
	restoreG := analyzeGrounding
	analyzeGrounding = func(_ context.Context, _ ragconfig.Config, _ string, _ int) (string, int, error) {
		groundingCalled = true
		return "", 0, nil
	}
	defer func() { analyzeGrounding = restoreG }()

	schema, _ := structgen.Lookup("finding")
	var out, errBuf bytes.Buffer
	o := analyzeOpts{schema: "finding", model: "test-model"}
	if err := analyzeRun(context.Background(), ragconfig.Config{}, o, schema, "subject", 5, &out, &errBuf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if groundingCalled {
		t.Fatalf("retrieval must not run when --retrieve is off")
	}
	if !strings.Contains(out.String(), `"severity": "high"`) {
		t.Fatalf("stdout missing JSON: %q", out.String())
	}
	if !strings.Contains(errBuf.String(), "schema=finding") || !strings.Contains(errBuf.String(), "model=test-model") {
		t.Fatalf("stderr missing provenance: %q", errBuf.String())
	}
}

func TestAnalyzeRunRetrieveWired(t *testing.T) {
	restore := analyzeGen
	analyzeGen = func(_ ragconfig.Config, _ string) (structgen.Generator, error) {
		return &fakeAnalyzeGen{reply: `{"title":"XSS","severity":"low","affected":"/q","description":"d"}`}, nil
	}
	defer func() { analyzeGen = restore }()

	var gotSubject string
	restoreG := analyzeGrounding
	analyzeGrounding = func(_ context.Context, _ ragconfig.Config, subject string, _ int) (string, int, error) {
		gotSubject = subject
		return "grounding text", 3, nil
	}
	defer func() { analyzeGrounding = restoreG }()

	schema, _ := structgen.Lookup("finding")
	var out, errBuf bytes.Buffer
	o := analyzeOpts{schema: "finding", model: "m", retrieve: true}
	if err := analyzeRun(context.Background(), ragconfig.Config{}, o, schema, "the subject", 5, &out, &errBuf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotSubject != "the subject" {
		t.Fatalf("grounding got subject %q", gotSubject)
	}
	if !strings.Contains(errBuf.String(), "retrieved=3") {
		t.Fatalf("stderr missing retrieved count: %q", errBuf.String())
	}
}
