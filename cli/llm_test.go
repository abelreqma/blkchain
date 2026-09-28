package main

import (
	"strings"
	"testing"

	"blkchain/cli/internal/client"

	"github.com/tmc/langchaingo/llms"
)

func chunk(source, path, section, text string) client.SearchResult {
	return client.SearchResult{
		Payload: client.Payload{Source: source, Path: path, Section: section, Text: text},
	}
}

func TestBuildContextNumbersAndTags(t *testing.T) {
	chunks := []client.SearchResult{
		chunk("kb", "docs/a.md", "Intro", "alpha body"),
		chunk("web", "https://x/y", "Title", "beta body"),
	}
	got := buildContext(chunks)

	if !strings.Contains(got, "[1] (local knowledge base) source=kb path=docs/a.md section=Intro\nalpha body") {
		t.Errorf("first block wrong:\n%s", got)
	}
	if !strings.Contains(got, "[2] (UNTRUSTED WEB RESULT) source=web path=https://x/y section=Title\nbeta body") {
		t.Errorf("web block should be tagged UNTRUSTED WEB RESULT:\n%s", got)
	}
}

func TestBuildUserPromptShape(t *testing.T) {
	got := buildUserPrompt("what is ssrf?", []client.SearchResult{chunk("kb", "p", "s", "t")})
	if !strings.HasPrefix(got, "Question: what is ssrf?\n\nSources:\n") {
		t.Errorf("user prompt should start with the question then Sources:\n%s", got)
	}
	if !strings.HasSuffix(got, "\n\nAnswer:") {
		t.Errorf("user prompt should end with the Answer: cue:\n%s", got)
	}
}

func TestBuildMessagesSystemThenHuman(t *testing.T) {
	msgs := buildMessages("q", []client.SearchResult{chunk("kb", "p", "s", "t")})
	if len(msgs) != 2 {
		t.Fatalf("want 2 messages, got %d", len(msgs))
	}
	if msgs[0].Role != llms.ChatMessageTypeSystem {
		t.Errorf("first message role = %q, want system", msgs[0].Role)
	}
	if msgs[1].Role != llms.ChatMessageTypeHuman {
		t.Errorf("second message role = %q, want human", msgs[1].Role)
	}
	// The system message must carry the single-source-of-truth prompt verbatim.
	sysText := msgs[0].Parts[0].(llms.TextContent).Text
	if sysText != answerSystemPrompt {
		t.Errorf("system message = %q, want answerSystemPrompt", sysText)
	}
}

func TestBoundChunksCapsCountAndLength(t *testing.T) {
	var many []client.SearchResult
	for i := 0; i < maxContextChunks+5; i++ {
		many = append(many, chunk("kb", "p", "s", strings.Repeat("x", maxChunkChars+50)))
	}
	got := boundChunks(many)
	if len(got) != maxContextChunks {
		t.Errorf("chunk count = %d, want %d", len(got), maxContextChunks)
	}
	for i, r := range got {
		if n := len([]rune(r.Payload.Text)); n != maxChunkChars {
			t.Errorf("chunk %d text len = %d, want %d", i, n, maxChunkChars)
		}
	}
	// boundChunks must not mutate the caller's slice contents.
	if n := len([]rune(many[0].Payload.Text)); n != maxChunkChars+50 {
		t.Errorf("input chunk was mutated: len = %d", n)
	}
}

func TestBoundChunksUnderCap(t *testing.T) {
	in := []client.SearchResult{chunk("kb", "p", "s", "short")}
	got := boundChunks(in)
	if len(got) != 1 || got[0].Payload.Text != "short" {
		t.Errorf("small input mangled: %+v", got)
	}
}

func TestDeriveCitationsDedupePreservesOrder(t *testing.T) {
	chunks := []client.SearchResult{
		chunk("kb", "a.md", "S1", "t1"),
		chunk("kb", "a.md", "S1", "t2"), // duplicate key
		chunk("kb", "b.md", "S2", "t3"),
		chunk("web", "http://x", "T", "t4"),
	}
	got := deriveCitations(chunks)
	want := []client.Citation{
		{Source: "kb", Path: "a.md", Section: "S1"},
		{Source: "kb", Path: "b.md", Section: "S2"},
		{Source: "web", Path: "http://x", Section: "T"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d citations, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("citation %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestCapRunes(t *testing.T) {
	if got := capRunes("héllo", 3); got != "hél" {
		t.Errorf("capRunes(héllo,3) = %q, want %q", got, "hél")
	}
	if got := capRunes("hi", 10); got != "hi" {
		t.Errorf("capRunes(hi,10) = %q, want hi", got)
	}
}
