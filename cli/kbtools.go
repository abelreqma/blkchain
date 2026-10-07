package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/tooldef"
)

// kbAnswerFn is the answer loop kb_answer runs. It is a variable so tests can
// stub it without a live LLM.
var kbAnswerFn = AnswerLoop

// kbSnippetRunes caps the text shown per kb_search result.
const kbSnippetRunes = 240

// kbSearchMaxTopK bounds the model-supplied top_k so it cannot inflate the
// Qdrant and rerank pool.
const kbSearchMaxTopK = 20

type kbSearchArgs struct {
	Query string `json:"query" desc:"the search query"`
	TopK  int    `json:"top_k,omitempty" desc:"max results (default from config)"`
}

type kbAnswerArgs struct {
	Question string `json:"question" desc:"the question to answer from the corpus with citations"`
}

// kbTool is a tooldef.Tool backed by a function.
type kbTool struct {
	name, desc string
	schema     map[string]any
	call       func(ctx context.Context, argsJSON string) (string, error)
}

func (t kbTool) Name() string           { return t.name }
func (t kbTool) Description() string    { return t.desc }
func (t kbTool) Schema() map[string]any { return t.schema }
func (t kbTool) Call(ctx context.Context, argsJSON string) (string, error) {
	return t.call(ctx, argsJSON)
}

// newKBSearchTool exposes hybrid retrieval plus rerank as the kb_search tool.
func newKBSearchTool(rc searcher, cfg ragconfig.Config) tooldef.Tool {
	schema, err := tooldef.SchemaFor(kbSearchArgs{})
	if err != nil {
		panic(err) // static struct; a failure is a programming error
	}
	return kbTool{
		name:   "kb_search",
		desc:   "Search the local security knowledge base and return the top matching chunks with source, path, section, and a short snippet.",
		schema: schema,
		call: func(ctx context.Context, argsJSON string) (string, error) {
			var a kbSearchArgs
			if err := json.Unmarshal([]byte(argsJSON), &a); err != nil {
				return "kb_search: invalid arguments: " + err.Error(), nil
			}
			if strings.TrimSpace(a.Query) == "" {
				return "kb_search: invalid arguments: query is required", nil
			}
			if a.TopK <= 0 {
				a.TopK = cfg.TopK
			}
			if a.TopK > kbSearchMaxTopK {
				a.TopK = kbSearchMaxTopK
			}
			results, err := rc.Search(ctx, a.Query, a.TopK, nil)
			if err != nil {
				return "kb_search: " + err.Error(), nil
			}
			if len(results) == 0 {
				return "kb_search: no results", nil
			}
			var b strings.Builder
			for i, r := range results {
				p := r.Payload
				fmt.Fprintf(&b, "[%d] %s | %s", i+1, p.Source, p.Path)
				if p.Section != "" {
					fmt.Fprintf(&b, " | %s", p.Section)
				}
				b.WriteString("\n    " + kbSnippet(p.Text) + "\n")
			}
			return strings.TrimRight(b.String(), "\n"), nil
		},
	}
}

// newKBAnswerTool exposes the bounded answer loop as the kb_answer tool. noWeb
// disables the web fallback, mirroring the /models web switch.
func newKBAnswerTool(rc searcher, cfg ragconfig.Config, noWeb bool) tooldef.Tool {
	schema, err := tooldef.SchemaFor(kbAnswerArgs{})
	if err != nil {
		panic(err) // static struct; a failure is a programming error
	}
	return kbTool{
		name:   "kb_answer",
		desc:   "Answer from the local knowledge base with citations. Exact CVEs use NVD and public PoC search when web is enabled.",
		schema: schema,
		call: func(ctx context.Context, argsJSON string) (string, error) {
			var a kbAnswerArgs
			if err := json.Unmarshal([]byte(argsJSON), &a); err != nil {
				return "kb_answer: invalid arguments: " + err.Error(), nil
			}
			if strings.TrimSpace(a.Question) == "" {
				return "kb_answer: invalid arguments: question is required", nil
			}
			answer, cits, _, _, _, err := kbAnswerFn(ctx, rc, cfg, a.Question, AnswerOpts{NoWeb: noWeb})
			if errors.Is(err, ErrNoResults) {
				// Finding nothing is a normal answer, as in the MCP tool.
				return noResultsAnswer, nil
			}
			if err != nil {
				return "kb_answer: " + err.Error(), nil
			}
			var b strings.Builder
			b.WriteString(strings.TrimSpace(answer))
			if len(cits) > 0 {
				b.WriteString("\n\nSources:")
				for i, c := range cits {
					fmt.Fprintf(&b, "\n[%d] %s | %s", citationNumber(i, c), c.Source, c.Path)
					if c.Section != "" {
						fmt.Fprintf(&b, " | %s", c.Section)
					}
					if c.Untrusted {
						b.WriteString(" " + webTag)
					}
				}
			}
			return b.String(), nil
		},
	}
}

// kbSnippet collapses whitespace and trims text to kbSnippetRunes.
func kbSnippet(text string) string {
	s := strings.Join(strings.Fields(text), " ")
	r := []rune(s)
	if len(r) > kbSnippetRunes {
		return string(r[:kbSnippetRunes]) + "..."
	}
	return s
}
