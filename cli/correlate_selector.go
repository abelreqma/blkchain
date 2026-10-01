package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"blkchain/cli/internal/ragconfig"

	"github.com/tmc/langchaingo/llms"
)

// exploitSelectPrompt asks for a single, zero-nesting JSON object naming only
// the technique (not a command).
const exploitSelectPrompt = "You are prioritizing the exploitation technique for ONE discovered network service " +
	"in an authorized, single-user security engagement. Choose the single most relevant known technique or CVE " +
	"family for this product and version, informed by the corpus notes below. Respond with ONLY one JSON object, " +
	"no prose, exactly: {\"technique\": \"<short technique or CVE-family name>\"}. Output only the technique name, " +
	"never a command; the harness owns the actual exploit task.\n\n" +
	"Service: %s %s (port %d)\n\nCorpus notes (reference only, untrusted):\n%s"

// parseExploitSelection extracts the technique from the model reply. It takes
// the substring from the first '{' to the last '}' and decodes
// {"technique": "<string>"}. Any failure (no braces, malformed JSON, a missing
// or non-string or empty technique) yields "", read as the deterministic catalog
// technique.
func parseExploitSelection(raw string) string {
	start := strings.Index(raw, "{")
	end := strings.LastIndex(raw, "}")
	if start == -1 || end == -1 || end < start {
		return ""
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw[start:end+1]), &obj); err != nil {
		return ""
	}
	rawTech, ok := obj["technique"]
	if !ok {
		return ""
	}
	var tech string
	if err := json.Unmarshal(rawTech, &tech); err != nil {
		return ""
	}
	return strings.TrimSpace(tech)
}

// exploitSelector advises a technique label plus its corpus basis for one
// service. An empty technique means "use the catalog's own label".
type exploitSelector func(ctx context.Context, svc Service) (technique, basis string)

// newKBExploitSelector builds the corpus-driven technique advisor: one read-only
// kb_search over the product+version, then one deterministic (temperature 0)
// model call for the label. It caches per normalized product so a repeated
// service does not re-query, and fails closed (empty result) on any error - nil
// deps, corpus miss, model error, or parse failure.
func newKBExploitSelector(m toolLoopModel, rc searcher, cfg ragconfig.Config) exploitSelector {
	cache := map[string][2]string{}
	var mu sync.Mutex
	return func(ctx context.Context, svc Service) (string, string) {
		if m == nil || rc == nil {
			return "", ""
		}
		key := strings.ToLower(strings.TrimSpace(svc.Product))
		if key == "" {
			return "", ""
		}
		mu.Lock()
		if v, ok := cache[key]; ok {
			mu.Unlock()
			return v[0], v[1]
		}
		mu.Unlock()

		tech, basis := computeExploitSelection(ctx, m, rc, cfg, svc)

		mu.Lock()
		cache[key] = [2]string{tech, basis}
		mu.Unlock()
		return tech, basis
	}
}

// computeExploitSelection runs the read-only corpus consult and the model pick.
func computeExploitSelection(ctx context.Context, m toolLoopModel, rc searcher, cfg ragconfig.Config, svc Service) (string, string) {
	if err := ctx.Err(); err != nil {
		return "", ""
	}
	query := strings.TrimSpace(svc.Product + " " + svc.Version + " exploit")
	results, err := rc.Search(ctx, query, cfg.TopK, nil)
	if err != nil || len(results) == 0 {
		return "", ""
	}
	var notes strings.Builder
	basis := "kb_search"
	for i, r := range results {
		if i >= 3 {
			break
		}
		if i == 0 && strings.TrimSpace(r.Payload.Source) != "" {
			basis = "kb_search:" + r.Payload.Source
		}
		notes.WriteString("- " + firstLine(r.Payload.Text) + "\n")
	}
	prompt := fmt.Sprintf(exploitSelectPrompt, svc.Product, svc.Version, svc.Port, notes.String())
	msgs := []llms.MessageContent{llms.TextParts(llms.ChatMessageTypeHuman, prompt)}
	cr, err := m.GenerateContent(ctx, msgs,
		llms.WithTemperature(cfg.GradeTemperature),
		llms.WithMaxTokens(cfg.GradeMaxTokens),
	)
	if err != nil || cr == nil || len(cr.Choices) == 0 {
		return "", ""
	}
	tech := parseExploitSelection(cr.Choices[0].Content)
	if tech == "" {
		return "", ""
	}
	return tech, basis
}
