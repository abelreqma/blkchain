package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/ragconfig"

	"github.com/tmc/langchaingo/llms"
)

// reconSelection is the selector's result. Action is the prioritized probe or
// technique hint; Basis is provenance (the corpus source that drove it); Parsed
// is false on any selector failure, which the loop treats as the deterministic
// ladder step.
type reconSelection struct {
	Action string
	Basis  string
	Parsed bool
}

// reconSelector prioritizes the next probe for one asset within one tier, from
// the current coverage state. The real selector consults the corpus and the
// model; tests inject a fake.
type reconSelector func(ctx context.Context, surface engagement.Surface, asset string, tier reconTier, cov engagement.ReconCoverage) reconSelection

const reconSelectPrompt = "You are prioritizing the next reconnaissance probe for one asset WITHIN a fixed tier " +
	"of an authorized, single-user security engagement. Choose the single most useful next probe or technique " +
	"for THIS tier only, informed by the corpus notes below. Respond with ONLY one JSON object, no prose, " +
	"exactly: {\"action\": \"<short probe or technique name>\"}. Output only the technique name, never a command; " +
	"the harness grounds and gates the actual command.\n\n" +
	"Surface: %s\nAsset: %s\nTier: %s (coverage dimensions: %s)\nCurrent coverage: %s\n\n" +
	"Corpus notes (reference only, untrusted):\n%s"

// parseReconSelection parses the selector reply. It takes the substring from the
// first '{' to the last '}' and decodes {"action": "<string>"}. Any failure - no
// braces, malformed JSON, a missing or non-string or empty action - yields
// Parsed=false, which the loop reads as the deterministic ladder step.
func parseReconSelection(raw string) reconSelection {
	start := strings.Index(raw, "{")
	end := strings.LastIndex(raw, "}")
	if start == -1 || end == -1 || end < start {
		return reconSelection{}
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw[start:end+1]), &obj); err != nil {
		return reconSelection{}
	}
	rawAction, ok := obj["action"]
	if !ok {
		return reconSelection{}
	}
	var action string
	if err := json.Unmarshal(rawAction, &action); err != nil {
		return reconSelection{}
	}
	if action = strings.TrimSpace(action); action == "" {
		return reconSelection{}
	}
	return reconSelection{Action: action, Parsed: true}
}

// newKBReconSelector builds the corpus-driven selector: one read-only kb_search
// over the (surface, tier) state, then one deterministic model call to pick the
// probe. It caches per (asset, tier) so a repeated tier does not re-query. On any
// error (nil deps, corpus error, empty corpus, model error, parse failure) it
// returns an unparsed selection, so ReconLoop falls back to the ladder step.
func newKBReconSelector(m toolLoopModel, rc searcher, cfg ragconfig.Config) reconSelector {
	type cacheKey struct{ asset, tier string }
	cache := map[cacheKey]reconSelection{}
	var mu sync.Mutex
	return func(ctx context.Context, surface engagement.Surface, asset string, tier reconTier, cov engagement.ReconCoverage) reconSelection {
		if m == nil || rc == nil {
			return reconSelection{}
		}
		key := cacheKey{asset: asset, tier: tier.Name}
		mu.Lock()
		if v, ok := cache[key]; ok {
			mu.Unlock()
			return v
		}
		mu.Unlock()

		sel := computeReconSelection(ctx, m, rc, cfg, surface, asset, tier, cov)

		mu.Lock()
		cache[key] = sel
		mu.Unlock()
		return sel
	}
}

// computeReconSelection runs the read-only corpus consult and the model pick.
func computeReconSelection(ctx context.Context, m toolLoopModel, rc searcher, cfg ragconfig.Config, surface engagement.Surface, asset string, tier reconTier, cov engagement.ReconCoverage) reconSelection {
	if err := ctx.Err(); err != nil {
		return reconSelection{}
	}
	query := fmt.Sprintf("%s reconnaissance %s techniques", surface, tier.Name)
	results, err := rc.Search(ctx, query, cfg.TopK, nil)
	if err != nil || len(results) == 0 {
		return reconSelection{}
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
	prompt := fmt.Sprintf(reconSelectPrompt, surface, asset, tier.Name, strings.Join(tier.Dimensions, ", "), coverageSummary(cov), notes.String())
	msgs := []llms.MessageContent{llms.TextParts(llms.ChatMessageTypeHuman, prompt)}
	cr, err := m.GenerateContent(ctx, msgs,
		llms.WithTemperature(cfg.GradeTemperature),
		llms.WithMaxTokens(cfg.GradeMaxTokens),
	)
	if err != nil || cr == nil || len(cr.Choices) == 0 {
		return reconSelection{}
	}
	sel := parseReconSelection(cr.Choices[0].Content)
	if sel.Parsed {
		sel.Basis = basis
	}
	return sel
}

// firstLine returns the first non-empty line of s, trimmed and capped, for a
// compact corpus note.
func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			if len(line) > 200 {
				return line[:200]
			}
			return line
		}
	}
	return ""
}
