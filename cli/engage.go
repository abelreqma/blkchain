package main

import (
	"context"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/tooldef"

	"github.com/tmc/langchaingo/llms"
)

// routingSystemPrompt makes retrieval adaptive: the model decides per question
// whether to call a kb tool. The deterministic guardrails it complements
// (CVE/PoC and arithmetic) live in route.go (routeGuard), shared with the ask
// path so both surfaces classify the same way.
const routingSystemPrompt = `You are a security research assistant with access to a local knowledge base through two tools: kb_search and kb_answer.

Answer general-knowledge and pure-reasoning questions directly, without calling any kb tool. This includes math, coding logic, and creative writing.

Call kb_search or kb_answer only when the question is about the local corpus, about recent or private data, or when cited and grounded accuracy is required. Use kb_search to inspect matching chunks and kb_answer for a cited answer.

Whenever you used retrieval, cite the sources (source and path) in your answer. If retrieval finds nothing relevant, say so instead of guessing.`

// runEngageTurn runs one adaptive-retrieval turn: the model gets the routing
// prompt and the question, and decides whether to call kb_search or kb_answer.
//
// The web switch is applied here through prefs. The reranker switch is not: it
// is applied to the concrete *retrieval.Client by followPrefs, so the caller
// must do that before passing rc in.
func runEngageTurn(ctx context.Context, m toolLoopModel, rc searcher, cfg ragconfig.Config, prefs modelPrefs, question string) (string, error) {
	reg := tooldef.NewRegistry()
	for _, t := range []tooldef.Tool{
		newKBSearchTool(rc, cfg),
		newKBAnswerTool(rc, cfg, !prefs.Web),
	} {
		if err := reg.Register(t); err != nil {
			return "", err
		}
	}
	msgs := []llms.MessageContent{
		{Role: llms.ChatMessageTypeSystem, Parts: []llms.ContentPart{llms.TextPart(routingSystemPrompt)}},
		{Role: llms.ChatMessageTypeHuman, Parts: []llms.ContentPart{llms.TextPart(question)}},
	}
	final, _, err := runToolLoop(ctx, m, reg, msgs, LoopCaps{MaxRounds: 6, MaxCalls: 12})
	return final, err
}
