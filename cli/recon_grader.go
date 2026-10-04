package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/promptguard"
	"blkchain/cli/internal/ragconfig"

	"github.com/tmc/langchaingo/llms"
)

// recon_grader.go is the LLM sufficiency grader for the recon tier loop. Unlike
// the RAG grader (grade.go), which defaults to "not sufficient -> keep going" on
// a bad reply, this grader is FAIL-CLOSED: a parse failure or a call error
// yields Parsed=false, and the loop stops unless the grader clearly said to
// continue. Autonomy must not be extended by a garbled model reply.

const reconGradePrompt = "You are deciding whether to continue attack-surface reconnaissance for one asset in a scoped penetration test. " +
	"Respond with ONLY one JSON object, no prose, exactly in this shape: {\"continue\": true or false}. " +
	"Set continue=true when a material coverage dimension remains, an observed service or identity exposes an untested path, " +
	"or a specific in-scope probe can resolve an important uncertainty. Set continue=false only when the current tier is covered " +
	"and no evidence-backed lead remains, or when the stated scope or test limits require stopping. Do not require discovery of a new host to continue useful validation.\n\nSurface: %s\nAsset: %s\nCurrent coverage:\n%s\n\n" + promptguard.UntrustedInputClause

// reconVerdict is the grader's decision. Parsed is false on any parse failure or
// grader error; the loop treats !Parsed (and !Continue) as STOP.
type reconVerdict struct {
	Continue bool
	Parsed   bool
}

// parseReconGrade parses the grader reply. It takes the substring from the first
// '{' to the last '}' (tolerating chatter around the object) and decodes it as
// {"continue": bool}. Any failure - missing braces, malformed JSON, a missing or
// wrongly-typed "continue" field - yields Parsed=false, which the loop reads as
// STOP (fail-closed).
func parseReconGrade(raw string) reconVerdict {
	start := strings.Index(raw, "{")
	end := strings.LastIndex(raw, "}")
	if start == -1 || end == -1 || end < start {
		return reconVerdict{Parsed: false}
	}
	// Decode into a map so a missing "continue" key is distinguishable from
	// false, and a non-boolean value is a parse failure rather than a zero value.
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw[start:end+1]), &obj); err != nil {
		return reconVerdict{Parsed: false}
	}
	rawCont, ok := obj["continue"]
	if !ok {
		return reconVerdict{Parsed: false}
	}
	var cont bool
	if err := json.Unmarshal(rawCont, &cont); err != nil {
		return reconVerdict{Parsed: false}
	}
	return reconVerdict{Continue: cont, Parsed: true}
}

// reconGrader decides whether to continue recon on one surface/asset given a
// compact coverage summary. The real grader calls the LLM; tests inject a fake.
type reconGrader func(ctx context.Context, surface engagement.Surface, asset, summary string) reconVerdict

// newLLMReconGrader builds a grader backed by one deterministic (temperature 0)
// LLM call. On a call error or an empty response it returns Parsed=false, so the
// loop stops. It takes the GenerateContent interface (toolLoopModel) so it can be
// tested without a live LLM.
func newLLMReconGrader(m toolLoopModel, cfg ragconfig.Config) reconGrader {
	return func(ctx context.Context, surface engagement.Surface, asset, summary string) reconVerdict {
		if err := ctx.Err(); err != nil {
			return reconVerdict{Parsed: false}
		}
		prompt := fmt.Sprintf(reconGradePrompt, surface, asset, summary)
		msgs := []llms.MessageContent{llms.TextParts(llms.ChatMessageTypeHuman, prompt)}
		opts := []llms.CallOption{
			llms.WithJSONMode(),
			llms.WithTemperature(cfg.GradeTemperature),
			llms.WithMaxTokens(cfg.GradeMaxTokens),
		}
		cr, err := m.GenerateContent(withLLMStage(ctx, "recon_grading"), msgs, opts...)
		if err != nil || cr == nil || len(cr.Choices) == 0 {
			return reconVerdict{Parsed: false}
		}
		return parseReconGrade(cr.Choices[0].Content)
	}
}
