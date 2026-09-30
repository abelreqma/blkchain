package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"

	"github.com/tmc/langchaingo/llms"
)

// gradePromptTemplate is the grading instruction: ask for one JSON verdict
// object, no prose, with sufficient/rewrite/use_web fields.
const gradePromptTemplate = "You are grading whether the retrieved context below is sufficient to answer the " +
	"user's offensive-security question. Respond with ONLY one JSON object, no prose, " +
	"in exactly this shape: {\"sufficient\": true or false, \"rewrite\": \"<improved search " +
	"query, or empty string>\", \"use_web\": true or false}. Set \"use_web\" to true only if " +
	"the question needs a CVE lookup, a public proof-of-concept, or other current external " +
	"information a local knowledge base would not contain.\n\n" +
	"Question: %s\n\nRetrieved context:\n%s"

// grade is the parsed sufficiency verdict from the grading call.
type grade struct {
	Sufficient bool
	Rewrite    string
	UseWeb     bool
}

// parseGrade takes the substring from the first '{' to the last '}'
// (tolerating chatter/prose around the JSON object), parses it as JSON, and
// falls back to the all-false/empty default on any failure (missing braces,
// malformed JSON, or unexpected shape).
func parseGrade(raw string) grade {
	def := grade{Sufficient: false, Rewrite: "", UseWeb: false}

	start := strings.Index(raw, "{")
	end := strings.LastIndex(raw, "}")
	if start == -1 || end == -1 || end < start {
		return def
	}

	var parsed struct {
		Sufficient bool   `json:"sufficient"`
		Rewrite    string `json:"rewrite"`
		UseWeb     bool   `json:"use_web"`
	}
	if err := json.Unmarshal([]byte(raw[start:end+1]), &parsed); err != nil {
		return def
	}
	return grade{Sufficient: parsed.Sufficient, Rewrite: parsed.Rewrite, UseWeb: parsed.UseWeb}
}

// gradeContext runs one non-streaming oMLX call to grade whether the
// retrieved chunks are sufficient to answer query. The numbered context block
// reuses buildContext (llm.go). oMLX occasionally returns a response with no
// choices at all, so it retries once before giving up. It errors when the call
// fails, when the context is canceled, or when both attempts produce no
// choices (an empty grade is a failure, not a silent all-false verdict).
// It takes the GenerateContent interface (toolLoopModel) so it can be tested
// without a live LLM; *openai.LLM satisfies it.
func gradeContext(ctx context.Context, l toolLoopModel, cfg ragconfig.Config, query string, chunks []retrieval.Result) (grade, error) {
	contextText := "(no results retrieved)"
	if len(chunks) > 0 {
		contextText = buildContext(chunks)
	}
	prompt := fmt.Sprintf(gradePromptTemplate, query, contextText)
	msgs := []llms.MessageContent{llms.TextParts(llms.ChatMessageTypeHuman, prompt)}
	opts := []llms.CallOption{
		llms.WithTemperature(cfg.GradeTemperature),
		llms.WithMaxTokens(cfg.GradeMaxTokens),
	}

	var text string
	var lastErr error
	gotChoices := false
	for attempt := 0; attempt < 2; attempt++ {

		if err := ctx.Err(); err != nil {
			return grade{}, err
		}
		cr, err := l.GenerateContent(ctx, msgs, opts...)
		if err != nil {
			lastErr = err
			continue
		}
		lastErr = nil
		if cr == nil || len(cr.Choices) == 0 {
			continue
		}
		gotChoices = true
		text = cr.Choices[0].Content
		break
	}
	if lastErr != nil {
		return grade{}, lastErr
	}

	if !gotChoices {
		return grade{}, fmt.Errorf("grader returned no choices after 2 attempts")
	}
	return parseGrade(text), nil
}
