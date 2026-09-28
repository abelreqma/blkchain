package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"blkchain/cli/internal/client"

	"github.com/tmc/langchaingo/llms"
	"github.com/tmc/langchaingo/llms/openai"
)

// llm.go is the RAG-mode streaming synthesizer (V2-BRIEF.md "RAG streaming").
// It retrieves chunks via the existing blkChain search API, then streams a
// cited answer DIRECTLY from the local oMLX server (OpenAI-compatible) via
// LangChainGo, token by token. It does not depend on the Python /answer
// endpoint; that path is the non-streaming fallback (see StreamRAG's callers).

const (
	// defaultOMLXBaseURL matches the local oMLX server (V2-BRIEF.md Env).
	defaultOMLXBaseURL = "http://127.0.0.1:8000/v1"
	// defaultOMLXModel is the last-resort model id when OMLX_MODEL is unset and
	// discovery via GET /models fails. It is the model loaded on this machine
	// (hermes-omlx-config: supergemma4-26b); override with OMLX_MODEL elsewhere.
	defaultOMLXModel = "supergemma4-26b"
	// maxContextChunks bounds how many retrieved chunks enter the prefill, to
	// keep it under the oMLX memory guard (V2-BRIEF.md: cap ~8).
	maxContextChunks = 8
	// maxChunkChars bounds each chunk's text, mirroring the Python
	// BLKCHAIN_CONTEXT_CHARS_PER_CHUNK default (1200).
	maxChunkChars = 1200
)

// answerSystemPrompt is the SINGLE SOURCE OF TRUTH for the RAG synthesis
// instruction. It mirrors the Python /answer prompt in blkchain/agent.py
// (_synthesize): answer only from the numbered sources, cite [n] inline after
// each claim, treat UNTRUSTED WEB RESULT sources as unverified, and never
// present anything as confirmed beyond what the sources show. Keep this in
// sync with agent.py if that prompt changes.
const answerSystemPrompt = "Answer the question using ONLY the numbered sources below. " +
	"Cite the source number inline in brackets (e.g. [1]) after every claim you draw from it. " +
	"If a source is marked UNTRUSTED WEB RESULT, treat it as unverified and say so when you rely on it. " +
	"State only what the sources support; do not present anything as confirmed beyond what they show."

// streamingEnabled reports whether the RAG streaming path should be used. Per
// V2-BRIEF.md the presence of OMLX_API_KEY is the single switch: unset means
// fall back to the non-streaming client.Answer path so ask always works.
func streamingEnabled() bool {
	return strings.TrimSpace(os.Getenv("OMLX_API_KEY")) != ""
}

// omlxBaseURL resolves the oMLX base URL from OMLX_BASE_URL, else the default.
func omlxBaseURL() string {
	if v := strings.TrimSpace(os.Getenv("OMLX_BASE_URL")); v != "" {
		return v
	}
	return defaultOMLXBaseURL
}

// capRunes truncates s to at most n runes (no ellipsis), mirroring the Python
// context slice. It is byte-safe on multi-byte UTF-8.
func capRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// boundChunks caps the retrieved results to maxContextChunks and truncates each
// chunk's text to maxChunkChars, so the prefill stays bounded (V2-BRIEF.md).
func boundChunks(results []client.SearchResult) []client.SearchResult {
	if len(results) > maxContextChunks {
		results = results[:maxContextChunks]
	}
	out := make([]client.SearchResult, len(results))
	for i, r := range results {
		r.Payload.Text = capRunes(r.Payload.Text, maxChunkChars)
		out[i] = r
	}
	return out
}

// buildContext renders the numbered context blocks the operator message carries.
// It mirrors _format_context in agent.py: one "[i] (tag) source=.. path=..
// section=..\n<text>" block per chunk, joined by blank lines. A "web" source
// is tagged UNTRUSTED WEB RESULT; everything else is the local knowledge base.
func buildContext(chunks []client.SearchResult) string {
	blocks := make([]string, 0, len(chunks))
	for i, r := range chunks {
		tag := "local knowledge base"
		if r.Payload.Source == "web" {
			tag = "UNTRUSTED WEB RESULT"
		}
		header := fmt.Sprintf("[%d] (%s) source=%s path=%s section=%s",
			i+1, tag, r.Payload.Source, r.Payload.Path, r.Payload.Section)
		blocks = append(blocks, header+"\n"+r.Payload.Text)
	}
	return strings.Join(blocks, "\n\n")
}

// buildUserPrompt renders the operator turn: the question plus the numbered
// sources, mirroring the Python /answer user prompt body.
func buildUserPrompt(question string, chunks []client.SearchResult) string {
	return fmt.Sprintf("Question: %s\n\nSources:\n%s\n\nAnswer:", question, buildContext(chunks))
}

// buildMessages assembles the system+user message pair for GenerateContent. It
// is pure so the prompt/context construction can be unit tested.
func buildMessages(question string, chunks []client.SearchResult) []llms.MessageContent {
	return []llms.MessageContent{
		llms.TextParts(llms.ChatMessageTypeSystem, answerSystemPrompt),
		llms.TextParts(llms.ChatMessageTypeHuman, buildUserPrompt(question, chunks)),
	}
}

// deriveCitations turns the retrieved chunks into the citation list the SOURCES
// block renders, deduped by (source, path, section) with order preserved. This
// mirrors the Python citation shape (client.Citation).
func deriveCitations(chunks []client.SearchResult) []client.Citation {
	var cits []client.Citation
	seen := map[[3]string]bool{}
	for _, r := range chunks {
		key := [3]string{r.Payload.Source, r.Payload.Path, r.Payload.Section}
		if seen[key] {
			continue
		}
		seen[key] = true
		cits = append(cits, client.Citation{
			Source:  r.Payload.Source,
			Path:    r.Payload.Path,
			Section: r.Payload.Section,
		})
	}
	return cits
}

// resolveModel picks the oMLX model: OMLX_MODEL, else the first id discovered
// via GET {base}/models, else the built-in default.
func resolveModel(baseURL, apiKey string) string {
	if v := strings.TrimSpace(os.Getenv("OMLX_MODEL")); v != "" {
		return v
	}
	if id := discoverModel(baseURL, apiKey); id != "" {
		return id
	}
	return defaultOMLXModel
}

// discoverModel queries GET {baseURL}/models and returns the first model id, or
// "" on any failure (the caller then uses the default).
func discoverModel(baseURL, apiKey string) string {
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(baseURL, "/")+"/models", nil)
	if err != nil {
		return ""
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	hc := &http.Client{Timeout: 5 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var out struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return ""
	}
	if len(out.Data) > 0 {
		return out.Data[0].ID
	}
	return ""
}

// newOMLX builds the LangChainGo OpenAI client pointed at oMLX.
func newOMLX() (*openai.LLM, error) {
	base := omlxBaseURL()
	key := strings.TrimSpace(os.Getenv("OMLX_API_KEY"))
	model := resolveModel(base, key)
	return openai.New(
		openai.WithBaseURL(base),
		openai.WithToken(key),
		openai.WithModel(model),
	)
}

// StreamRAG retrieves context via the existing blkChain search API (reusing the
// caller's real client), then streams a cited synthesis directly from oMLX. It
// calls onChunk for every streamed token slice and returns the full answer, the
// citations derived from the retrieved chunks, and any error. ctx cancels the
// stream: when ctx is done the streaming callback returns ctx.Err(), which
// aborts GenerateContent (Ctrl-C in the TUI).
//
// model overrides the oMLX model for this turn when non-empty (from the /model
// picker); "" uses the resolved default. reasoning is tracked for the status
// line and session record but is NOT sent to oMLX: langchaingo v0.1.13 exposes no
// reasoning_effort call option, so RAG reasoning selection is display-only.
// preface, when non-empty, is extra context (@file attachments, /init ambient
// context) prepended to the human message; the retrieval query stays the clean
// question. It returns the completion-token count when the model reports usage
// (0 otherwise), for the /cost footer.
func StreamRAG(ctx context.Context, c *client.Client, question, preface, model, reasoning string, onChunk func([]byte)) (string, []client.Citation, int, error) {
	_ = reasoning // display-only in RAG mode (see doc comment)
	resp, err := c.Search(question, 0, nil)
	if err != nil {
		return "", nil, 0, err
	}
	chunks := boundChunks(resp.Results)
	if len(chunks) == 0 {
		return "", nil, 0, fmt.Errorf("no sources found for %q", question)
	}

	msgs := buildMessages(question, chunks)
	if strings.TrimSpace(preface) != "" {
		human := "Additional context:\n" + preface + "\n\n" + buildUserPrompt(question, chunks)
		msgs = []llms.MessageContent{
			llms.TextParts(llms.ChatMessageTypeSystem, answerSystemPrompt),
			llms.TextParts(llms.ChatMessageTypeHuman, human),
		}
	}
	citations := deriveCitations(chunks)

	l, err := newOMLX()
	if err != nil {
		return "", citations, 0, err
	}

	var full strings.Builder
	stream := func(_ context.Context, chunk []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		full.Write(chunk)
		if onChunk != nil {
			onChunk(chunk)
		}
		return nil
	}

	opts := []llms.CallOption{
		llms.WithStreamingFunc(stream),
		llms.WithTemperature(0.2),
	}
	if strings.TrimSpace(model) != "" {
		opts = append(opts, llms.WithModel(model))
	}
	cr, err := l.GenerateContent(ctx, msgs, opts...)
	return full.String(), citations, completionTokens(cr), err
}

// completionTokens extracts the completion-token count from a langchaingo
// response's GenerationInfo when the model reported it (0 otherwise; streaming
// responses often omit usage).
func completionTokens(cr *llms.ContentResponse) int {
	if cr == nil {
		return 0
	}
	for _, ch := range cr.Choices {
		if ch == nil || ch.GenerationInfo == nil {
			continue
		}
		for _, k := range []string{"CompletionTokens", "completion_tokens", "OutputTokens"} {
			if v, ok := ch.GenerationInfo[k]; ok {
				if n := asInt(v); n > 0 {
					return n
				}
			}
		}
	}
	return 0
}

// asInt coerces the numeric shapes GenerationInfo may hold into an int.
func asInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	default:
		return 0
	}
}

// omlxModels queries GET {base}/models and returns every model id, or nil on any
// failure. It seeds the RAG-mode model picker (V2-BRIEF.md T4).
func omlxModels() []string {
	base := omlxBaseURL()
	key := strings.TrimSpace(os.Getenv("OMLX_API_KEY"))
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(base, "/")+"/models", nil)
	if err != nil {
		return nil
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	hc := &http.Client{Timeout: 5 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var out struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil
	}
	ids := make([]string, 0, len(out.Data))
	for _, d := range out.Data {
		if d.ID != "" {
			ids = append(ids, d.ID)
		}
	}
	return ids
}
