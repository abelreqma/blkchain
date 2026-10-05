package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"blkchain/cli/internal/modeleval"
	"blkchain/cli/internal/promptguard"
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"

	"github.com/tmc/langchaingo/llms"
	"github.com/tmc/langchaingo/llms/cache"
	"github.com/tmc/langchaingo/llms/openai"
)

// llm.go holds the RAG synthesis building blocks shared by AnswerLoop
// (rag.go): prompt construction, the oMLX (OpenAI-compatible) LangChainGo
// client, and citation extraction.

// defaultOMLXBaseURL matches the local oMLX server.
const defaultOMLXBaseURL = "http://127.0.0.1:8000/v1"

// citationRefPattern matches single or comma-separated citation markers.
var citationRefPattern = regexp.MustCompile(`\[(\d+(?:\s*,\s*\d+)*)\]`)

// answerGenericPreamble is the default expert persona; a domain persona
// (personas.go) swaps it for a specialist one. answerConstraints is the shared,
// load-bearing body every persona must carry unchanged (grounding, citations,
// payload generation, no fabricated specifics, and embedded-instruction handling), so
// specializing the persona can never drop or contradict a constraint.
const answerGenericPreamble = "You are a security research assistant for authorized testing. "

const offensiveReasoningStandard = "Reason from the operator's stated scope, vantage, access, target behavior, and available tools. " +
	"Separate observed facts, plausible hypotheses, and untested paths. For a proposed test, state its prerequisite, exact input or command when enough detail is known, expected positive and negative signals, and the next decision each result supports. " +
	"Prefer a small reproducible proof over a broad scan or an assumed exploit chain. Account for current identity, application state, protocol, mitigations, and likely side effects. " +
	"If a crucial target detail is missing, ask for that detail or give a clearly labeled adaptable example; never present guessed hostnames, paths, versions, privileges, or output as observed. " +
	"Distinguish an established weakness from a version-based lead, and describe impact only to the level the evidence proves. "

const answerConstraints = offensiveReasoningStandard + "Write a complete, well-organized " +
	"answer to the question, grounded in the numbered sources below and in any context the user provided (their " +
	"stated target, constraints, and attached project context). Cite the source number inline in brackets " +
	"(e.g. [1]) after each claim you draw from a source. Synthesize the sources into a clear, useful answer and do " +
	"not simply restate them: you may add explanatory detail, structure, and well-established background that the " +
	"sources support. When the question calls for payloads, exploit strings, test inputs, or commands, generate " +
	"concrete, ready-to-use ones adapted to the context the user provided, grounded in and citing the retrieved " +
	"techniques and examples; you may combine and adapt the retrieved payloads. Whenever it helps the user act, " +
	"name the specific tools to use and show concrete example commands or invocations (copy-pasteable), not only " +
	"prose. Do not fabricate CVE identifiers, " +
	"version numbers, or statistics that the sources do not support. " + promptguard.UntrustedInputClause + " " +
	"Treat external web evidence as unverified and say so when you rely on it."

// omlxBaseURL resolves the oMLX base URL from OMLX_BASE_URL, else the default.
func omlxBaseURL() string {
	if v := strings.TrimSpace(os.Getenv("OMLX_BASE_URL")); v != "" {
		return v
	}
	return defaultOMLXBaseURL
}

// capRunes truncates s to at most n runes (no ellipsis). It is byte-safe on
// multi-byte UTF-8.
func capRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// boundChunks caps the retrieved results to cfg.AnswerMaxChunks and truncates
// each chunk's text to cfg.ContextCharsPerChunk runes, so the prefill stays
// bounded (BLKCHAIN_ANSWER_MAX_CHUNKS and BLKCHAIN_CONTEXT_CHARS_PER_CHUNK).
func boundChunks(cfg ragconfig.Config, results []retrieval.Result) []retrieval.Result {
	// A non-positive cap means "no cap": guard so a bad value never indexes
	// results[:negative] or truncates every chunk to empty. ragconfig.Load
	// already validates these, so this only defends a directly-built Config.
	if cfg.AnswerMaxChunks > 0 && len(results) > cfg.AnswerMaxChunks {
		results = results[:cfg.AnswerMaxChunks]
	}
	out := make([]retrieval.Result, len(results))
	for i, r := range results {
		if cfg.ContextCharsPerChunk > 0 {
			r.Payload.Text = capRunes(r.Payload.Text, cfg.ContextCharsPerChunk)
		}
		out[i] = r
	}
	return out
}

// buildContext encodes each retrieved record as JSON so source text cannot
// forge record delimiters or metadata fields in the prompt. Local chunks are
// tagged as trusted corpus evidence; external results are tagged as unverified.
func buildContext(chunks []retrieval.Result) string {
	type evidence struct {
		Number  int    `json:"number"`
		Trust   string `json:"trust"`
		Source  string `json:"source"`
		Path    string `json:"path"`
		Section string `json:"section"`
		Text    string `json:"text"`
	}
	blocks := make([]evidence, 0, len(chunks))
	for i, r := range chunks {
		trust := "trusted_corpus"
		if r.Payload.Source == webSource || r.Payload.Source == nvdSource {
			trust = "unverified_external"
		}
		blocks = append(blocks, evidence{i + 1, trust, r.Payload.Source,
			r.Payload.Path, r.Payload.Section, r.Payload.Text})
	}
	b, _ := json.Marshal(blocks)
	return string(b)
}

// buildUserPrompt renders the operator turn: the question plus the numbered
// sources.
func buildUserPrompt(question string, chunks []retrieval.Result) string {
	questionJSON, _ := json.Marshal(question)
	return fmt.Sprintf("Question (JSON data):\n%s\n\nSources (JSON data):\n%s\n\nAnswer:", questionJSON, buildContext(chunks))
}

// chatType maps a stored history role ("human"/"ai", as the history store and
// langchaingo record them) to its llms.ChatMessageType. An unrecognized role
// falls back to a generic (human) turn so a malformed entry is still carried
// as context rather than dropped silently.
func chatType(role string) llms.ChatMessageType {
	switch role {
	case string(llms.ChatMessageTypeAI):
		return llms.ChatMessageTypeAI
	case string(llms.ChatMessageTypeSystem):
		return llms.ChatMessageTypeSystem
	default:
		return llms.ChatMessageTypeHuman
	}
}

// messagesWithHistory assembles [system, ...history (oldest first), human]. It
// is the shared shape for the grounded (buildMessages) and skip (directAnswer)
// answer paths, so both carry conversation memory identically. Empty history
// reproduces the stateless single-turn prompt.
func messagesWithHistory(systemPrompt string, history []priorTurn, human string) []llms.MessageContent {
	msgs := make([]llms.MessageContent, 0, len(history)+2)
	msgs = append(msgs, llms.TextParts(llms.ChatMessageTypeSystem, systemPrompt))
	for _, t := range history {
		msgs = append(msgs, llms.TextParts(chatType(t.Role), t.Content))
	}
	msgs = append(msgs, llms.TextParts(llms.ChatMessageTypeHuman, human))
	return msgs
}

// buildMessages assembles the grounded-answer message slice: the system prompt,
// any prior conversation turns, then the current question with its sources.
// history is the bounded conversation memory. It is pure so the prompt/context
// and memory construction can be unit tested.
func buildMessages(systemPrompt string, question string, chunks []retrieval.Result, history []priorTurn) []llms.MessageContent {
	return messagesWithHistory(systemPrompt, history, buildUserPrompt(question, chunks))
}

// citationsFromAnswer extracts the citations for the chunks the answer
// actually cited via inline [n] markers (1-based, matching the numbered
// Sources block from buildContext). Cited indices are collected into a set,
// sorted ascending, then mapped to chunks and deduped by (source, path,
// section) with first-seen (i.e. ascending index) order preserved.
// Out-of-range or unparsable indices are ignored. When the answer cites
// nothing (no markers, or all out of range), it falls back to citing every
// retrieved chunk in chunk order.
func citationsFromAnswer(answer string, chunks []retrieval.Result) []citation {
	indexSet := map[int]bool{}
	for _, m := range citationRefPattern.FindAllStringSubmatch(answer, -1) {
		for _, token := range strings.Split(m[1], ",") {
			n, err := strconv.Atoi(strings.TrimSpace(token))
			if err != nil || n < 1 || n > len(chunks) {
				continue
			}
			indexSet[n] = true
		}
	}
	indices := make([]int, 0, len(indexSet))
	for n := range indexSet {
		indices = append(indices, n)
	}
	sort.Ints(indices)

	cited := make([]retrieval.Result, 0, len(indices))
	for _, n := range indices {
		cited = append(cited, chunks[n-1])
	}
	if len(cited) == 0 {
		cited = chunks
	}
	return dedupCitations(cited)
}

// dedupCitations turns a chunk slice into the citation list the SOURCES block
// renders, deduped by (source, path, section) with order preserved.
func dedupCitations(chunks []retrieval.Result) []citation {
	var cits []citation
	seen := map[[3]string]bool{}
	for _, r := range chunks {
		key := [3]string{r.Payload.Source, r.Payload.Path, r.Payload.Section}
		if seen[key] {
			continue
		}
		seen[key] = true
		cits = append(cits, citation{
			Source:    r.Payload.Source,
			Path:      r.Payload.Path,
			Section:   r.Payload.Section,
			Untrusted: r.Payload.Source == webSource || r.Payload.Source == nvdSource,
		})
	}
	return cits
}

// omlxAPIKey is the LLM server's API key from OMLX_API_KEY, "" when unset.
func omlxAPIKey() string { return strings.TrimSpace(os.Getenv("OMLX_API_KEY")) }

// llmModels lists the LLM server's model ids, bounded by modelsListTimeout.
func llmModels() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), modelsListTimeout)
	defer cancel()
	return modeleval.ListModels(ctx, llmHTTP, omlxBaseURL(), omlxAPIKey())
}

// resolveModel picks the oMLX model when the caller named none: OMLX_MODEL,
// else the first id the server lists (see listedModel), else cfg's
// default_model.
func resolveModel(cfg ragconfig.Config) string {
	if id := listedModel(); id != "" {
		return id
	}
	return cfg.DefaultModel
}

// listedModel is the model a turn uses when none is picked and the server
// answers: OMLX_MODEL, else the first id the server lists. It is "" when
// neither is known. It may call the LLM server.
func listedModel() string {
	if v := strings.TrimSpace(os.Getenv("OMLX_MODEL")); v != "" {
		return v
	}
	if ids, _ := llmModels(); len(ids) > 0 {
		return ids[0]
	}
	return ""
}

// newOMLX builds the LangChainGo OpenAI client pointed at oMLX for model (see
// resolveModel when it is empty), with a custom
// HTTP client whose transport shapes each request and bounds each response
// (see llmTransport).
func newOMLX(cfg ragconfig.Config, model string) (*llmClient, error) {
	return newOMLXFormat(cfg, model, nil)
}

func newOMLXFormat(cfg ragconfig.Config, model string, format *openai.ResponseFormat) (*llmClient, error) {
	base := omlxBaseURL()
	key := omlxAPIKey()
	if strings.TrimSpace(model) == "" {
		model = resolveModel(cfg)
	}
	hc := &http.Client{
		Timeout:   cfg.RequestTimeout(),
		Transport: &llmTransport{base: http.DefaultTransport, keyless: key == ""},
	}
	token := key
	if token == "" {
		// LangChainGo refuses an empty token and falls back to OPENAI_API_KEY.
		// A keyless server gets this placeholder, and llmTransport drops the
		// Authorization header it would carry.
		token = "no-key"
	}
	options := []openai.Option{
		openai.WithBaseURL(base),
		openai.WithToken(token),
		openai.WithModel(model),
		openai.WithHTTPClient(hc),
		openai.WithCallback(usageCallback{}),
	}
	if format != nil {
		options = append(options, openai.WithResponseFormat(format))
	}
	raw, err := openai.New(options...)
	if err != nil {
		return nil, err
	}
	config, err := json.Marshal([]any{base, model, key, format})
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(config)
	return &llmClient{raw: raw, cached: cache.New(raw, sharedDecisions), cfg: cfg, model: model, namespace: hex.EncodeToString(sum[:])}, nil
}

const (
	// llmMaxBodyBytes caps a successful LLM response body. An answer is bounded
	// by the token caps, so this only stops a misbehaving server.
	llmMaxBodyBytes = 32 << 20
	// llmMaxErrorBodyBytes caps a failed response's body, whose message
	// LangChainGo quotes in the error that reaches the terminal.
	llmMaxErrorBodyBytes = 512
)

// samplingKey is the context key for the answer call's sampling settings.
type samplingKey struct{}

// sampling holds the answer sampling settings LangChainGo v0.1.13 drops from
// the request body: it never copies top_p into the request and has no top_k
// field. oMLX honors both as top-level fields. Zero means the server default.
type sampling struct {
	topP float64
	topK int
}

// withSampling returns ctx carrying cfg's answer sampling settings, for
// llmTransport to add to that one call's body.
func withSampling(ctx context.Context, cfg ragconfig.Config) context.Context {
	return context.WithValue(ctx, samplingKey{}, sampling{topP: cfg.SynthTopP, topK: cfg.SynthTopK})
}

// addTo sets each nonzero setting in body when body lacks that key, so a field
// the library did send is never overwritten. It reports whether body changed.
func (s sampling) addTo(body map[string]any) bool {
	changed := false
	add := func(key string, v any, set bool) {
		if _, ok := body[key]; set && !ok {
			body[key] = v
			changed = true
		}
	}
	add("top_p", s.topP, s.topP != 0)
	add("top_k", s.topK, s.topK != 0)
	return changed
}

// llmTransport is the LLM client's transport. On POST /chat/completions it
// injects top-level chat_template_kwargs.enable_thinking=false, which oMLX
// honors to turn off the model's reasoning channel (it otherwise loops on
// constrained prompts and returns empty content); LangChainGo has no option for
// it, and BLK_ENABLE_THINKING=1 skips it. When the request context carries
// sampling (see withSampling) it adds those fields too. A body that is not JSON
// passes through unchanged. With keyless set it drops the Authorization
// header. It caps every response body.
type llmTransport struct {
	base    http.RoundTripper
	keyless bool
}

func (t *llmTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone before touching the body, ContentLength, or headers: a RoundTripper
	// must not mutate the caller's request. This was only done on the keyless
	// path, so a keyed request leaked the rewritten body/headers back.
	req = req.Clone(req.Context())
	if t.keyless {
		req.Header.Del("Authorization")
	}
	noThinking := os.Getenv("BLK_ENABLE_THINKING") != "1"
	samp, hasSampling := req.Context().Value(samplingKey{}).(sampling)
	if (noThinking || hasSampling) && req.Body != nil && strings.HasSuffix(req.URL.Path, "/chat/completions") {
		raw, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, err
		}
		var m map[string]any
		if json.Unmarshal(raw, &m) == nil {
			changed := false
			if _, ok := m["chat_template_kwargs"]; noThinking && !ok {
				m["chat_template_kwargs"] = map[string]any{"enable_thinking": false}
				changed = true
			}
			if hasSampling && samp.addTo(m) {
				changed = true
			}
			if changed {
				if b, e := json.Marshal(m); e == nil {
					raw = b
				}
			}
		}
		req.Body = io.NopCloser(strings.NewReader(string(raw)))
		req.ContentLength = int64(len(raw))
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	limit := int64(llmMaxBodyBytes)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		limit = llmMaxErrorBodyBytes
	}
	resp.Body = limitedBody{io.LimitReader(resp.Body, limit), resp.Body}
	return resp, nil
}

// limitedBody reads through a limit and closes the underlying body.
type limitedBody struct {
	io.Reader
	io.Closer
}

// llmUnreachableError is a connection-refused or timeout failure talking to the
// LLM server, carrying the base URL. Unwrap exposes the original network error to
// errors.Is and errors.As. Only a refused connection means the server is down; a
// timeout means the model is slow, so the two get different advice.
type llmUnreachableError struct {
	base    string
	timeout bool
	err     error
}

func (e *llmUnreachableError) Error() string {
	if e.timeout {
		return fmt.Sprintf("LLM request to %s timed out: raise BLKCHAIN_TIMEOUT_SECONDS", e.base)
	}
	return fmt.Sprintf("LLM server at %s did not answer (connection refused): start the LLM server at %s, or set OMLX_BASE_URL", e.base, e.base)
}

func (e *llmUnreachableError) Unwrap() error { return e.err }

// refused reports whether the server refused the connection (it is down), as
// opposed to a timeout.
func (e *llmUnreachableError) refused() bool { return !e.timeout }

// mapLLMError turns a connection-refused or timeout failure from the LLM client
// into a one-line llmUnreachableError naming baseURL. Any other error, and a
// cancellation, is returned unchanged. It matches on the error chain, not text.
func mapLLMError(err error, baseURL string) error {
	if err == nil || errors.Is(err, context.Canceled) {
		return err
	}
	var timeout bool
	var ne net.Error
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		timeout = true
	default:
		return err
	}
	return &llmUnreachableError{base: redactedURL(baseURL), timeout: timeout, err: err}
}

// redactedURL drops the userinfo, query, and fragment of a URL before it is
// shown, since any of them can carry a token. An unparsable URL is not echoed.
func redactedURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "(invalid URL)"
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	u.RawFragment = ""
	return u.String()
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

// errRequestTimeout is the one-line wording for a turn that ran out of time.
var errRequestTimeout = errors.New("request timed out (raise BLKCHAIN_TIMEOUT_SECONDS)")

// timeoutOrErr maps a bare context deadline (a turn that timed out with nothing
// to answer from) to errRequestTimeout. A deadline that already carries its own
// advice (an LLM or unreachable-service error) and every other error, cancel
// included, pass through unchanged. It matches on the error chain, not text.
func timeoutOrErr(err error) error {
	var llmErr *llmUnreachableError
	if errors.Is(err, context.DeadlineExceeded) && !errors.As(err, &llmErr) && !isUnreachable(err) {
		return errRequestTimeout
	}
	return err
}
