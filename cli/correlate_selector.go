package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/promptguard"
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"

	"github.com/tmc/langchaingo/llms"
)

// MinCitationScore is the reranker-score floor a kb_search top hit must clear to
// ground a candidate. 0 disables the score floor, leaving product/technique
// specificity (acceptCitation's `term` gate) as the sole scale-free control; it
// is a tunable being calibrated on the live corpus with the LLM-stack test
// session, so a keyword-adjacent low-score hit can also be rejected by score once
// the live distribution is known. It is never raised to a value that would reject
// real product-specific hits.
const MinCitationScore = 0.0

// citationTerm returns the distinctive lowercased token a grounding hit must
// mention to be specific to this subject: the first whitespace token of the
// product/technique name (e.g. "OpenSSH" -> "openssh", "Apache httpd" ->
// "apache"). "" means no specificity requirement (the caller gates by score
// alone, used for the deterministic logic-gap technique domains).
// citationTerm returns the FULL product/subject phrase (lowercased), which
// citationMentions then requires as ALL tokens on word boundaries. Keeping the
// full phrase - rather than the first token alone - is what rejects a sibling in
// the same vendor namespace: "Apache httpd" needs both "apache" AND "httpd", so
// an Apache Tomcat page (apache, no httpd) is rejected, and an IIS page (no
// apache) is rejected too - the vendor token distinguishes cross-vendor while the
// product token distinguishes within-vendor. First-token-only ("apache") was the
// bug; the vendor word alone must never ground. (Live-corpus validated: real
// product exploit pages carry both the vendor and the product word; too-strict
// cases fail safe to a coverage-gap, never a false ground. A generic 3rd suffix
// token like "server" is the one case that could over-restrict; drop it only if
// a real coverage gap appears.)
func citationTerm(subject string) string {
	return strings.Join(strings.Fields(strings.ToLower(subject)), " ")
}

// citationMentions reports whether the distinctive term appears anywhere in a
// result's source/path/section/text, so a loose/keyword-adjacent hit that does
// not actually name the subject is rejected (no false grounding).
func citationMentions(p retrieval.Payload, term string) bool {
	hay := strings.ToLower(p.Source + " " + p.Path + " " + p.Section + " " + p.Text)
	toks := strings.Fields(strings.ToLower(term))
	if len(toks) == 0 {
		return false
	}
	// EVERY token of the subject phrase must appear as a WORD-BOUNDARY match, not
	// a bare substring: substring matching grounds a short term like "idor" on
	// "corridor" (superstring) and the vendor token on a sibling product. Requiring
	// all tokens on word boundaries rejects both.
	for _, tok := range toks {
		if !wordBoundaryContains(hay, tok) {
			return false
		}
	}
	return true
}

// wordBoundaryContains reports whether tok occurs in hay delimited by non-word
// bytes on both sides (ASCII word chars are [A-Za-z0-9_]). Both are expected
// lowercased. It avoids a per-call regex compile in the top-K scan.
func wordBoundaryContains(hay, tok string) bool {
	if tok == "" {
		return false
	}
	for start := 0; ; {
		i := strings.Index(hay[start:], tok)
		if i < 0 {
			return false
		}
		i += start
		beforeOK := i == 0 || !isWordByte(hay[i-1])
		afterOK := i+len(tok) >= len(hay) || !isWordByte(hay[i+len(tok)])
		if beforeOK && afterOK {
			return true
		}
		start = i + 1
	}
}

// isWordByte reports whether b is an ASCII word byte ([A-Za-z0-9_]).
func isWordByte(b byte) bool {
	return b == '_' ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9')
}

func acceptCitation(results []retrieval.Result, term string) (engagement.Citation, bool) {
	cit, _, ok := acceptCitationAt(results, term)
	return cit, ok
}

// acceptCitationAt is acceptCitation plus the index of the accepted result, -1
// when none grounds. A Citation names only source/path/section, which every chunk
// of one corpus section shares, so the index is the only unambiguous handle on the
// chunk that actually grounded; a caller feeding the accepted chunk's body to a
// prompt must key on it rather than re-matching the citation fields.
func acceptCitationAt(results []retrieval.Result, term string) (engagement.Citation, int, bool) {
	term = strings.ToLower(strings.TrimSpace(term))
	for i, r := range results {
		if r.Score < MinCitationScore {
			continue
		}
		if term != "" && !citationMentions(r.Payload, term) {
			continue
		}
		return engagement.Citation{
			Source:   r.Payload.Source,
			Path:     r.Payload.Path,
			Section:  r.Payload.Section,
			CWEClass: r.Payload.CWEClass,
			Origin:   "trusted",
		}, i, true
	}
	return engagement.Citation{}, -1, false
}

// groundCitation runs one read-only kb_search for query and returns an accepted,
// subject-specific citation (see acceptCitation) or ok=false. It is the
// grounding primitive for the deterministic logic-gap detectors (which have no
// model label); the service selector inlines the same acceptCitation gate so it
// can reuse the fetched results for the technique-label prompt.
func groundCitation(ctx context.Context, rc searcher, cfg ragconfig.Config, query, term string) (engagement.Citation, bool) {
	if rc == nil || ctx.Err() != nil {
		return engagement.Citation{}, false
	}
	results, err := rc.Search(ctx, query, cfg.TopK, nil)
	if err != nil {
		return engagement.Citation{}, false
	}
	return acceptCitation(results, term)
}

// maxEpisodeHints bounds how many advisory "prior episode" lines the read-hint
// may add to the selection prompt, regardless of how many the hint returns.
const maxEpisodeHints = 3

// priorEpisodeHint, when non-nil, returns advisory "what worked" notes for a
// discovered service, drawn from episodic technique memory (episodic.go). It is
// NON-BINDING reference text only: it enriches the technique-label prompt that
// already asks solely for a label (never a command), never changes whether a
// candidate exists, is never executed, and never touches the deterministic
// ladders, gate, backstop, or saturation. nil (the default, and the only value
// in a standalone build) leaves selection behavior byte-for-byte unchanged, and
// it is consulted only on the path that already makes a model call, so the
// fail-closed empty-corpus path is untouched. episodic.go installs it at
// activation; the stored text it surfaces is untrusted.
var priorEpisodeHint func(svc Service) []string

// exploitSelectPrompt asks for a single, zero-nesting JSON object naming only
// the technique (not a command).
const exploitSelectPrompt = "You are prioritizing the next offensive technique for ONE discovered network service " +
	"in a scoped penetration test. Choose the technique or CVE family that best matches the observed product, version, " +
	"and service evidence, grounded in the corpus notes below. Prefer a path with concrete prerequisites and a testable " +
	"impact over a generic vulnerability association. Respond with ONLY one JSON object, " +
	"no prose, exactly: {\"technique\": \"<short technique or CVE-family name>\"}. If the corpus notes are unrelated " +
	"to this product or describe no exploitable weakness for it at all, respond with {\"technique\": \"\"} (empty) " +
	"rather than guessing - an empty technique is correct for a benign service with no applicable exploit. Output " +
	"only the technique name, never a command; the harness owns the actual exploit task.\n\n" +
	"Service: %s %s (port %d)\n\nCorpus notes (reference only):\n%s\n\n" + promptguard.UntrustedInputClause

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

// exploitSelector advises a technique label plus its structured corpus citation
// for one service. An empty technique means "use the catalog's own label"; the
// citation is then empty too.
type exploitSelector func(ctx context.Context, svc Service) (technique string, citation engagement.Citation)

// selectResult is one cached (technique, citation) pair.
type selectResult struct {
	tech     string
	citation engagement.Citation
}

// newKBExploitSelector builds the corpus-driven technique advisor: one read-only
// kb_search over the product+version, then one deterministic (temperature 0)
// model call for the label. It caches per normalized product so a repeated
// service does not re-query, and fails closed (empty result) on any error - nil
// deps, corpus miss, model error, or parse failure.
func newKBExploitSelector(m toolLoopModel, rc searcher, cfg ragconfig.Config) exploitSelector {
	cache := map[string]selectResult{}
	var mu sync.Mutex
	return func(ctx context.Context, svc Service) (string, engagement.Citation) {
		if m == nil || rc == nil {
			return "", engagement.Citation{}
		}
		key := strings.ToLower(strings.TrimSpace(svc.Product))
		if key == "" {
			return "", engagement.Citation{}
		}
		mu.Lock()
		if v, ok := cache[key]; ok {
			mu.Unlock()
			return v.tech, v.citation
		}
		mu.Unlock()

		tech, cit := computeExploitSelection(ctx, m, rc, cfg, svc)

		mu.Lock()
		cache[key] = selectResult{tech: tech, citation: cit}
		mu.Unlock()
		return tech, cit
	}
}

// computeExploitSelection runs the read-only corpus consult and the model pick.
// The citation is the top result's source pointer; the selector only consults the
// LOCAL corpus (never web), so its origin is always "trusted".
func computeExploitSelection(ctx context.Context, m toolLoopModel, rc searcher, cfg ragconfig.Config, svc Service) (string, engagement.Citation) {
	if err := ctx.Err(); err != nil {
		return "", engagement.Citation{}
	}
	// Two retrieval queries - version-bearing first, then version-free - merged and
	// de-duplicated by result id. The version token helps retrieval for a product
	// whose exploit page names the version (GitLab 11.4.7) and hurts it for one whose
	// page omits it (Elasticsearch 1.4.2), so scanning the union surfaces the real
	// exploit page in either case. Both queries use generic technique vocabulary,
	// never a product-specific hint, so detection stays corpus-grounded rather than
	// catalog-driven.
	var results []retrieval.Result
	seen := map[string]bool{}
	for _, q := range buildExploitQueries(svc) {
		rs, err := rc.Search(ctx, q, cfg.TopK, nil)
		if err != nil {
			continue
		}
		for _, r := range rs {
			if r.ID != "" && seen[r.ID] {
				continue
			}
			if r.ID != "" {
				seen[r.ID] = true
			}
			results = append(results, r)
		}
	}
	if len(results) == 0 {
		return "", engagement.Citation{}
	}
	// Grounding is decided IN CODE by acceptCitation over the union (product-specific
	// hit + score), never by the model: a keyword-adjacent hit from a loose query does
	// not ground (no false grounding). The union keeps query order rather than a
	// merged score order, because reranker scores are query-conditional and so are
	// not comparable across the two queries; the version-bearing query is issued
	// first, so its product-specific hits ground ahead of the version-free query's.
	cit, accepted, ok := acceptCitationAt(results, citationTerm(svc.Product))
	if !ok {
		return "", engagement.Citation{}
	}
	// The notes feature the BODY of the accepted, product-specific hit, not just the
	// first line of the top few results. A chunk filed under a pivot service (the
	// GitLab 11.4.7 RCE lives under "Pentesting Redis") has an on-topic body under an
	// off-topic heading; feeding headings alone made the model abstain on a
	// correctly-grounded citation.
	var notes strings.Builder
	notes.WriteString(exploitNotes(results, accepted))
	// Advisory, non-binding: surface prior successful episodes for this service as
	// reference-only lines. Bounded in code; the label the model returns is still
	// parsed and owned by correlateService, so this never changes the candidate.
	if priorEpisodeHint != nil {
		n := 0
		for _, line := range priorEpisodeHint(svc) {
			if n >= maxEpisodeHints {
				break
			}
			line = firstLine(strings.TrimSpace(line))
			if line == "" {
				continue
			}
			notes.WriteString("- [prior episode, advisory] " + line + "\n")
			n++
		}
	}
	prompt := fmt.Sprintf(exploitSelectPrompt, svc.Product, svc.Version, svc.Port, notes.String())
	msgs := []llms.MessageContent{llms.TextParts(llms.ChatMessageTypeHuman, prompt)}
	cr, err := m.GenerateContent(ctx, msgs,
		llms.WithTemperature(cfg.GradeTemperature),
		llms.WithMaxTokens(cfg.GradeMaxTokens),
	)
	if err != nil || cr == nil || len(cr.Choices) == 0 {
		// The citation is already code-accepted; the model label is advisory, so a
		// model error still grounds (empty technique label) rather than dropping an
		// accepted citation. A caller that requires a technique (the non-catalog
		// Path 2) treats an empty technique as no candidate.
		return "", cit
	}
	// tech may be "" (the model judged the service benign). The accepted citation
	// still grounds a deterministic (catalog) detector match; the non-catalog path
	// requires a non-empty technique, so it reads "" as no candidate.
	return parseExploitSelection(cr.Choices[0].Content), cit
}

// buildExploitQueries returns the retrieval queries for a discovered service: a
// version-bearing query first, then a version-free one (the version-free query
// alone when the service has no version). See computeExploitSelection for why both
// are issued. The suffix is generic technique vocabulary, never a product-specific
// hint, so detection stays corpus-grounded rather than catalog-driven.
func buildExploitQueries(svc Service) []string {
	const suffix = "exploit vulnerability CVE"
	product := strings.TrimSpace(svc.Product)
	var queries []string
	if v := strings.TrimSpace(svc.Version); v != "" {
		queries = append(queries, strings.TrimSpace(product+" "+v+" "+suffix))
	}
	queries = append(queries, strings.TrimSpace(product+" "+suffix))
	return queries
}

// maxNoteLine bounds one rendered notes line, matching firstLine's cap.
const maxNoteLine = 200

// exploitNotes renders the corpus notes for the prompt: up to four body lines of
// the accepted hit, then one heading line from each of up to four other results,
// so the notes carry the accepted citation's detail without losing the breadth of
// sibling techniques. accepted is the index acceptCitationAt returned, or -1.
func exploitNotes(results []retrieval.Result, accepted int) string {
	var b strings.Builder
	if accepted >= 0 && accepted < len(results) {
		for _, ln := range noteLines(results[accepted].Payload.Text, 4) {
			b.WriteString("- " + ln + "\n")
		}
	}
	n := 0
	for i := range results {
		if i == accepted {
			continue
		}
		lines := noteLines(results[i].Payload.Text, 1)
		if len(lines) == 0 {
			continue
		}
		b.WriteString("- " + lines[0] + "\n")
		n++
		if n >= 4 {
			break
		}
	}
	return b.String()
}

// noteLines returns up to n substantive lines of text, skipping blank lines and
// bare code fences so a heading is followed by the actual exploit prose. Each line
// is truncated to maxNoteLine, since corpus text is untrusted and unbounded.
func noteLines(text string, n int) []string {
	var out []string
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "```") {
			continue
		}
		if len(ln) > maxNoteLine {
			ln = ln[:maxNoteLine]
		}
		out = append(out, ln)
		if len(out) >= n {
			break
		}
	}
	return out
}
