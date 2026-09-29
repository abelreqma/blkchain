// Package client holds the shared result, citation, answer, and health types
// used by the blk CLI and its JSON output.
package client

// HealthResponse is the response body of GET /health. The API reports not just
// its own liveness but whether each dependency answered, so a caller can tell
// "up" from "up but /search would 500". LLM is set only by the native Go probe
// (the Python API does not report it) and is omitted from JSON when false, so
// the documented /health wire fields are unchanged.
type HealthResponse struct {
	Status      string `json:"status"`
	Qdrant      bool   `json:"qdrant"`
	EmbedServer bool   `json:"embed_server"`
	LLM         bool   `json:"llm,omitempty"`
}

// Payload describes a search result's underlying document chunk.
type Payload struct {
	Source  string `json:"source"`
	Path    string `json:"path"`
	Section string `json:"section"`
	Type    string `json:"type"`
	Text    string `json:"text"`
}

// SearchResult is a single ranked result from POST /search.
type SearchResult struct {
	ID      string  `json:"id"`
	Score   float64 `json:"score"`
	Payload Payload `json:"payload"`
}

// SearchResponse is the response body of POST /search.
type SearchResponse struct {
	Results []SearchResult `json:"results"`
}

// Citation is a single source citation for a RAG answer.
type Citation struct {
	Source  string `json:"source"`
	Path    string `json:"path"`
	Section string `json:"section"`
}

// AnswerResponse mirrors the shape of a RAG answer loop's output. Results
// carries the retrieved chunks the answer was synthesized from, so callers
// can show the evidence behind an answer, not just the citation list.
type AnswerResponse struct {
	Answer    string         `json:"answer"`
	Citations []Citation     `json:"citations"`
	UsedWeb   bool           `json:"used_web"`
	Results   []SearchResult `json:"results,omitempty"`
}
