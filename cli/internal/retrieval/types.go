// Package retrieval is the Go-native hybrid retrieval engine for blkChain,
// replacing the Python /search and /answer HTTP calls with direct Qdrant and
// embed_server access.
package retrieval

// Payload describes a search result's underlying document chunk. It mirrors
// cli/internal/client.Payload field-for-field so a later adapter is trivial.
type Payload struct {
	Source  string `json:"source"`
	Path    string `json:"path"`
	Section string `json:"section"`
	Type    string `json:"type"`
	Text    string `json:"text"`
}

// Result is a single ranked retrieval result. It mirrors
// cli/internal/client.SearchResult field-for-field so a later adapter is
// trivial.
type Result struct {
	ID      string  `json:"id"`
	Score   float64 `json:"score"`
	Payload Payload `json:"payload"`
}
