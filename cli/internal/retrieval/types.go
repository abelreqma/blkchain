// Package retrieval is blkChain's hybrid retrieval engine: it queries Qdrant and
// embed_server directly.
package retrieval

// Payload describes a search result's underlying document chunk. Its JSON is
// the payload blk search --json and blk ask --json print.
type Payload struct {
	Source  string `json:"source"`
	Path    string `json:"path"`
	Section string `json:"section"`
	Type    string `json:"type"`
	Text    string `json:"text"`
	// CWEClass is the indexer's concept tag, such as "sqli"; "" when absent.
	CWEClass string `json:"cwe_class"`
}

// Result is a single ranked retrieval result.
type Result struct {
	ID      string  `json:"id"`
	Score   float64 `json:"score"`
	Payload Payload `json:"payload"`
}
