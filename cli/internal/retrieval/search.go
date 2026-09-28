package retrieval

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"time"

	"github.com/qdrant/go-client/qdrant"

	"blkchain/cli/internal/ragconfig"
)

// defaultQdrantPort is used when cfg.QdrantGRPCURL carries no port.
const defaultQdrantPort = 6334

// ErrUnreachable indicates the retrieval backend (embed_server or Qdrant)
// could not be reached at all. It mirrors cli/internal/client.UnreachableError's
// hint so callers get the same actionable guidance regardless of which
// engine path served them.
var ErrUnreachable = errors.New("blkChain retrieval services are not reachable — start them with `blk up`")

// Client is a Go-native hybrid retrieval client: it talks to embed_server
// (dense embeddings and cross-encoder rerank) and Qdrant (hybrid dense+sparse
// search) directly, replacing the Python /search HTTP call.
type Client struct {
	cfg        ragconfig.Config
	qc         *qdrant.Client
	collection string
}

// New constructs a Client for the given collection. It does not dial Qdrant
// eagerly: qdrant.NewClient only validates the target and builds a lazy gRPC
// connection, so New succeeds even when the server is unreachable. Failures
// surface later, from Search.
func New(cfg ragconfig.Config, collection string) (*Client, error) {
	host, port := splitHostPort(cfg.QdrantGRPCURL)
	qc, err := qdrant.NewClient(&qdrant.Config{
		Host: host,
		Port: port,
		// Skip the server-version compatibility check, which would otherwise
		// perform an RPC during NewClient and defeat the "no eager dial"
		// contract when the server is down or slow.
		SkipCompatibilityCheck: true,
	})
	if err != nil {
		return nil, fmt.Errorf("creating qdrant client: %w", err)
	}
	return &Client{cfg: cfg, qc: qc, collection: collection}, nil
}

// splitHostPort parses a "host:port" address, defaulting the port to 6334
// when absent so a bare host or an empty string still works.
func splitHostPort(addr string) (string, int) {
	if addr == "" {
		return "127.0.0.1", defaultQdrantPort
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, defaultQdrantPort
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return host, defaultQdrantPort
	}
	return host, port
}

// Search retrieves the top-scoring chunks for query: it embeds the query,
// runs a hybrid dense+sparse RRF query against Qdrant to build a candidate
// pool, reranks that pool with the cross-encoder, and returns the top topK
// results sorted by rerank score. If topK <= 0, cfg.TopK is used. An empty
// candidate pool is not an error: it returns an empty, non-nil slice.
func (c *Client) Search(ctx context.Context, query string, topK int, filter map[string]any) ([]Result, error) {
	if topK <= 0 {
		topK = c.cfg.TopK
	}
	if _, ok := ctx.Deadline(); !ok && c.cfg.RequestTimeoutSeconds > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(c.cfg.RequestTimeoutSeconds)*time.Second)
		defer cancel()
	}

	dense, err := embedQuery(ctx, c.cfg.EmbedServerURL, query)
	if err != nil {
		return nil, fmt.Errorf("%w: embed_server: %v", ErrUnreachable, err)
	}

	req := buildHybridQuery(c.collection, c.cfg.DenseVectorName, c.cfg.SparseVectorName,
		c.cfg.SparseModel, query, dense, filter, c.cfg.PoolSize)
	points, err := c.qc.Query(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("%w: qdrant: %v", ErrUnreachable, err)
	}
	if len(points) == 0 {
		return []Result{}, nil
	}

	results := make([]Result, len(points))
	texts := make([]string, len(points))
	for i, p := range points {
		payload := p.GetPayload()
		text := payloadString(payload, "text")
		results[i] = Result{
			ID:    pointIDString(p.GetId()),
			Score: float64(p.GetScore()),
			Payload: Payload{
				Source:  payloadString(payload, "source"),
				Path:    payloadString(payload, "path"),
				Section: payloadString(payload, "section"),
				Type:    payloadString(payload, "type"),
				Text:    text,
			},
		}
		texts[i] = text
	}

	scores, err := rerank(ctx, c.cfg.EmbedServerURL, query, texts)
	if err != nil {
		return nil, fmt.Errorf("%w: embed_server rerank: %v", ErrUnreachable, err)
	}
	if len(scores) != len(results) {
		return nil, fmt.Errorf("rerank returned %d scores for %d documents", len(scores), len(results))
	}
	for i := range results {
		results[i].Score = scores[i]
	}

	sort.Slice(results, func(i, j int) bool { return results[i].Score > results[j].Score })

	if topK < len(results) {
		results = results[:topK]
	}
	return results, nil
}

// pointIDString renders a Qdrant PointId (either a UUID or a numeric id) to
// its string form.
func pointIDString(id *qdrant.PointId) string {
	if id == nil {
		return ""
	}
	if uuid := id.GetUuid(); uuid != "" {
		return uuid
	}
	return strconv.FormatUint(id.GetNum(), 10)
}

// payloadString reads a string field out of a Qdrant point payload map,
// returning "" if the key is absent or not a string value.
func payloadString(payload map[string]*qdrant.Value, key string) string {
	v, ok := payload[key]
	if !ok || v == nil {
		return ""
	}
	return v.GetStringValue()
}
