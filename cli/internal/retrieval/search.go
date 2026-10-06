package retrieval

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"

	"github.com/qdrant/go-client/qdrant"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"blkchain/cli/internal/ragconfig"
)

// defaultQdrantPort is used when cfg.QdrantGRPCURL carries no port.
const defaultQdrantPort = 6334

// ErrUnreachable indicates the retrieval backend (embed_server or Qdrant)
// could not be reached at all. Its text says how to fix that.
var ErrUnreachable = errors.New("blkChain retrieval services are not reachable, start them with `blk up`")

// unreachable reports whether a Qdrant error is a transport failure, so the
// service could not be reached at all. A request the service answered and
// refused, such as one naming a collection that does not exist, is not a
// transport failure: reporting it as one sends the operator to start services
// that are already running.
func unreachable(err error) bool {
	switch status.Code(err) {
	case codes.Unavailable, codes.DeadlineExceeded, codes.Canceled:
		return true
	}
	return false
}

// Client is the hybrid retrieval client: it talks to embed_server (dense
// embeddings and cross-encoder rerank) and Qdrant (hybrid dense+sparse search)
// directly.
type Client struct {
	cfg        ragconfig.Config
	qc         *qdrant.Client
	collection string

	// SkipRerank makes Search skip the cross-encoder and keep the hybrid (RRF)
	// order and scores. The caller decides it; this package reads no settings.
	SkipRerank bool
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
		// One user issues one query at a time, so one connection is enough.
		PoolSize: 1,
	})
	if err != nil {
		return nil, fmt.Errorf("creating qdrant client: %w", err)
	}
	return &Client{cfg: cfg, qc: qc, collection: collection}, nil
}

// Close releases the Qdrant connection. Copies made by the caller share it, so
// Close once, when the process or session that owns the client ends.
func (c *Client) Close() error { return c.qc.Close() }

// Health issues Qdrant's liveness RPC on the client's connection.
func (c *Client) Health(ctx context.Context) error {
	_, err := c.qc.HealthCheck(ctx)
	return err
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
// results sorted by rerank score. With SkipRerank it makes no rerank call and
// returns the top topK in hybrid order with their RRF scores. If topK <= 0,
// cfg.TopK is used. An empty candidate pool is not an error: it returns an
// empty, non-nil slice.
func (c *Client) Search(ctx context.Context, query string, topK int, filter map[string]any) ([]Result, error) {
	if topK <= 0 {
		topK = c.cfg.TopK
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.cfg.RequestTimeout())
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
		if unreachable(err) {
			return nil, fmt.Errorf("%w: qdrant: %v", ErrUnreachable, err)
		}
		return nil, fmt.Errorf("searching collection %q: %w", c.collection, err)
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
				Source:   payloadString(payload, "source"),
				Path:     payloadString(payload, "path"),
				Section:  payloadString(payload, "section"),
				Type:     payloadString(payload, "type"),
				Text:     text,
				CWEClass: payloadString(payload, "cwe_class"),
				Origin:   payloadString(payload, "origin"),
			},
		}
		texts[i] = text
	}
	if c.SkipRerank {
		return results[:min(topK, len(results))], nil
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
