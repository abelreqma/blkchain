package retrieval

import (
	"context"
	"errors"
	"testing"

	"blkchain/cli/internal/ragconfig"
)

func TestSearchUnreachableQdrantGivesActionableError(t *testing.T) {
	cfg := ragconfig.Config{QdrantGRPCURL: "127.0.0.1:6399", EmbedServerURL: "http://127.0.0.1:8199", DenseVectorName: "dense", SparseVectorName: "sparse", SparseModel: "qdrant/bm25", PoolSize: 10}
	c, err := New(cfg, "blkchain_dwq")
	if err != nil {
		t.Fatalf("New: %v", err) // New should not dial eagerly
	}
	_, err = c.Search(context.Background(), "ssrf", 5, nil)
	if err == nil || !errors.Is(err, ErrUnreachable) {
		t.Fatalf("want ErrUnreachable, got %v", err)
	}
}
