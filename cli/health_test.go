package main

import (
	"testing"

	"blkchain/cli/internal/ragconfig"
)

// TestProbeHealthEmbedDown verifies probeHealth never panics and reports both
// dependencies down when nothing is listening on either port (Task 16).
func TestProbeHealthEmbedDown(t *testing.T) {
	cfg := ragconfig.Config{QdrantGRPCURL: "127.0.0.1:6399", EmbedServerURL: "http://127.0.0.1:8199"}
	q, e := probeHealth(cfg)
	if q || e {
		t.Fatalf("both should be false when nothing is up: q=%v e=%v", q, e)
	}
}
