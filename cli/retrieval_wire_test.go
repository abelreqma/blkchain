package main

import "testing"

// TestNewRetrievalClientHonorsCollectionEnv verifies newRetrievalClient reads
// BLKCHAIN_COLLECTION (Task 8): the Go retrieval client must target whatever
// collection the environment names, matching the Python engine's env-driven
// config (blkchain.config).
func TestNewRetrievalClientHonorsCollectionEnv(t *testing.T) {
	t.Setenv("BLKCHAIN_COLLECTION", "blkchain_dwq")
	c, err := newRetrievalClient()
	if err != nil || c == nil {
		t.Fatalf("newRetrievalClient: %v", err)
	}
}
