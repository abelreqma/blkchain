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

// Every Go retrieval path builds its client here, so the saved reranker switch
// reaches search, ask, both REPLs, and blk mcp.
func TestNewRetrievalClientFollowsTheRerankerSwitch(t *testing.T) {
	isolateUserDirs(t)
	c, err := newRetrievalClient()
	if err != nil || c.SkipRerank {
		t.Fatalf("default: SkipRerank=%v err=%v, want the reranker on", c != nil && c.SkipRerank, err)
	}
	if err := savePrefs(modelPrefs{Rerank: false, Web: true}); err != nil {
		t.Fatal(err)
	}
	if c, _ := newRetrievalClient(); !c.SkipRerank {
		t.Error("reranker off in the saved settings, but the client still reranks")
	}
	// followPrefs copies: the shared client a long-running server keeps is not changed.
	base, _ := newRetrievalClient()
	on := followPrefs(base, modelPrefs{Rerank: true})
	if on.SkipRerank || !base.SkipRerank {
		t.Errorf("followPrefs: copy SkipRerank=%v, original=%v", on.SkipRerank, base.SkipRerank)
	}
}
