//go:build live

// Live retrieval parity gate (Task 7). Compares Go Search top-k against the
// Python retrieve.kb_search top-k on the same running stack (Qdrant + embed_server),
// requiring high overlap. This is the migration's sparse-parity gate: it proves the
// Go server-side BM25 query is compatible with the index built by client-side
// FastEmbed, so no re-index is required.
//
// Run:
//
//	BLKCHAIN_PARITY_PYTHON=/path/to/.venv/bin/python \
//	BLKCHAIN_PARITY_REPO=/path/to/main/checkout \
//	BLKCHAIN_COLLECTION=blkchain_dwq \
//	go test -tags live ./internal/retrieval/ -run TestLiveParityTopK -v
package retrieval

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strconv"
	"testing"

	"blkchain/cli/internal/ragconfig"
)

var parityQueries = []string{
	"SSRF to cloud metadata",
	"local file inclusion to remote code execution",
	"JWT none algorithm signature bypass",
	"XXE out of band data exfiltration",
	"SQL injection UNION based extraction",
}

const pyParityScript = `import json,sys
from blkchain.retrieve import kb_search
q=sys.argv[1]; k=int(sys.argv[2]); col=sys.argv[3]
print(json.dumps([str(r['id']) for r in kb_search(q, top_k=k, collection=col)]))`

func TestLiveParityTopK(t *testing.T) {
	py := os.Getenv("BLKCHAIN_PARITY_PYTHON")
	repo := os.Getenv("BLKCHAIN_PARITY_REPO")
	if py == "" || repo == "" {
		t.Skip("set BLKCHAIN_PARITY_PYTHON and BLKCHAIN_PARITY_REPO to run the live parity gate")
	}
	collection := os.Getenv("BLKCHAIN_COLLECTION")
	if collection == "" {
		collection = "blkchain"
	}

	cfg := ragconfig.Load()
	rc, err := New(cfg, collection)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const k = 5
	failures := 0
	for _, q := range parityQueries {
		ctx := context.Background()
		results, err := rc.Search(ctx, q, k, nil)
		if err != nil {
			t.Fatalf("Go Search(%q): %v", q, err)
		}
		goIDs := make([]string, 0, len(results))
		for _, r := range results {
			goIDs = append(goIDs, r.ID)
		}
		pyIDs := pythonTopKIDs(t, py, repo, collection, q, k)

		overlap := setOverlap(goIDs, pyIDs)
		t.Logf("query %q: overlap %d/%d\n  go=%v\n  py=%v", q, overlap, k, goIDs, pyIDs)
		if overlap < 4 {
			failures++
			t.Errorf("parity too low for %q: %d/%d overlap", q, overlap, k)
		}
	}
	if failures > 0 {
		t.Fatalf("%d/%d queries below the 4/5 overlap threshold — sparse parity gate FAILED", failures, len(parityQueries))
	}
}

func pythonTopKIDs(t *testing.T, py, repo, collection, query string, k int) []string {
	t.Helper()
	cmd := exec.Command(py, "-c", pyParityScript, query, strconv.Itoa(k), collection)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "BLKCHAIN_COLLECTION="+collection)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("python kb_search(%q): %v (output: %s)", query, err, string(out))
	}
	var ids []string
	if err := json.Unmarshal(out, &ids); err != nil {
		t.Fatalf("decode python ids for %q: %v (raw: %s)", query, err, string(out))
	}
	return ids
}

func setOverlap(a, b []string) int {
	set := make(map[string]bool, len(a))
	for _, x := range a {
		set[x] = true
	}
	n := 0
	for _, y := range b {
		if set[y] {
			n++
		}
	}
	return n
}
