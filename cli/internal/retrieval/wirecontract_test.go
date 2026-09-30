package retrieval

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

// jsonKeys marshals v and returns its top-level JSON object keys, sorted. A
// renamed or dropped json tag changes this set, so a golden comparison against
// it fails on drift.
func jsonKeys(t *testing.T, v any) []string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %T: %v", v, err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal %T: %v", v, err)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func assertKeys(t *testing.T, name string, v any, want []string) {
	t.Helper()
	sort.Strings(want)
	if got := jsonKeys(t, v); !reflect.DeepEqual(got, want) {
		t.Errorf("%s JSON keys = %v, want %v (cross-language wire drift)", name, got, want)
	}
}

// The Qdrant payload contract: retrieval.Payload's JSON keys are the fields the
// Go client reads back from a Qdrant point. They must match the keys
// blkchain/schema.py Chunk.payload() emits (verified reciprocally by the Python
// test tests/test_contract_binding.py). A rename on either side breaks its own
// golden.
func TestPayloadContractKeys(t *testing.T) {
	assertKeys(t, "Payload", Payload{}, []string{
		"source", "path", "section", "type", "text", "cwe_class",
	})
}

// The embed_server wire contract: the request/response struct keys must match
// blkchain/embed_server.py's JSON (POST /embed {"texts":...} ->
// {"embeddings":..., "dim":...}; POST /rerank {"query":...,"documents":...} ->
// {"scores":...}). The Python side is pinned reciprocally by
// tests/test_contract_binding.py against blkchain/embed_wire.py.
func TestEmbedWireContractKeys(t *testing.T) {
	assertKeys(t, "embedRequest", embedRequest{}, []string{"texts"})
	assertKeys(t, "embedResponse", embedResponse{}, []string{"embeddings", "dim"})
	assertKeys(t, "rerankRequest", rerankRequest{}, []string{"query", "documents"})
	assertKeys(t, "rerankResponse", rerankResponse{}, []string{"scores"})
}
