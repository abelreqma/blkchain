package retrieval

import (
	"fmt"
	"sort"

	"github.com/qdrant/go-client/qdrant"
)

// buildHybridQuery builds a Qdrant QueryPoints request for hybrid dense+sparse
// retrieval fused with native RRF: one prefetch leg on the dense vector, one
// prefetch leg on the server-computed BM25 sparse vector, fused by RRF, with
// payload included. It is a pure function returning the request struct so it
// is unit-testable without a live Qdrant server.
func buildHybridQuery(collection, denseName, sparseName, sparseModel, query string,
	dense []float32, filter map[string]any, pool int) *qdrant.QueryPoints {
	poolLimit := qdrant.PtrOf(uint64(pool))
	return &qdrant.QueryPoints{
		CollectionName: collection,
		Prefetch: []*qdrant.PrefetchQuery{
			{
				Query:  qdrant.NewQueryDense(dense),
				Using:  qdrant.PtrOf(denseName),
				Limit:  poolLimit,
				Filter: buildFilter(filter),
			},
			{
				Query: qdrant.NewQueryNearest(qdrant.NewVectorInputDocument(
					&qdrant.Document{Model: sparseModel, Text: query})),
				Using:  qdrant.PtrOf(sparseName),
				Limit:  poolLimit,
				Filter: buildFilter(filter),
			},
		},
		Query:       qdrant.NewQueryRRF(&qdrant.Rrf{}),
		Limit:       qdrant.PtrOf(uint64(pool)),
		WithPayload: qdrant.NewWithPayload(true),
		Filter:      buildFilter(filter),
	}
}

// buildFilter translates a simple {field: value} map into a Qdrant Filter of
// must-match keyword conditions, mirroring the Python single-valued payload
// filter in blkchain/api.py's _build_filter. Returns nil for an empty or nil
// map so an unfiltered query carries no Filter.
func buildFilter(filter map[string]any) *qdrant.Filter {
	if len(filter) == 0 {
		return nil
	}
	fields := make([]string, 0, len(filter))
	for field := range filter {
		fields = append(fields, field)
	}
	sort.Strings(fields)

	must := make([]*qdrant.Condition, 0, len(fields))
	for _, field := range fields {
		must = append(must, qdrant.NewMatch(field, fmt.Sprintf("%v", filter[field])))
	}
	return &qdrant.Filter{Must: must}
}
