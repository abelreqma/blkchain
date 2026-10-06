package retrieval

import (
	"context"
	"fmt"
	"sort"

	"github.com/qdrant/go-client/qdrant"
)

// sourceFacetLimit caps how many distinct sources SourceCounts asks Qdrant
// for. It is a variable only so a test can lower it.
var sourceFacetLimit = 10000

// SourceCount is one indexed source and the number of chunks it holds.
type SourceCount struct {
	Source string
	Count  int
}

// SourceCounts lists each distinct "source" payload value in the collection
// with its chunk count, sorted by count descending then name. It is read-only:
// one exact Facet request on the keyword-indexed source field, so nothing is
// scanned client-side and no vectors or payloads are transferred. The bool is
// true when the source list hit sourceFacetLimit and may be missing sources.
// Points with no string source are not counted. A dead Qdrant yields an error
// wrapping ErrUnreachable; other failures (such as a missing collection) are
// returned as they are.
func (c *Client) SourceCounts(ctx context.Context) ([]SourceCount, bool, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.cfg.RequestTimeout())
		defer cancel()
	}
	hits, err := c.qc.Facet(ctx, &qdrant.FacetCounts{
		CollectionName: c.collection,
		Key:            "source",
		Limit:          qdrant.PtrOf(uint64(sourceFacetLimit)),
		Exact:          qdrant.PtrOf(true),
	})
	if err != nil {
		if unreachable(err) {
			return nil, false, fmt.Errorf("%w: qdrant: %v", ErrUnreachable, err)
		}
		return nil, false, fmt.Errorf("listing sources: %w", err)
	}
	out := make([]SourceCount, 0, len(hits))
	for _, h := range hits {
		s := h.GetValue().GetStringValue()
		if s == "" {
			continue
		}
		out = append(out, SourceCount{Source: s, Count: int(h.GetCount())})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Source < out[j].Source
	})
	return out, len(hits) >= sourceFacetLimit, nil
}
