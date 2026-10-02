package engagement

import (
	"database/sql"
	"encoding/json"
	"errors"
)

// ReconDimStatus is the coverage status of one recon dimension for an asset.
type ReconDimStatus string

const (
	ReconPending ReconDimStatus = "pending"
	ReconCovered ReconDimStatus = "covered"
)

// valid reports whether d is a known recon dimension status.
func (d ReconDimStatus) valid() bool {
	switch d {
	case ReconPending, ReconCovered:
		return true
	}
	return false
}

// ReconNoveltyThisRev is a sentinel for ReconCoverage.LastNoveltyRev: an upsert
// carrying it has applyLocked stamp the field with the revision this upsert
// commits at. It lets a caller record "this pass produced novelty" in one Delta,
// since the new revision is not known until the Apply runs. Any real revision is
// non-negative, so a negative sentinel can never collide with one.
const ReconNoveltyThisRev int64 = -1

// mergeReconDims returns the union of prev and incoming where ReconCovered wins:
// a dimension covered by either side stays covered. Recon coverage only ever
// advances (pending -> covered), so merging - rather than replacing - lets two
// concurrent writers on the same (surface, asset) row never clobber a dimension
// the other has already covered.
func mergeReconDims(prev, incoming map[string]ReconDimStatus) map[string]ReconDimStatus {
	out := make(map[string]ReconDimStatus, len(prev)+len(incoming))
	for k, v := range prev {
		out[k] = v
	}
	for k, v := range incoming {
		if out[k] == ReconCovered || v == ReconCovered {
			out[k] = ReconCovered
		} else {
			out[k] = v
		}
	}
	return out
}

// ReconCoverage tracks per-asset recon-dimension coverage for the recon-tier
// engine: how far recon has gone on one asset on one surface, and
// which revision last produced new (novel) coverage.
type ReconCoverage struct {
	Surface        Surface
	Asset          string
	Dimensions     map[string]ReconDimStatus
	IterationCount int
	LastNoveltyRev int64
	CreatedRev     int64
	UpdatedRev     int64
}

// marshalReconDims encodes a recon dimension map as a JSON object; nil and
// empty give "{}".
func marshalReconDims(m map[string]ReconDimStatus) string {
	if len(m) == 0 {
		return "{}"
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// unmarshalReconDims decodes a JSON object into a recon dimension map; ""
// and "{}" give an empty (non-nil) map.
func unmarshalReconDims(s string) (map[string]ReconDimStatus, error) {
	if s == "" || s == "{}" {
		return map[string]ReconDimStatus{}, nil
	}
	out := map[string]ReconDimStatus{}
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ReconCoverageFor returns the recon coverage row for one (surface, asset)
// pair. The second return is false, with a zero ReconCoverage and nil error,
// when no row exists.
func (s *Store) ReconCoverageFor(surface Surface, asset string) (ReconCoverage, bool, error) {
	var (
		rc  ReconCoverage
		dim string
	)
	rc.Surface = surface
	rc.Asset = asset
	err := s.db.QueryRow(
		`SELECT dimensions, iteration_count, last_novelty_rev, created_rev, updated_rev
		 FROM recon_coverage WHERE surface = ? AND asset = ?`, string(surface), asset).
		Scan(&dim, &rc.IterationCount, &rc.LastNoveltyRev, &rc.CreatedRev, &rc.UpdatedRev)
	if errors.Is(err, sql.ErrNoRows) {
		return ReconCoverage{}, false, nil
	}
	if err != nil {
		return ReconCoverage{}, false, err
	}
	if rc.Dimensions, err = unmarshalReconDims(dim); err != nil {
		return ReconCoverage{}, false, err
	}
	return rc, true, nil
}

// AllReconCoverage returns every recon coverage row, ordered by created_rev
// ascending, then surface, then asset. It returns a non-nil empty slice when
// there are no rows.
func (s *Store) AllReconCoverage() ([]ReconCoverage, error) {
	rows, err := s.db.Query(
		`SELECT surface, asset, dimensions, iteration_count, last_novelty_rev, created_rev, updated_rev
		 FROM recon_coverage ORDER BY created_rev ASC, surface ASC, asset ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []ReconCoverage{}
	for rows.Next() {
		var (
			rc      ReconCoverage
			surface string
			dim     string
		)
		if err := rows.Scan(&surface, &rc.Asset, &dim, &rc.IterationCount, &rc.LastNoveltyRev, &rc.CreatedRev, &rc.UpdatedRev); err != nil {
			return nil, err
		}
		rc.Surface = Surface(surface)
		if rc.Dimensions, err = unmarshalReconDims(dim); err != nil {
			return nil, err
		}
		out = append(out, rc)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
