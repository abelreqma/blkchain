package main

import (
	"blkchain/cli/internal/webanalysis"
	"blkchain/cli/internal/webcollect"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"time"
)

func webScanLibraries(ctx context.Context, s *webcollect.Service) error {
	path := os.Getenv("BLKCHAIN_RETIRE_MANIFEST")
	if path == "" {
		s.Gap("libraries", "", "pinned local Retire advisory snapshot unavailable")
		return s.RecordStage(ctx, "libraries")
	}
	b, e := webReadFile(path, 64<<10)
	if e != nil {
		return e
	}
	var m struct {
		Path     string `json:"path"`
		SHA256   string `json:"sha256"`
		Date     string `json:"date"`
		Revision string `json:"revision"`
	}
	if json.Unmarshal(b, &m) != nil {
		return errors.New("invalid advisory manifest")
	}
	revision, re := hex.DecodeString(m.Revision)
	digest, de := hex.DecodeString(m.SHA256)
	if re != nil || de != nil || len(revision) != 20 || len(digest) != 32 {
		return errors.New("invalid advisory integrity pins")
	}
	if _, e = time.Parse("2006-01-02", m.Date); e != nil || len(m.Revision) != 40 || len(m.SHA256) != 64 {
		return errors.New("advisory manifest requires snapshot date, immutable revision and SHA256")
	}
	repo, e := webReadFile(m.Path, 4<<20)
	if e != nil {
		return e
	}
	if webanalysis.Hash(repo) != m.SHA256 {
		return errors.New("advisory repository integrity mismatch")
	}
	snapshot := webanalysis.AdvisorySnapshot(m.Date, m.Revision, m.SHA256)
	data, e := s.Store.WebSnapshot(ctx)
	if e != nil {
		return e
	}
	for _, u := range data.Units {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		body, e := s.Store.WebBlob(u.Hash)
		if e != nil {
			return e
		}
		findings, gaps, e := webanalysis.ScanRetire(ctx, u, body, repo, snapshot)
		if e != nil {
			return e
		}
		for _, f := range findings {
			if e = s.Store.PutWeb(ctx, "finding", f.ID, "", f); e != nil {
				return e
			}
		}
		for _, g := range gaps {
			s.Gap(g.Stage, g.URL, g.Reason)
		}
	}
	return s.RecordStage(ctx, "libraries")
}
