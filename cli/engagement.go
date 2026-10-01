package main

import (
	"context"
	"sync"

	eng "blkchain/cli/internal/engagement"
)

// engagement.go is the read-only projection of the harness engagement store
// (parent spec section 4.2) that the progress view consumes. The store
// implements EngagementView; stubEngagement implements it for development and
// tests. The view never mutates the store.

// EngagementView is the read-only projection the progress view consumes.
type EngagementView interface {
	Revision(ctx context.Context) (int64, error)
	Snapshot(ctx context.Context) (eng.Engagement, error)
}

// stubEngagement is an in-memory EngagementView for development and tests.
type stubEngagement struct {
	mu   sync.Mutex
	name string
	cur  eng.Engagement
}

func newStubEngagement(name string) *stubEngagement {
	return &stubEngagement{name: name, cur: eng.Engagement{Name: name}}
}

func (s *stubEngagement) Revision(context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur.Revision, nil
}

func (s *stubEngagement) Snapshot(context.Context) (eng.Engagement, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur, nil
}

// setSnapshot replaces the DAG and bumps the revision, standing in for a store
// transition. Test and dev-driver only.
func (s *stubEngagement) setSnapshot(e eng.Engagement) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e.Revision = s.cur.Revision + 1
	if e.Name == "" {
		e.Name = s.name
	}
	s.cur = e
}
