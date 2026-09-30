package main

import (
	"context"
	"sync"
)

// engagement.go is the read-only projection of the harness engagement store
// (parent spec section 4.2) that the progress view consumes. The store
// implements EngagementView; stubEngagement implements it for development and
// tests. The view never mutates the store.

type TaskStatus int

const (
	TaskTodo TaskStatus = iota
	TaskActive
	TaskDone
	TaskNA
	TaskBlocked
)

func (s TaskStatus) String() string {
	switch s {
	case TaskActive:
		return "active"
	case TaskDone:
		return "done"
	case TaskNA:
		return "na"
	case TaskBlocked:
		return "blocked"
	default:
		return "todo"
	}
}

func taskStatusFromStore(s string) TaskStatus {
	switch s {
	case "active":
		return TaskActive
	case "done":
		return TaskDone
	case "na":
		return TaskNA
	case "blocked":
		return TaskBlocked
	default:
		return TaskTodo
	}
}

// Task is one node of the engagement DAG. DependsOn holds task ids (edges).
type Task struct {
	ID        string
	Kind      string
	Target    string
	Objective string
	Status    TaskStatus
	DependsOn []string
	BasisIDs  []string
}

// Stage is the pipeline position of the active work, for the live bar.
type Stage struct {
	Label string
	Step  int
	Total int
	Tool  string
}

// Engagement is the task DAG at one revision.
type Engagement struct {
	Revision int64
	Name     string
	Tasks    []Task
	ActiveID string
	Stage    Stage
}

// EngagementView is the read-only projection the progress view consumes.
type EngagementView interface {
	Revision(ctx context.Context) (int64, error)
	Snapshot(ctx context.Context) (Engagement, error)
}

// stubEngagement is an in-memory EngagementView for development and tests.
type stubEngagement struct {
	mu   sync.Mutex
	name string
	cur  Engagement
}

func newStubEngagement(name string) *stubEngagement {
	return &stubEngagement{name: name, cur: Engagement{Name: name}}
}

func (s *stubEngagement) Revision(context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur.Revision, nil
}

func (s *stubEngagement) Snapshot(context.Context) (Engagement, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur, nil
}

// setSnapshot replaces the DAG and bumps the revision, standing in for a store
// transition. Test and dev-driver only.
func (s *stubEngagement) setSnapshot(e Engagement) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e.Revision = s.cur.Revision + 1
	if e.Name == "" {
		e.Name = s.name
	}
	s.cur = e
}
