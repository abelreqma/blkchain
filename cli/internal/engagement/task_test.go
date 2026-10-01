package engagement

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "e.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func insertTaskRow(t *testing.T, s *Store, id, dependsOn, basisIDs string) {
	t.Helper()
	_, err := s.db.Exec(
		`INSERT INTO task (id, kind, target, objective, done_when, status, depends_on, basis_ids, created_rev, updated_rev)
		 VALUES (?, 'recon', 'example.test', 'map the surface', 'endpoints listed', 'active', ?, ?, 1, 2)`,
		id, dependsOn, basisIDs)
	if err != nil {
		t.Fatalf("insert task: %v", err)
	}
}

func TestTaskGetRoundTrip(t *testing.T) {
	s := openTemp(t)
	insertTaskRow(t, s, "t1", `["a","b"]`, `["c"]`)

	got, err := s.GetTask("t1")
	if err != nil {
		t.Fatalf("GetTask: %v", err)
	}
	want := Task{
		ID: "t1", Kind: "recon", Target: "example.test",
		Objective: "map the surface", DoneWhen: "endpoints listed",
		Status:    StatusActive,
		DependsOn: []string{"a", "b"}, BasisIDs: []string{"c"},
		CreatedRev: 1, UpdatedRev: 2,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("GetTask = %+v, want %+v", got, want)
	}
}

func TestTaskGetEmptySlices(t *testing.T) {
	s := openTemp(t)
	insertTaskRow(t, s, "t1", "", "[]")

	got, err := s.GetTask("t1")
	if err != nil {
		t.Fatalf("GetTask: %v", err)
	}
	if len(got.DependsOn) != 0 || len(got.BasisIDs) != 0 {
		t.Fatalf("want empty slices, got %v and %v", got.DependsOn, got.BasisIDs)
	}
}

func TestTaskGetNotFound(t *testing.T) {
	s := openTemp(t)
	_, err := s.GetTask("nope")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestTaskStatusValid(t *testing.T) {
	for _, st := range []Status{StatusTodo, StatusActive, StatusDone, StatusNA, StatusBlocked} {
		if !st.valid() {
			t.Errorf("%q should be valid", st)
		}
	}
	if Status("bogus").valid() {
		t.Error("bogus should be invalid")
	}
	if Status("").valid() {
		t.Error("empty should be invalid")
	}
}

func TestTaskRevisionFreshZero(t *testing.T) {
	s := openTemp(t)
	got, err := s.Revision(context.Background())
	if err != nil {
		t.Fatalf("Revision: %v", err)
	}
	if got != 0 {
		t.Fatalf("Revision = %d, want 0", got)
	}
}

func TestTaskArmedRoundTrips(t *testing.T) {
	s := openTemp(t)
	if _, err := s.Apply(Delta{Upserts: []Task{
		{ID: "a", Kind: "recon", Status: StatusTodo}, // default: unarmed
		{ID: "b", Kind: "exploit", Phase: PhaseExploit, Status: StatusTodo, Armed: true},
	}}); err != nil {
		t.Fatal(err)
	}
	a, err := s.GetTask("a")
	if err != nil || a.Armed {
		t.Errorf("task a: Armed = %v err=%v, want false", a.Armed, err)
	}
	b, err := s.GetTask("b")
	if err != nil || !b.Armed {
		t.Errorf("task b: Armed = %v err=%v, want true", b.Armed, err)
	}
	snap, err := s.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, tk := range snap.Tasks {
		got[tk.ID] = tk.Armed
	}
	if got["a"] || !got["b"] {
		t.Errorf("snapshot armed = %v, want a:false b:true", got)
	}
}

func TestTaskJSONHelpers(t *testing.T) {
	if got := marshalStrings(nil); got != "[]" {
		t.Errorf("marshalStrings(nil) = %q, want []", got)
	}
	if got := marshalStrings([]string{}); got != "[]" {
		t.Errorf("marshalStrings(empty) = %q, want []", got)
	}
	if got := marshalStrings([]string{"x"}); got != `["x"]` {
		t.Errorf("marshalStrings = %q", got)
	}
	if _, err := unmarshalStrings("{bad"); err == nil {
		t.Error("unmarshalStrings of malformed JSON should error")
	}
}
