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
		CompletionEvidenceIDs: []string{},
		CreatedRev:            1, UpdatedRev: 2,
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

func TestPhaseForKind(t *testing.T) {
	// exploit-dev is the one exploit-phase persona; every other Kind (and the empty
	// and unknown cases) defaults to recon. The lookup is case-insensitive and
	// trimmed, so a mis-cased exploit Kind still derives the stricter phase
	// (fail-safe, not fail-open).
	cases := map[string]Phase{
		"exploit-dev":     PhaseExploit,
		"exploit":         PhaseExploit,
		"Exploit":         PhaseExploit,
		"Exploit-Dev":     PhaseExploit,
		"  exploit-dev  ": PhaseExploit,
		"recon":           PhaseRecon,
		"web":             PhaseRecon,
		"ad":              PhaseRecon,
		"local":           PhaseRecon,
		"target-analysis": PhaseRecon,
		"generic":         PhaseRecon,
		"":                PhaseRecon,
		"unknown-kind":    PhaseRecon,
	}
	for kind, want := range cases {
		if got := phaseForKind(kind); got != want {
			t.Errorf("phaseForKind(%q) = %q, want %q", kind, got, want)
		}
	}
}

func TestSurfaceValid(t *testing.T) {
	for _, sf := range []Surface{
		SurfaceLocal, SurfaceNetwork, SurfaceWeb, SurfaceAD,
		SurfaceCloud, SurfaceCloudAWS, SurfaceCloudGCP, SurfaceCloudAzure,
		SurfaceContainer, SurfaceAISecurity,
	} {
		if !sf.valid() {
			t.Errorf("%q should be valid", sf)
		}
	}
	// ad-cloud was split into ad + cloud (+ per-CSP) and removed entirely.
	if Surface("ad-cloud").valid() {
		t.Error("ad-cloud was removed and must be invalid")
	}
	if Surface("bogus").valid() {
		t.Error("bogus should be invalid")
	}
	if Surface("").valid() {
		t.Error("empty should be invalid")
	}
}

func TestAllSurfaces(t *testing.T) {
	// Independent source of truth: the explicit ordered set. AllSurfaces must
	// equal it, and valid() must accept every member (drift guard between the
	// canonical list and the validity check).
	want := []Surface{
		SurfaceLocal, SurfaceNetwork, SurfaceWeb, SurfaceAD,
		SurfaceCloud, SurfaceCloudAWS, SurfaceCloudGCP, SurfaceCloudAzure,
		SurfaceContainer, SurfaceAISecurity,
	}
	got := AllSurfaces()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("AllSurfaces() = %v, want %v", got, want)
	}
	for _, sf := range want {
		if !sf.valid() {
			t.Errorf("AllSurfaces member %q is not valid()", sf)
		}
	}
	// The returned slice is a copy: mutating it must not affect a later call.
	got[0] = Surface("mutated")
	if again := AllSurfaces(); again[0] != SurfaceLocal {
		t.Errorf("AllSurfaces() shares its backing array: again[0] = %q after mutation", again[0])
	}
}

func TestSurfaceForKind(t *testing.T) {
	// ad/cloud/k8s split out of the old ad-cloud surface; container and
	// ai-security are new. An unknown or empty kind falls back to network.
	cases := map[string]Surface{
		"web":             SurfaceWeb,
		"ad":              SurfaceAD,
		"cloud":           SurfaceCloud,
		"k8s":             SurfaceContainer,
		"container":       SurfaceContainer,
		"ai-security":     SurfaceAISecurity,
		"ai":              SurfaceAISecurity,
		"local":           SurfaceLocal,
		"target-analysis": SurfaceLocal,
		"exploit-dev":     SurfaceLocal,
		"wifi":            SurfaceNetwork,
		"recon":           SurfaceNetwork,
		"generic":         SurfaceNetwork,
		"":                SurfaceNetwork,
		"unknown-kind":    SurfaceNetwork,
	}
	for kind, want := range cases {
		if got := surfaceForKind(kind); got != want {
			t.Errorf("surfaceForKind(%q) = %q, want %q", kind, got, want)
		}
	}
}

func TestApplyLockedDerivesPhaseFromKind(t *testing.T) {
	s := openTemp(t)
	if _, err := s.Apply(Delta{Upserts: []Task{
		{ID: "e", Kind: "exploit-dev", Status: StatusTodo},                    // empty phase -> exploit (fail-safe)
		{ID: "w", Kind: "web", Status: StatusTodo},                            // empty phase -> recon
		{ID: "x", Kind: "exploit-dev", Phase: PhaseRecon, Status: StatusTodo}, // explicit phase is respected (derivation is for empty only)
	}}); err != nil {
		t.Fatal(err)
	}
	if e, _ := s.GetTask("e"); e.Phase != PhaseExploit {
		t.Errorf("exploit-dev with empty phase = %q, want exploit", e.Phase)
	}
	if w, _ := s.GetTask("w"); w.Phase != PhaseRecon {
		t.Errorf("web with empty phase = %q, want recon", w.Phase)
	}
	if x, _ := s.GetTask("x"); x.Phase != PhaseRecon {
		t.Errorf("explicit phase overridden = %q, want recon (explicit respected)", x.Phase)
	}
}
