package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/qdrant/go-client/qdrant"
	"google.golang.org/grpc"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"
)

// fakeFacetPoints answers Facet with fixed hits and remembers the collection.
type fakeFacetPoints struct {
	qdrant.UnimplementedPointsServer
	hits       []*qdrant.FacetHit
	collection string
}

func (f *fakeFacetPoints) Facet(_ context.Context, r *qdrant.FacetCounts) (*qdrant.FacetResponse, error) {
	f.collection = r.GetCollectionName()
	return &qdrant.FacetResponse{Hits: f.hits}, nil
}

func hit(source string, n uint64) *qdrant.FacetHit {
	return &qdrant.FacetHit{Value: &qdrant.FacetValue{Variant: &qdrant.FacetValue_StringValue{StringValue: source}}, Count: n}
}

// useFakeSources points loadConfig at a loopback Qdrant that serves hits.
func useFakeSources(t *testing.T, hits ...*qdrant.FacetHit) *fakeFacetPoints {
	t.Helper()
	isolateUserDirs(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeFacetPoints{hits: hits}
	gs := grpc.NewServer()
	qdrant.RegisterPointsServer(gs, f)
	go gs.Serve(l)
	t.Cleanup(gs.Stop)
	prev := loadConfig
	loadConfig = func() ragconfig.Config {
		cfg := prev()
		cfg.QdrantGRPCURL = l.Addr().String()
		return cfg
	}
	t.Cleanup(func() { loadConfig = prev })
	return f
}

func TestCommaInt(t *testing.T) {
	for in, want := range map[int]string{0: "0", 7: "7", 999: "999", 1000: "1,000", 8432: "8,432", 1234567: "1,234,567"} {
		if got := commaInt(in); got != want {
			t.Errorf("commaInt(%d) = %q, want %q", in, got, want)
		}
	}
}

func sampleSources() []retrieval.SourceCount {
	return []retrieval.SourceCount{{Source: "wstg", Count: 3201}, {Source: "hacktricks", Count: 2940}, {Source: "notes", Count: 12}}
}

func TestFormatSourcesTable(t *testing.T) {
	out := formatSources("blkchain", sampleSources(), false, 100)
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if !strings.Contains(lines[0], "SOURCES") || !strings.Contains(lines[0], "blkchain") ||
		!strings.Contains(lines[0], "3 sources, 6,153 chunks") {
		t.Errorf("banner = %q", lines[0])
	}
	var rows []string
	for _, l := range lines[1:] {
		if strings.TrimSpace(l) != "" {
			rows = append(rows, l)
		}
	}
	if len(rows) != 3 {
		t.Fatalf("want 3 source rows, got %d:\n%s", len(rows), out)
	}
	for i, want := range []struct{ name, count string }{{"wstg", "3,201"}, {"hacktricks", "2,940"}, {"notes", "12"}} {
		if !strings.Contains(rows[i], want.name) || !strings.HasSuffix(rows[i], want.count) {
			t.Errorf("row %d = %q, want name %q and count %q at the end", i, rows[i], want.name, want.count)
		}
	}
	// counts are right-aligned to one column
	if lipgloss.Width(rows[0]) != lipgloss.Width(rows[2]) {
		t.Errorf("rows differ in width: %q vs %q", rows[0], rows[2])
	}
}

func TestFormatSourcesFitsWidthAndKeepsOneLinePerSource(t *testing.T) {
	long := strings.Repeat("very-long-source-name-", 8)
	rows := append(sampleSources(), retrieval.SourceCount{Source: long, Count: 5})
	for _, width := range []int{60, 100} {
		out := formatSources("blkchain_with_a_rather_long_collection_name_indeed_yes", rows, false, width)
		lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
		n := 0
		for _, l := range lines {
			if w := lipgloss.Width(l); w > width-1 {
				t.Errorf("width %d: line is %d columns: %q", width, w, l)
			}
			if strings.Contains(l, "very-long") {
				n++
				if !strings.HasSuffix(l, " 5") || !strings.Contains(l, "...") {
					t.Errorf("width %d: long row = %q, want an ellipsized name and the count", width, l)
				}
			}
		}
		if n != 1 {
			t.Errorf("width %d: long source spans %d lines, want 1", width, n)
		}
		if len(lines) != 1+1+len(rows) { // banner, blank, rows
			t.Errorf("width %d: %d lines, want %d:\n%s", width, len(lines), 2+len(rows), out)
		}
	}
}

func TestFormatSourcesSanitizesNames(t *testing.T) {
	rows := []retrieval.SourceCount{{Source: "evil\x1b]0;pwned\x07name\x1b[31m", Count: 3}}
	out := formatSources("blkchain", rows, false, 80)
	if strings.ContainsAny(out, "\x1b\x07") {
		t.Errorf("output holds a control byte: %q", out)
	}
	if !strings.Contains(out, "evilname") {
		t.Errorf("output = %q, want the cleaned name", out)
	}
}

func TestFormatSourcesSingularAndPartial(t *testing.T) {
	out := formatSources("blkchain", []retrieval.SourceCount{{Source: "wstg", Count: 1}}, true, 80)
	if !strings.Contains(out, "1 source, 1 chunk") {
		t.Errorf("want singular counts, got:\n%s", out)
	}
	if !strings.Contains(out, "partial") {
		t.Errorf("want a partial-counts note, got:\n%s", out)
	}
}

func TestFormatSourcesEmpty(t *testing.T) {
	out := formatSources("blkchain", nil, false, 80)
	if !strings.Contains(out, "no sources indexed yet; add some with `blk add <path>`") {
		t.Errorf("out = %q", out)
	}
}

func TestRunSourcesPrintsTableFromQdrant(t *testing.T) {
	t.Setenv("BLKCHAIN_COLLECTION", "mykb")
	f := useFakeSources(t, hit("hacktricks", 2940), hit("wstg", 3201))
	var err error
	out := captureStdout(t, func() { err = dispatch("sources", nil) })
	if err != nil {
		t.Fatal(err)
	}
	if f.collection != "mykb" {
		t.Errorf("queried collection %q, want mykb", f.collection)
	}
	if i, j := strings.Index(out, "wstg"), strings.Index(out, "hacktricks"); i < 0 || j < 0 || i > j {
		t.Errorf("want wstg (3,201) before hacktricks (2,940):\n%s", out)
	}
	if !strings.Contains(out, "2 sources, 6,141 chunks") {
		t.Errorf("out = %q", out)
	}
}

func TestRunSourcesJSON(t *testing.T) {
	t.Setenv("BLKCHAIN_COLLECTION", "mykb")
	useFakeSources(t, hit("b", 2), hit("a", 2), hit("evil\u009b31m", 9))
	var err error
	out := captureStdout(t, func() { err = dispatch("sources", []string{"--json"}) })
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "SOURCES") || strings.Contains(out, "\u009b") {
		t.Errorf("json output has table text or a raw C1 rune: %q", out)
	}
	var got struct {
		Collection  string `json:"collection"`
		TotalChunks int    `json:"total_chunks"`
		Sources     []struct {
			Source string `json:"source"`
			Chunks int    `json:"chunks"`
		} `json:"sources"`
		Partial bool `json:"partial"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, out)
	}
	if got.Collection != "mykb" || got.TotalChunks != 13 || got.Partial || len(got.Sources) != 3 {
		t.Fatalf("got %+v", got)
	}
	if got.Sources[0].Source != "evil\u009b31m" || got.Sources[0].Chunks != 9 || got.Sources[1].Source != "a" || got.Sources[2].Source != "b" {
		t.Errorf("sources not sorted by count then name: %+v", got.Sources)
	}
}

func TestRunSourcesEmptyCollection(t *testing.T) {
	t.Setenv("BLKCHAIN_COLLECTION", "")
	useFakeSources(t)
	var err error
	out := captureStdout(t, func() { err = dispatch("sources", nil) })
	if err != nil || exitCode(err) != 0 {
		t.Fatalf("err = %v, want success", err)
	}
	if !strings.Contains(out, "no sources indexed yet; add some with `blk add <path>`") {
		t.Errorf("out = %q", out)
	}
	out = captureStdout(t, func() { err = dispatch("sources", []string{"--json"}) })
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if got["collection"] != "blkchain" || got["total_chunks"] != float64(0) {
		t.Errorf("got %v", got)
	}
	if s, ok := got["sources"].([]any); !ok || len(s) != 0 {
		t.Errorf("sources = %v, want an empty array", got["sources"])
	}
}

func TestRunSourcesUnreachableExitsOneWithEmptyStdout(t *testing.T) {
	isolateUserDirs(t)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := l.Addr().String()
	l.Close()
	prev := loadConfig
	loadConfig = func() ragconfig.Config {
		cfg := prev()
		cfg.QdrantGRPCURL = dead
		return cfg
	}
	t.Cleanup(func() { loadConfig = prev })
	for _, args := range [][]string{nil, {"--json"}} {
		var err error
		out := captureStdout(t, func() { err = dispatch("sources", args) })
		if !errors.Is(err, retrieval.ErrUnreachable) || exitCode(err) != 1 {
			t.Errorf("args %v: err = %v (exit %d), want ErrUnreachable and exit 1", args, err, exitCode(err))
		}
		if out != "" {
			t.Errorf("args %v: stdout = %q, want empty", args, out)
		}
		if !strings.Contains(err.Error(), "blk up") {
			t.Errorf("args %v: error %q does not say to run blk up", args, err)
		}
	}
}

func TestRunSourcesRejectsArguments(t *testing.T) {
	var err error
	out := captureStdout(t, func() { err = dispatch("sources", []string{"wstg"}) })
	if exitCode(err) != 2 || out != "" {
		t.Errorf("err = %v (exit %d), stdout %q, want a usage error and no output", err, exitCode(err), out)
	}
}
