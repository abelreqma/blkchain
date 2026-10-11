package webanalysis

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

func bundleSnapshot() Snapshot {
	return Snapshot{
		Units: []SourceUnit{
			{ID: "u1", Language: "javascript", Hash: "h1", URL: "https://example.com/app.js", Kind: "script"},
			{ID: "u2", Language: "typescript", Hash: "h2", URL: "https://example.com/api.ts", Kind: "script"},
		},
		Operations: []Operation{
			{ID: "op1", Method: "GET", Origin: "https://example.com", Path: "/api/items"},
			{ID: "op2", Method: "POST", Origin: "https://example.com", Path: "/api/items"},
		},
		Findings: []Finding{{ID: "f1", Kind: "credential", Detector: "jsluice", Confidence: "high"}},
		Requests: []RequestExample{{Method: "GET", URL: "https://example.com/api/items", Status: 200}},
	}
}

func bundleTrees() []AST {
	return []AST{{
		Unit: "u1", Language: "javascript", Hash: "h1",
		Nodes: []ASTNode{
			{Type: "program", Parent: -1, Children: []int{1}},
			{Type: "call_expression", Parent: 0, Text: "fetch(x)"},
		},
	}}
}

func buildTestBundle(t *testing.T) Bundle {
	t.Helper()
	b, err := BuildBundle(bundleSnapshot(), bundleTrees())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBundleHoldsEveryKindAndTheManifestAgrees(t *testing.T) {
	b := buildTestBundle(t)
	if b.Manifest.Version != BundleVersion {
		t.Errorf("version = %q", b.Manifest.Version)
	}
	for _, name := range []string{"manifest.json", "checksums.txt", "snapshot.json.gz", "index.html", "data.js"} {
		if _, ok := b.File(name); !ok {
			t.Errorf("the bundle has no %s", name)
		}
	}
	// Every kind has at least one shard, so a reader never has to tell an absent kind from an empty one.
	for _, k := range bundleKinds() {
		name := fmt.Sprintf("records/%s.00000.jsonl.gz", k.name)
		if _, ok := b.File(name); !ok {
			t.Errorf("the bundle has no shard for %s", k.name)
		}
	}
	if _, ok := b.File("records/ast.00000.jsonl.gz"); !ok {
		t.Error("the bundle has no syntax-tree shard")
	}
	if b.Manifest.Counts["units"] != 2 || b.Manifest.Counts["operations"] != 2 {
		t.Errorf("counts = %v", b.Manifest.Counts)
	}
	if b.Manifest.Counts["ast"] != 1 {
		t.Errorf("ast count = %d, want 1", b.Manifest.Counts["ast"])
	}
	if b.Manifest.Counts["calls"] != 0 {
		t.Errorf("an empty kind counted %d", b.Manifest.Counts["calls"])
	}
	if bad := VerifyBundle(b); len(bad) != 0 {
		t.Errorf("verification failed: %v", bad)
	}
}

func TestBundleShardsRoundTripAsJSONL(t *testing.T) {
	b := buildTestBundle(t)
	f, ok := b.File("records/units.00000.jsonl.gz")
	if !ok {
		t.Fatal("no unit shard")
	}
	if !f.Gzip {
		t.Error("the shard is not marked gzip")
	}
	if f.Records != 2 {
		t.Errorf("shard records = %d, want 2", f.Records)
	}
	raw, err := GunzipBytes(f.Data)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("the shard holds %d lines, want 2", len(lines))
	}
	var first SourceUnit
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("line is not a JSON record: %v", err)
	}
	if first.ID != "u1" || first.URL != "https://example.com/app.js" {
		t.Errorf("the record lost its fields: %+v", first)
	}
	// Each line is one complete record, so a reader can stream the shard.
	for i, line := range lines {
		if !json.Valid([]byte(line)) {
			t.Errorf("line %d is not valid JSON: %q", i, line)
		}
		if strings.Contains(line, "\n") {
			t.Errorf("line %d holds a newline", i)
		}
	}
}

func TestBundleSharding(t *testing.T) {
	s := Snapshot{}
	total := MaxShardRecords*2 + 7
	for i := 0; i < total; i++ {
		s.Operations = append(s.Operations, Operation{ID: fmt.Sprintf("op%05d", i), Method: "GET"})
	}
	b, err := BuildBundle(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	var shards []BundleFile
	for _, f := range b.Files {
		if f.Kind == "operations" {
			shards = append(shards, f)
		}
	}
	if len(shards) != 3 {
		t.Fatalf("got %d operation shards, want 3", len(shards))
	}
	seen := 0
	for i, f := range shards {
		if f.Shard != i {
			t.Errorf("shard %d reports index %d", i, f.Shard)
		}
		if f.Records > MaxShardRecords {
			t.Errorf("shard %d holds %d records, past the bound", i, f.Records)
		}
		seen += f.Records
	}
	if seen != total {
		t.Errorf("the shards hold %d of %d records", seen, total)
	}
	if b.Manifest.Counts["operations"] != total {
		t.Errorf("the manifest counts %d operations", b.Manifest.Counts["operations"])
	}
	// The last shard holds the remainder rather than a whole block.
	if shards[2].Records != 7 {
		t.Errorf("the final shard holds %d records, want the remainder 7", shards[2].Records)
	}
}

// The same snapshot produces the same bytes, so a bundle's checksums identify its content rather than when it was written.
func TestBundleIsDeterministic(t *testing.T) {
	first := buildTestBundle(t)
	second := buildTestBundle(t)
	if len(first.Files) != len(second.Files) {
		t.Fatalf("file counts differ: %d and %d", len(first.Files), len(second.Files))
	}
	for i := range first.Files {
		a, b := first.Files[i], second.Files[i]
		if a.Name != b.Name {
			t.Fatalf("file %d is %q then %q", i, a.Name, b.Name)
		}
		if a.SHA256 != b.SHA256 {
			t.Errorf("%s has two different checksums across builds", a.Name)
		}
		if !bytes.Equal(a.Data, b.Data) {
			t.Errorf("%s has different bytes across builds", a.Name)
		}
	}
}

func TestBundleChecksumsCoverEveryFile(t *testing.T) {
	b := buildTestBundle(t)
	f, ok := b.File("checksums.txt")
	if !ok {
		t.Fatal("no checksum list")
	}
	lines := strings.Split(strings.TrimRight(string(f.Data), "\n"), "\n")
	listed := map[string]string{}
	for _, line := range lines {
		sum, name, found := strings.Cut(line, "  ")
		if !found {
			t.Errorf("line %q is not a checksum entry", line)
			continue
		}
		if len(sum) != 64 {
			t.Errorf("%q is not a sha256", sum)
		}
		listed[name] = sum
	}
	for _, file := range b.Files {
		if file.Name == "checksums.txt" {
			continue
		}
		sum, ok := listed[file.Name]
		if !ok {
			t.Errorf("%s is not in the checksum list", file.Name)
			continue
		}
		if sum != Hash(file.Data) {
			t.Errorf("%s has checksum %q, want %q", file.Name, sum, Hash(file.Data))
		}
	}
	// The list is sorted, so two builds of the same bundle produce the same file.
	sorted := append([]string(nil), lines...)
	for i := 1; i < len(sorted); i++ {
		if sorted[i-1] > sorted[i] {
			t.Errorf("the checksum list is not sorted at line %d", i)
			break
		}
	}
}

func TestBundleManifestIsSortedAndComplete(t *testing.T) {
	b := buildTestBundle(t)
	for i := 1; i < len(b.Manifest.Files); i++ {
		if b.Manifest.Files[i-1].Name > b.Manifest.Files[i].Name {
			t.Errorf("the manifest is not sorted at %d", i)
			break
		}
	}
	for _, m := range b.Manifest.Files {
		if m.SHA256 == "" || m.Bytes == 0 && m.Records > 0 {
			t.Errorf("manifest entry is incomplete: %+v", m)
		}
	}
	// The manifest does not list itself or the checksum file, which are written from it.
	for _, m := range b.Manifest.Files {
		if m.Name == "manifest.json" || m.Name == "checksums.txt" {
			t.Errorf("the manifest lists %s", m.Name)
		}
	}
	raw, ok := b.File("manifest.json")
	if !ok {
		t.Fatal("no manifest file")
	}
	var back BundleManifest
	if err := json.Unmarshal(raw.Data, &back); err != nil {
		t.Fatalf("the manifest file is not JSON: %v", err)
	}
	if back.Version != BundleVersion || len(back.Files) != len(b.Manifest.Files) {
		t.Errorf("the manifest file does not match the manifest: %+v", back)
	}
}

func TestVerifyBundleDetectsTampering(t *testing.T) {
	b := buildTestBundle(t)
	if bad := VerifyBundle(b); len(bad) != 0 {
		t.Fatalf("a fresh bundle failed verification: %v", bad)
	}
	// The alteration keeps the size, so the checksum is what catches it.
	altered := buildTestBundle(t)
	for i := range altered.Files {
		if altered.Files[i].Name == "records/units.00000.jsonl.gz" {
			data := append([]byte{}, altered.Files[i].Data...)
			data[len(data)/2] ^= 0xff
			altered.Files[i].Data = data
		}
	}
	bad := VerifyBundle(altered)
	if len(bad) == 0 {
		t.Fatal("an altered file passed verification")
	}
	if !strings.Contains(strings.Join(bad, " "), "records/units.00000.jsonl.gz") {
		t.Errorf("verification did not name the altered file: %v", bad)
	}

	missing := buildTestBundle(t)
	var kept []BundleFile
	for _, f := range missing.Files {
		if f.Name != "snapshot.json.gz" {
			kept = append(kept, f)
		}
	}
	missing.Files = kept
	if bad := VerifyBundle(missing); len(bad) == 0 {
		t.Error("a bundle with a missing file passed verification")
	}

	extra := buildTestBundle(t)
	extra.Files = append(extra.Files, bundleFile("records/planted.jsonl.gz", "", 0, 0, []byte("x"), false))
	bad = VerifyBundle(extra)
	if len(bad) == 0 || !strings.Contains(strings.Join(bad, " "), "planted") {
		t.Errorf("an unlisted file passed verification: %v", bad)
	}
}

func TestBundleSnapshotFileRoundTrips(t *testing.T) {
	b := buildTestBundle(t)
	f, ok := b.File("snapshot.json.gz")
	if !ok {
		t.Fatal("no snapshot file")
	}
	raw, err := GunzipBytes(f.Data)
	if err != nil {
		t.Fatal(err)
	}
	var back Snapshot
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	want := bundleSnapshot()
	if len(back.Units) != len(want.Units) || back.Units[0].ID != "u1" {
		t.Errorf("units did not round trip: %+v", back.Units)
	}
	if len(back.Operations) != len(want.Operations) || back.Operations[1].Method != "POST" {
		t.Errorf("operations did not round trip: %+v", back.Operations)
	}
	if len(back.Findings) != 1 || back.Findings[0].Kind != "credential" {
		t.Errorf("findings did not round trip: %+v", back.Findings)
	}
	// Compression is worth doing on this content.
	if f.Bytes >= len(raw) {
		t.Errorf("the gzipped snapshot is %d bytes against %d raw", f.Bytes, len(raw))
	}
}

// A tree whose unit is not in the snapshot has nothing to attach it to, so it is left out and named as a gap.
func TestBundleDropsATreeWithNoUnit(t *testing.T) {
	trees := append(bundleTrees(), AST{Unit: "orphan", Language: "javascript"})
	b, err := BuildBundle(bundleSnapshot(), trees)
	if err != nil {
		t.Fatal(err)
	}
	if b.Manifest.Counts["ast"] != 1 {
		t.Errorf("ast count = %d, want only the tree with a unit", b.Manifest.Counts["ast"])
	}
	if !strings.Contains(strings.Join(b.Manifest.Gaps, " "), "orphan") {
		t.Errorf("gaps do not name the dropped tree: %v", b.Manifest.Gaps)
	}
	raw, err := GunzipBytes(mustFile(t, b, "records/ast.00000.jsonl.gz").Data)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "orphan") {
		t.Error("the orphan tree was written to the shard")
	}
	data := string(mustFile(t, b, "data.js").Data)
	payload := strings.TrimSuffix(strings.TrimPrefix(data, "window.BLK_BUNDLE = "), ";\n")
	var viewer struct {
		Counts map[string]int `json:"counts"`
		Kinds  struct {
			AST []json.RawMessage `json:"ast"`
		} `json:"kinds"`
	}
	if err := json.Unmarshal([]byte(payload), &viewer); err != nil {
		t.Fatal(err)
	}
	if viewer.Counts["ast"] != b.Manifest.Counts["ast"] || len(viewer.Kinds.AST) != b.Manifest.Counts["ast"] {
		t.Errorf("viewer holds %d trees and reports %d, manifest reports %d",
			len(viewer.Kinds.AST), viewer.Counts["ast"], b.Manifest.Counts["ast"])
	}
}

func TestBundleNamesParsedUnitWithoutSyntaxTree(t *testing.T) {
	s := bundleSnapshot()
	s.Units[0].Parse = "ok"
	s.Units[1].Parse = "ok"
	b, err := BuildBundle(s, bundleTrees())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(b.Manifest.Gaps, " "), "syntax tree for unit u2 is absent") {
		t.Errorf("manifest gaps do not name the missing tree: %v", b.Manifest.Gaps)
	}
}

// A truncated tree is carried but named as a gap, so a reader is not left to infer completeness from the record count.
func TestBundleNamesATruncatedTree(t *testing.T) {
	trees := bundleTrees()
	trees[0].Truncated = true
	trees[0].Gap = "tree exceeds the node bound"
	b, err := BuildBundle(bundleSnapshot(), trees)
	if err != nil {
		t.Fatal(err)
	}
	if b.Manifest.Counts["ast"] != 1 {
		t.Errorf("a truncated tree was dropped: %v", b.Manifest.Counts)
	}
	joined := strings.Join(b.Manifest.Gaps, " ")
	if !strings.Contains(joined, "truncated") || !strings.Contains(joined, "node bound") {
		t.Errorf("gaps do not name the truncation: %v", b.Manifest.Gaps)
	}
}

func TestBundleViewerLoadsFromTheFilesystem(t *testing.T) {
	b := buildTestBundle(t)
	page := string(mustFile(t, b, "index.html").Data)
	data := string(mustFile(t, b, "data.js").Data)
	// The viewer reads a sibling script, because a page opened from the filesystem cannot fetch a sibling file.
	if !strings.Contains(page, `<script src="data.js">`) {
		t.Error("the viewer does not load data.js")
	}
	for _, forbidden := range []string{"fetch(", "XMLHttpRequest", "http://", "https://", "import("} {
		if strings.Contains(page, forbidden) {
			t.Errorf("the viewer references %q, so it is not offline", forbidden)
		}
	}
	if !strings.HasPrefix(data, "window.BLK_BUNDLE = ") {
		t.Errorf("data.js does not assign the global: %.40s", data)
	}
	payload := strings.TrimSuffix(strings.TrimPrefix(data, "window.BLK_BUNDLE = "), ";\n")
	var back map[string]any
	if err := json.Unmarshal([]byte(payload), &back); err != nil {
		t.Fatalf("data.js payload is not JSON: %v", err)
	}
	counts, _ := back["counts"].(map[string]any)
	if counts["units"] != float64(2) {
		t.Errorf("the viewer data counts %v units", counts["units"])
	}
	kinds, _ := back["kinds"].(map[string]any)
	if units, _ := kinds["units"].([]any); len(units) != 2 {
		t.Errorf("the viewer embeds %d unit records", len(units))
	}
	if back["version"] != BundleVersion {
		t.Errorf("the viewer data names version %v", back["version"])
	}
}

// The viewer embeds a bounded sample, and says how many records it is not showing, so it opens on a large bundle without hiding the rest.
func TestBundleViewerSampleIsBounded(t *testing.T) {
	s := Snapshot{}
	for i := 0; i < MaxViewerRecords*2; i++ {
		s.Operations = append(s.Operations, Operation{ID: fmt.Sprintf("op%05d", i), Method: "GET"})
	}
	b, err := BuildBundle(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	data := string(mustFile(t, b, "data.js").Data)
	payload := strings.TrimSuffix(strings.TrimPrefix(data, "window.BLK_BUNDLE = "), ";\n")
	var back struct {
		Limit  int            `json:"limit"`
		Counts map[string]int `json:"counts"`
		Kinds  struct {
			Operations []json.RawMessage `json:"operations"`
		} `json:"kinds"`
	}
	if err := json.Unmarshal([]byte(payload), &back); err != nil {
		t.Fatal(err)
	}
	if len(back.Kinds.Operations) != MaxViewerRecords {
		t.Errorf("the viewer embeds %d operations, want the bound of %d",
			len(back.Kinds.Operations), MaxViewerRecords)
	}
	if back.Counts["operations"] != MaxViewerRecords*2 {
		t.Errorf("the viewer reports %d operations, want the real total", back.Counts["operations"])
	}
	if back.Limit != MaxViewerRecords {
		t.Errorf("the viewer data does not state its bound: %d", back.Limit)
	}
}

func TestBundleOfAnEmptySnapshot(t *testing.T) {
	b, err := BuildBundle(Snapshot{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bad := VerifyBundle(b); len(bad) != 0 {
		t.Errorf("an empty bundle failed verification: %v", bad)
	}
	for _, k := range bundleKinds() {
		if b.Manifest.Counts[k.name] != 0 {
			t.Errorf("%s counted %d in an empty snapshot", k.name, b.Manifest.Counts[k.name])
		}
		f := mustFile(t, b, fmt.Sprintf("records/%s.00000.jsonl.gz", k.name))
		raw, err := GunzipBytes(f.Data)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) != 0 {
			t.Errorf("the %s shard is not empty: %q", k.name, raw)
		}
	}
}

func TestGunzipBytesRejectsBadInput(t *testing.T) {
	if _, err := GunzipBytes([]byte("not gzip")); err == nil {
		t.Error("non-gzip input was accepted")
	}
	if _, err := GunzipBytes(nil); err == nil {
		t.Error("empty input was accepted")
	}
	round, err := gzipBytes([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	back, err := GunzipBytes(round)
	if err != nil || string(back) != "hello" {
		t.Errorf("round trip gave %q (%v)", back, err)
	}
	// A truncated member is an error, not a short read.
	if _, err := GunzipBytes(round[:len(round)-4]); err == nil {
		t.Error("a truncated gzip member was accepted")
	}
}

// A member that expands past the limit is refused, so a bundle read from elsewhere cannot decompress without bound.
func TestGunzipBoundedRefusesAnOversizeExpansion(t *testing.T) {
	small, err := gzipBytes(bytes.Repeat([]byte("a"), 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	if len(small) >= 1<<20 {
		t.Fatalf("the fixture did not compress: %d bytes", len(small))
	}
	if _, err := gunzipBounded(small, 4096); err == nil {
		t.Error("an expansion past the limit was accepted")
	}
	out, err := gunzipBounded(small, 1<<20)
	if err != nil || len(out) != 1<<20 {
		t.Errorf("an expansion inside the limit gave %d bytes (%v)", len(out), err)
	}
}

func TestBundleTotalBytesAndFileLookup(t *testing.T) {
	b := buildTestBundle(t)
	total := 0
	for _, f := range b.Files {
		total += len(f.Data)
	}
	if b.TotalBytes() != total {
		t.Errorf("TotalBytes = %d, want %d", b.TotalBytes(), total)
	}
	if _, ok := b.File("records/absent.jsonl.gz"); ok {
		t.Error("File found a name the bundle does not hold")
	}
}

func mustFile(t *testing.T, b Bundle, name string) BundleFile {
	t.Helper()
	f, ok := b.File(name)
	if !ok {
		t.Fatalf("the bundle has no %s", name)
	}
	return f
}

// A caller's own gap reaches the manifest file, so the written manifest states everything the bundle does not hold.
func TestBundleCarriesCallerGaps(t *testing.T) {
	b, err := BuildBundle(bundleSnapshot(), bundleTrees(), "syntax tree abc: blob unreadable")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(b.Manifest.Gaps, " "), "blob unreadable") {
		t.Errorf("gaps = %v, want the caller's gap", b.Manifest.Gaps)
	}
	raw, ok := b.File("manifest.json")
	if !ok {
		t.Fatal("no manifest file")
	}
	var back BundleManifest
	if err := json.Unmarshal(raw.Data, &back); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(back.Gaps, " "), "blob unreadable") {
		t.Errorf("the manifest file does not carry the gap: %v", back.Gaps)
	}
}

func TestMarshalASTRoundTrips(t *testing.T) {
	tree := bundleTrees()[0]
	body, err := MarshalAST(tree)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) >= len(tree.Nodes[0].Type)*len(tree.Nodes)+1<<20 {
		t.Errorf("the serialized tree is %d bytes", len(body))
	}
	back, err := UnmarshalAST(body)
	if err != nil {
		t.Fatal(err)
	}
	if back.Unit != tree.Unit || len(back.Nodes) != len(tree.Nodes) {
		t.Errorf("round trip changed the tree: %+v", back)
	}
	if back.Nodes[0].Type != "program" || back.Nodes[0].Parent != -1 {
		t.Errorf("the root did not round trip: %+v", back.Nodes[0])
	}
	if _, err := UnmarshalAST([]byte("not gzip")); err == nil {
		t.Error("a non-gzip body was accepted")
	}
	plain, err := gzipBytes([]byte("not a tree"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalAST(plain); err == nil {
		t.Error("a gzip body that is not a tree was accepted")
	}
}

func TestUnmarshalASTBoundsExpandedInput(t *testing.T) {
	body, err := gzipBytes(bytes.Repeat([]byte("x"), (32<<20)+1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalAST(body); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Errorf("oversize AST expansion returned %v, want a size limit", err)
	}
}

// A tree too large to store is refused rather than truncated silently, so the caller records a gap instead of storing a partial body.
func TestMarshalASTRefusesAnOversizeTree(t *testing.T) {
	// The limit applies to the compressed body, so the text has to be incompressible for the tree to reach it.
	rng := rand.New(rand.NewSource(1))
	letters := []byte("abcdefghijklmnopqrstuvwxyz0123456789")
	big := AST{Unit: "u1", Language: "javascript"}
	for i := 0; i < 40000; i++ {
		text := make([]byte, MaxASTText)
		for k := range text {
			text[k] = letters[rng.Intn(len(letters))]
		}
		big.Nodes = append(big.Nodes, ASTNode{
			Type: "identifier", Parent: 0, StartByte: i, EndByte: i + 1, Text: string(text),
		})
	}
	if _, err := MarshalAST(big); err == nil {
		t.Error("a tree past the artifact body limit was accepted")
	} else if !strings.Contains(err.Error(), "artifact body limit") {
		t.Errorf("error = %v, want the body limit named", err)
	}
}
