package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/webanalysis"
)

func TestWebBundleTreesBoundsAggregateExpansion(t *testing.T) {
	ws, err := engagement.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	ctx := context.Background()
	snapshot := webanalysis.Snapshot{}
	for i := 0; i < 3; i++ {
		tree := webanalysis.AST{Unit: fmt.Sprintf("unit-%d", i), Nodes: []webanalysis.ASTNode{{
			Type: "program", Parent: -1, Text: strings.Repeat("x", 24<<20),
		}}}
		body, err := webanalysis.MarshalAST(tree)
		if err != nil {
			t.Fatal(err)
		}
		artifact, err := ws.Store.SaveWebArtifact(ctx, webanalysis.Artifact{
			Kind: webanalysis.ASTArtifactKind, URL: fmt.Sprintf("https://example.test/%d.js", i),
		}, body)
		if err != nil {
			t.Fatal(err)
		}
		snapshot.Artifacts = append(snapshot.Artifacts, artifact)
	}
	trees, gaps := webBundleTrees(ws, snapshot)
	if len(trees) != 2 || len(gaps) != 1 || !strings.Contains(gaps[0], "budget exhausted") {
		t.Errorf("loaded %d trees with gaps %v, want two trees and one budget gap", len(trees), gaps)
	}
}

func bundleFixture(t *testing.T) webanalysis.Bundle {
	t.Helper()
	b, err := webanalysis.BuildBundle(webanalysis.Snapshot{
		Units:      []webanalysis.SourceUnit{{ID: "u1", Language: "javascript", Hash: "h1"}},
		Operations: []webanalysis.Operation{{ID: "op1", Method: "GET", Origin: "https://example.com", Path: "/x"}},
	}, []webanalysis.AST{{Unit: "u1", Language: "javascript", Nodes: []webanalysis.ASTNode{{Type: "program", Parent: -1}}}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestWriteWebBundleWritesEveryFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundle")
	b := bundleFixture(t)
	written, err := writeWebBundle(dir, b)
	if err != nil {
		t.Fatal(err)
	}
	if len(written) != len(b.Files) {
		t.Fatalf("wrote %d of %d files", len(written), len(b.Files))
	}
	for _, f := range b.Files {
		path := filepath.Join(dir, filepath.FromSlash(f.Name))
		got, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("%s: %v", f.Name, err)
			continue
		}
		if webanalysis.Hash(got) != f.SHA256 {
			t.Errorf("%s was written with different bytes", f.Name)
		}
		st, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0600 {
			t.Errorf("%s has mode %v, want 0600", f.Name, st.Mode().Perm())
		}
	}
	// The shards land in their own directory, which the writer creates.
	if st, err := os.Lstat(filepath.Join(dir, "records")); err != nil || !st.IsDir() {
		t.Errorf("the records directory was not created: %v", err)
	}
	if st, err := os.Lstat(dir); err != nil || st.Mode().Perm() != 0700 {
		t.Errorf("the bundle directory has mode %v", st.Mode().Perm())
	}
}

func TestWriteWebBundleIsIdempotentAndReplacesADifferentBundle(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundle")
	b := bundleFixture(t)
	if _, err := writeWebBundle(dir, b); err != nil {
		t.Fatal(err)
	}
	if _, err := writeWebBundle(dir, b); err != nil {
		t.Fatalf("rewriting the same bundle failed: %v", err)
	}
	other, err := webanalysis.BuildBundle(webanalysis.Snapshot{
		Units: []webanalysis.SourceUnit{{ID: "u2", Language: "typescript", Hash: "h2"}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writeWebBundle(dir, other); err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if webanalysis.Hash(manifest) != webanalysis.Hash(mustBundleFile(t, other, "manifest.json").Data) {
		t.Error("the new manifest was not installed")
	}
}

func TestWriteWebBundleKeepsPreviousBundleWhenStagingFails(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundle")
	original := bundleFixture(t)
	if _, err := writeWebBundle(dir, original); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	invalid := bundleFixture(t)
	invalid.Files = append(invalid.Files, webanalysis.BundleFile{Name: "../outside", Data: []byte("x")})
	if written, err := writeWebBundle(dir, invalid); err == nil || len(written) != 0 {
		t.Fatalf("invalid bundle result = %v, %v", written, err)
	}
	after, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if webanalysis.Hash(after) != webanalysis.Hash(before) {
		t.Error("the previous bundle changed after staging failed")
	}
}

func mustBundleFile(t *testing.T, b webanalysis.Bundle, name string) webanalysis.BundleFile {
	t.Helper()
	f, ok := b.File(name)
	if !ok {
		t.Fatalf("bundle is missing %s", name)
	}
	return f
}

// A bundle file name is written where the manifest says, so a name that escapes the bundle directory is refused rather than cleaned.
func TestBundleFilePathRefusesAnEscapingName(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{
		"", "/etc/passwd", "../outside.json", "records/../../outside.json",
		"./records/x.json", "records//x.json", "records/x.json\x00",
		`records\x.json`, "..",
	} {
		if _, err := bundleFilePath(root, name); err == nil {
			t.Errorf("accepted %q", name)
		}
	}
	for _, name := range []string{"manifest.json", "records/units.00000.jsonl.gz", "index.html"} {
		path, err := bundleFilePath(root, name)
		if err != nil {
			t.Errorf("rejected %q: %v", name, err)
			continue
		}
		if !strings.HasPrefix(path, root+string(os.PathSeparator)) {
			t.Errorf("%q resolved to %q, outside the root", name, path)
		}
	}
}

func TestWriteWebBundleNeedsADirectory(t *testing.T) {
	if _, err := writeWebBundle("", bundleFixture(t)); err == nil {
		t.Error("an empty directory was accepted")
	}
}

// A bundle written to disk verifies against its own checksum list, so an analyst can check the directory without the tool that wrote it.
func TestWrittenBundleVerifiesAgainstItsChecksums(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundle")
	b := bundleFixture(t)
	if _, err := writeWebBundle(dir, b); err != nil {
		t.Fatal(err)
	}
	list, err := os.ReadFile(filepath.Join(dir, "checksums.txt"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, line := range strings.Split(strings.TrimRight(string(list), "\n"), "\n") {
		sum, name, ok := strings.Cut(line, "  ")
		if !ok {
			t.Fatalf("line %q is not a checksum entry", line)
		}
		got, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if webanalysis.Hash(got) != sum {
			t.Errorf("%s does not match its recorded checksum", name)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) < 10 {
		t.Errorf("the checksum list covers only %d files", len(names))
	}
	// The list itself is not in it, and nothing on disk is unlisted.
	entries, err := bundleTree(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e == "checksums.txt" {
			continue
		}
		if sort.SearchStrings(names, e) >= len(names) || names[sort.SearchStrings(names, e)] != e {
			t.Errorf("%s is on disk but not in the checksum list", e)
		}
	}
}

func TestWriteWebBundleRejectsTamperedContent(t *testing.T) {
	b := bundleFixture(t)
	for i := range b.Files {
		if b.Files[i].Name == "data.js" {
			b.Files[i].Data = append(b.Files[i].Data, 'x')
			break
		}
	}
	dir := filepath.Join(t.TempDir(), "bundle")
	if _, err := writeWebBundle(dir, b); err == nil {
		t.Fatal("tampered bundle was written")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("tampered bundle left output: %v", err)
	}
}

func TestWriteWebBundleRejectsTamperedMetadata(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*webanalysis.Bundle)
	}{
		{"size", func(b *webanalysis.Bundle) {
			for i := range b.Files {
				if b.Files[i].Name == "data.js" {
					b.Files[i].Bytes++
				}
			}
			for i := range b.Manifest.Files {
				if b.Manifest.Files[i].Name == "data.js" {
					b.Manifest.Files[i].Bytes++
				}
			}
		}},
		{"manifest", func(b *webanalysis.Bundle) {
			for i := range b.Files {
				if b.Files[i].Name == "manifest.json" {
					b.Files[i].Data = append(b.Files[i].Data, 'x')
				}
			}
		}},
		{"checksums", func(b *webanalysis.Bundle) {
			for i := range b.Files {
				if b.Files[i].Name == "checksums.txt" {
					b.Files[i].Data = append(b.Files[i].Data, 'x')
				}
			}
		}},
		{"duplicate", func(b *webanalysis.Bundle) {
			b.Files = append(b.Files, b.Files[0])
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := bundleFixture(t)
			tc.mutate(&b)
			dir := filepath.Join(t.TempDir(), "bundle")
			if _, err := writeWebBundle(dir, b); err == nil {
				t.Fatal("invalid bundle was written")
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatalf("invalid bundle left output: %v", err)
			}
		})
	}
}

// bundleTree lists the bundle-relative paths of every file under dir.
func bundleTree(dir string) ([]string, error) {
	var out []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	sort.Strings(out)
	return out, err
}

func TestWebBundleDirIsUnderTheWebEvidence(t *testing.T) {
	got := webBundleDir("/work/evidence")
	want := filepath.Join("/work/evidence", "web", "bundle")
	if got != want {
		t.Errorf("webBundleDir = %q, want %q", got, want)
	}
}

// A maximal syntax tree must fit the result the analysis worker may return, or a unit with a large tree would fail the whole parse.
func TestMaximalSyntaxTreeFitsTheWorkerResultLimit(t *testing.T) {
	var b strings.Builder
	b.WriteString("const xs = [")
	for i := 0; i < webanalysis.MaxASTNodes; i++ {
		b.WriteString("1,")
	}
	b.WriteString("];")
	out, _ := webanalysis.Analyze(context.Background(), webanalysis.Input{
		Unit:    webanalysis.SourceUnit{ID: "u1", Language: "javascript", Hash: "h"},
		Source:  []byte(b.String()),
		KeepAST: true,
	})
	if out.AST == nil {
		t.Fatal("no syntax tree was serialized")
	}
	if len(out.AST.Nodes) != webanalysis.MaxASTNodes {
		t.Fatalf("the tree holds %d nodes, want the bound %d", len(out.AST.Nodes), webanalysis.MaxASTNodes)
	}
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > webWorkerResultLimit {
		t.Errorf("a maximal tree gives a %d-byte result, past the worker limit of %d",
			len(raw), webWorkerResultLimit)
	}
}

// A relative bundle directory is refused, so a workspace with a relative evidence path cannot write the bundle into the working directory.
func TestWriteWebBundleRequiresAnAbsoluteDirectory(t *testing.T) {
	for _, dir := range []string{".", "bundle", "web/bundle", "./out", ".."} {
		if _, err := writeWebBundle(dir, bundleFixture(t)); err == nil {
			t.Errorf("accepted the relative directory %q", dir)
		}
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		switch e.Name() {
		case "manifest.json", "checksums.txt", "data.js", "index.html", "snapshot.json.gz", "records":
			t.Errorf("a bundle file was written into the working directory: %s", e.Name())
		}
	}
}
