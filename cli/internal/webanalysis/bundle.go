package webanalysis

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// bundle.go turns a snapshot into sharded JSONL, a gzipped snapshot, a checksummed manifest and an offline viewer, deterministically and without touching disk.

// BundleVersion is the bundle layout this package writes.
const BundleVersion = "blkchain-web-bundle/1"

// MaxShardRecords bounds one JSONL shard.
const MaxShardRecords = 5000

// MaxBundleBytes bounds a whole bundle.
const MaxBundleBytes = 512 << 20

// MaxViewerRecords bounds how many records of each kind the viewer embeds; the rest stay in the shards.
const MaxViewerRecords = 200

// BundleFile is one file of a bundle.
type BundleFile struct {
	// Name is the file's path inside the bundle.
	Name string `json:"name"`
	// Kind is the record kind a shard holds, empty for a bundle-level file.
	Kind string `json:"kind,omitempty"`
	// Shard is the zero-based shard index within its kind.
	Shard int `json:"shard,omitempty"`
	// Records is how many records the file holds.
	Records int `json:"records,omitempty"`
	// Bytes and SHA256 describe the file as written.
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
	// Gzip reports whether the content is gzip-compressed.
	Gzip bool `json:"gzip,omitempty"`
	// Data is the file's content. It is not part of the manifest.
	Data []byte `json:"-"`
}

// BundleManifest describes a bundle's content.
type BundleManifest struct {
	Version string `json:"version"`
	// Counts is the record count per kind in the snapshot.
	Counts map[string]int `json:"counts"`
	// Files lists every file in the bundle, ordered by name.
	Files []BundleFile `json:"files"`
	// Gaps names what the bundle does not hold.
	Gaps []string `json:"gaps,omitempty"`
}

// Bundle is a manifest and the files it describes.
type Bundle struct {
	Manifest BundleManifest
	Files    []BundleFile
}

// File returns the bundle file with the given name.
func (b Bundle) File(name string) (BundleFile, bool) {
	for _, f := range b.Files {
		if f.Name == name {
			return f, true
		}
	}
	return BundleFile{}, false
}

// TotalBytes is the size of every file in the bundle.
func (b Bundle) TotalBytes() int {
	n := 0
	for _, f := range b.Files {
		n += f.Bytes
	}
	return n
}

// bundleKind is one record kind and the records it holds, read from a snapshot.
type bundleKind struct {
	name    string
	records func(Snapshot) []any
}

// bundleKinds is every record kind a bundle shards.
func bundleKinds() []bundleKind {
	return []bundleKind{
		{"requests", func(s Snapshot) []any { return anySlice(s.Requests) }},
		{"exports", func(s Snapshot) []any { return anySlice(s.Exports) }},
		{"artifacts", func(s Snapshot) []any { return anySlice(s.Artifacts) }},
		{"units", func(s Snapshot) []any { return anySlice(s.Units) }},
		{"functions", func(s Snapshot) []any { return anySlice(s.Functions) }},
		{"calls", func(s Snapshot) []any { return anySlice(s.Calls) }},
		{"operations", func(s Snapshot) []any { return anySlice(s.Operations) }},
		{"relationships", func(s Snapshot) []any { return anySlice(s.Relationships) }},
		{"findings", func(s Snapshot) []any { return anySlice(s.Findings) }},
		{"features", func(s Snapshot) []any { return anySlice(s.Features) }},
		{"coverage", func(s Snapshot) []any { return anySlice(s.Coverage) }},
	}
}

func anySlice[T any](in []T) []any {
	out := make([]any, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}

// BuildBundle assembles a bundle from a snapshot, its units' syntax trees and the caller's own gaps, leaving out a tree with no unit.
func BuildBundle(s Snapshot, trees []AST, callerGaps ...string) (Bundle, error) {
	gaps := append([]string(nil), callerGaps...)
	manifest := BundleManifest{Version: BundleVersion, Counts: map[string]int{}}
	var files []BundleFile

	for _, k := range bundleKinds() {
		records := k.records(s)
		manifest.Counts[k.name] = len(records)
		shards, err := shardJSONL(k.name, records)
		if err != nil {
			return Bundle{}, err
		}
		files = append(files, shards...)
	}

	units := map[string]bool{}
	for _, u := range s.Units {
		units[u.ID] = true
	}
	var kept []AST
	treeUnits := map[string]bool{}
	for _, t := range trees {
		if !units[t.Unit] {
			gaps = append(gaps, "syntax tree for unit "+t.Unit+" has no unit record in this snapshot")
			continue
		}
		if t.Truncated {
			gaps = append(gaps, "syntax tree for unit "+t.Unit+" is truncated: "+t.Gap)
		}
		treeUnits[t.Unit] = true
		kept = append(kept, t)
	}
	for _, u := range s.Units {
		if (u.Parse == "ok" || u.Parse == "partial") && !treeUnits[u.ID] {
			gaps = append(gaps, "syntax tree for unit "+u.ID+" is absent")
		}
	}
	manifest.Counts["ast"] = len(kept)
	astShards, err := shardJSONL("ast", anySlice(kept))
	if err != nil {
		return Bundle{}, err
	}
	files = append(files, astShards...)

	whole, err := json.Marshal(s)
	if err != nil {
		return Bundle{}, err
	}
	compressed, err := gzipBytes(whole)
	if err != nil {
		return Bundle{}, err
	}
	files = append(files, bundleFile("snapshot.json.gz", "", 0, 0, compressed, true))

	viewer, err := viewerData(s, kept)
	if err != nil {
		return Bundle{}, err
	}
	files = append(files, bundleFile("data.js", "", 0, 0, viewer, false))
	files = append(files, bundleFile("index.html", "", 0, 0, []byte(bundleViewerHTML), false))

	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	// The manifest describes the data files, so it copies the list before those two are added.
	manifest.Files = append([]BundleFile(nil), files...)
	manifest.Gaps = gaps

	manifestJSON, err := json.MarshalIndent(manifest, "", " ")
	if err != nil {
		return Bundle{}, err
	}
	files = append(files, bundleFile("manifest.json", "", 0, 0, append(manifestJSON, '\n'), false))
	files = append(files, bundleFile("checksums.txt", "", 0, 0, checksumList(files), false))
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })

	out := Bundle{Manifest: manifest, Files: files}
	if out.TotalBytes() > MaxBundleBytes {
		return Bundle{}, errors.New("bundle exceeds the size limit")
	}
	return out, nil
}

// bundleFile describes one file and its content.
func bundleFile(name, kind string, shard, records int, data []byte, gz bool) BundleFile {
	return BundleFile{
		Name: name, Kind: kind, Shard: shard, Records: records,
		Bytes: len(data), SHA256: Hash(data), Gzip: gz, Data: data,
	}
}

// shardJSONL writes records as gzipped JSONL, one file per MaxShardRecords, with one empty shard for an empty kind.
func shardJSONL(kind string, records []any) ([]BundleFile, error) {
	var out []BundleFile
	for shard := 0; ; shard++ {
		start := shard * MaxShardRecords
		end := start + MaxShardRecords
		if end > len(records) {
			end = len(records)
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		for _, r := range records[start:end] {
			if err := enc.Encode(r); err != nil {
				return nil, err
			}
		}
		data, err := gzipBytes(buf.Bytes())
		if err != nil {
			return nil, err
		}
		name := fmt.Sprintf("records/%s.%05d.jsonl.gz", kind, shard)
		out = append(out, bundleFile(name, kind, shard, end-start, data, true))
		if end >= len(records) {
			return out, nil
		}
	}
}

// gzipBytes compresses b with no header modification time, so the same input gives the same bytes.
func gzipBytes(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(b); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// gunzipBounded decompresses b and fails once the output passes limit.
func gunzipBounded(b []byte, limit int64) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	var out bytes.Buffer
	if _, err := out.ReadFrom(io.LimitReader(r, limit+1)); err != nil {
		return nil, err
	}
	if int64(out.Len()) > limit {
		return nil, errors.New("decompressed bundle member exceeds the size limit")
	}
	return out.Bytes(), nil
}

// checksumList renders "<sha256>  <name>" for every file, ordered by name.
func checksumList(files []BundleFile) []byte {
	lines := make([]string, 0, len(files))
	for _, f := range files {
		lines = append(lines, f.SHA256+"  "+f.Name)
	}
	sort.Strings(lines)
	return []byte(strings.Join(lines, "\n") + "\n")
}

// VerifyBundle recomputes every file's checksum against the manifest and reports the mismatches.
func VerifyBundle(b Bundle) []string {
	var bad []string
	files := make(map[string]BundleFile, len(b.Files))
	var checksumFiles []BundleFile
	total := 0
	for _, f := range b.Files {
		if _, duplicate := files[f.Name]; duplicate {
			bad = append(bad, f.Name+": duplicate file")
			continue
		}
		files[f.Name] = f
		if f.Name != "checksums.txt" {
			checksumFiles = append(checksumFiles, f)
		}
		if len(f.Data) != f.Bytes || Hash(f.Data) != f.SHA256 {
			bad = append(bad, f.Name+": content does not match file metadata")
		}
		if len(f.Data) > MaxBundleBytes-total {
			bad = append(bad, "bundle exceeds the size limit")
		} else {
			total += len(f.Data)
		}
	}
	listed := map[string]bool{}
	for _, m := range b.Manifest.Files {
		if listed[m.Name] {
			bad = append(bad, m.Name+": duplicate manifest entry")
			continue
		}
		listed[m.Name] = true
		f, ok := files[m.Name]
		if !ok {
			bad = append(bad, m.Name+": listed in the manifest but absent")
			continue
		}
		if f.Bytes != m.Bytes || f.SHA256 != m.SHA256 {
			bad = append(bad, m.Name+": metadata does not match the manifest")
		}
	}
	for name := range files {
		switch name {
		case "manifest.json", "checksums.txt":
			continue
		}
		if !listed[name] {
			bad = append(bad, name+": present but not listed in the manifest")
		}
	}
	manifest, ok := b.File("manifest.json")
	if !ok {
		bad = append(bad, "manifest.json: absent")
	} else if data, err := json.MarshalIndent(b.Manifest, "", " "); err != nil || !bytes.Equal(manifest.Data, append(data, '\n')) {
		bad = append(bad, "manifest.json: content does not match the manifest")
	}
	checksums, ok := b.File("checksums.txt")
	if !ok {
		bad = append(bad, "checksums.txt: absent")
	} else if !bytes.Equal(checksums.Data, checksumList(checksumFiles)) {
		bad = append(bad, "checksums.txt: content does not match the files")
	}
	sort.Strings(bad)
	return bad
}

// viewerData renders a bounded sample of each kind into one global, which a page opened from the filesystem can read.
func viewerData(s Snapshot, trees []AST) ([]byte, error) {
	payload := map[string]any{
		"version": BundleVersion,
		"limit":   MaxViewerRecords,
		"counts":  map[string]int{},
		"kinds":   map[string]any{},
	}
	counts := payload["counts"].(map[string]int)
	kinds := payload["kinds"].(map[string]any)
	for _, k := range bundleKinds() {
		records := k.records(s)
		counts[k.name] = len(records)
		if len(records) > MaxViewerRecords {
			records = records[:MaxViewerRecords]
		}
		kinds[k.name] = records
	}
	counts["ast"] = len(trees)
	summaries := make([]map[string]any, 0, len(trees))
	for _, t := range trees {
		if len(summaries) == MaxViewerRecords {
			break
		}
		summaries = append(summaries, map[string]any{
			"unit": t.Unit, "language": t.Language, "nodes": len(t.Nodes),
			"truncated": t.Truncated, "types": len(t.NodeTypes()),
		})
	}
	kinds["ast"] = summaries
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return append(append([]byte("window.BLK_BUNDLE = "), body...), ";\n"...), nil
}
