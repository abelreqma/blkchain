package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
)

// modelprefs.go is the saved model settings behind /models: which chat models
// the model picker hides, and whether the reranker and the web-search fallback
// run. It lives in a small JSON file beside the history file. It never holds a
// secret.

// prefsMaxBytes caps how much of the prefs file is read.
const prefsMaxBytes = 64 << 10

// modelPrefs is the saved model settings. The zero value of a missing field is
// replaced by its default on load (see loadPrefs).
type modelPrefs struct {
	Hidden []string `json:"hidden,omitempty"`
	Rerank bool     `json:"rerank"`
	Web    bool     `json:"web"`
}

// defaultPrefs hides nothing and runs the reranker and the web fallback.
func defaultPrefs() modelPrefs { return modelPrefs{Rerank: true, Web: true} }

// prefsPath is models.json in the config directory the CLI already uses for the
// saved project root and the history, created private if needed.
func prefsPath() (string, error) {
	root, err := configPath()
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(root)
	if err := privateDir(dir); err != nil {
		return "", err
	}
	return filepath.Join(dir, "models.json"), nil
}

// loadPrefs reads the saved settings. A missing, unreadable, oversize, or
// corrupt file, and a symlink, all yield the defaults; a field the file leaves
// out keeps its default.
func loadPrefs() modelPrefs {
	p := defaultPrefs()
	path, err := prefsPath()
	if err != nil {
		return p
	}
	if fi, err := os.Lstat(path); err != nil || !fi.Mode().IsRegular() {
		return p
	}
	f, err := os.Open(path)
	if err != nil {
		return p
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, prefsMaxBytes+1))
	if err != nil || len(data) > prefsMaxBytes {
		return p
	}
	if err := json.Unmarshal(data, &p); err != nil {
		return defaultPrefs()
	}
	return p
}

// savePrefs writes the settings atomically: a private temp file in the same
// directory, then a rename over the old file. The rename replaces a symlink at
// the path instead of following it.
func savePrefs(p modelPrefs) error {
	path, err := prefsPath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".models-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op once the rename has moved it
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// isHidden reports whether the model picker hides id.
func (p modelPrefs) isHidden(id string) bool { return slices.Contains(p.Hidden, id) }

// withHidden returns p with id hidden or shown. It never changes p's own list.
func (p modelPrefs) withHidden(id string, hide bool) modelPrefs {
	hidden := slices.DeleteFunc(slices.Clone(p.Hidden), func(h string) bool { return h == id })
	if hide {
		hidden = append(hidden, id)
	}
	p.Hidden = hidden
	return p
}
