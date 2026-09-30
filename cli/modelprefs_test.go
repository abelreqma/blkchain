package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func prefsFile(t *testing.T) string {
	t.Helper()
	p, err := prefsPath()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPrefsDefaultsWhenMissingOrCorrupt(t *testing.T) {
	isolateUserDirs(t)
	want := modelPrefs{Rerank: true, Web: true, Rag: true, Viz: true}
	if got := loadPrefs(); !reflect.DeepEqual(got, want) {
		t.Errorf("missing file: got %+v, want %+v", got, want)
	}
	if err := os.WriteFile(prefsFile(t), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := loadPrefs(); !reflect.DeepEqual(got, want) {
		t.Errorf("corrupt file: got %+v, want %+v", got, want)
	}
	// A file that sets only one switch keeps the other at its default.
	if err := os.WriteFile(prefsFile(t), []byte(`{"web":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := loadPrefs(); !got.Rerank || got.Web {
		t.Errorf("partial file: got %+v, want rerank on and web off", got)
	}
}

func TestPrefsRoundTripAndMode(t *testing.T) {
	isolateUserDirs(t)
	in := modelPrefs{Hidden: []string{"a", "b/c"}, Rerank: false, Web: true, Rag: true, Viz: true}
	if err := savePrefs(in); err != nil {
		t.Fatal(err)
	}
	if got := loadPrefs(); !reflect.DeepEqual(got, in) {
		t.Errorf("round trip: got %+v, want %+v", got, in)
	}
	fi, err := os.Stat(prefsFile(t))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("prefs file mode = %v, want 0600", fi.Mode().Perm())
	}
	di, err := os.Stat(filepath.Dir(prefsFile(t)))
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Errorf("config dir mode = %v, want 0700", di.Mode().Perm())
	}
}

// Save replaces the file by rename: it leaves no temp file behind, and a
// symlink planted at the path is replaced, not followed, so the file it points
// at is never written.
func TestPrefsSaveIsAtomicAndDoesNotFollowSymlinks(t *testing.T) {
	isolateUserDirs(t)
	path := prefsFile(t)
	outside := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if err := savePrefs(modelPrefs{Rerank: true, Web: false, Rag: true, Viz: true}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(outside); string(b) != "keep" {
		t.Errorf("save wrote through the symlink: %q", b)
	}
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("prefs path is still a symlink (%v)", err)
	}
	if got := loadPrefs(); got.Web {
		t.Errorf("saved prefs not read back: %+v", got)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".models-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func TestPrefsLoadRejectsOversizeAndSymlink(t *testing.T) {
	isolateUserDirs(t)
	path := prefsFile(t)
	big := `{"web":false,"hidden":["` + strings.Repeat("x", prefsMaxBytes) + `"]}`
	if err := os.WriteFile(path, []byte(big), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := loadPrefs(); !got.Web || len(got.Hidden) != 0 {
		t.Errorf("oversize file should load as defaults, got web=%v hidden=%d", got.Web, len(got.Hidden))
	}

	os.Remove(path)
	target := filepath.Join(t.TempDir(), "elsewhere.json")
	if err := os.WriteFile(target, []byte(`{"web":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if got := loadPrefs(); !got.Web {
		t.Error("a symlinked prefs file should be ignored")
	}
}

func TestPrefsHiddenToggle(t *testing.T) {
	var p modelPrefs
	p = p.withHidden("a", true)
	p = p.withHidden("a", true)
	p = p.withHidden("b", true)
	if !p.isHidden("a") || !p.isHidden("b") || len(p.Hidden) != 2 {
		t.Fatalf("hide: %+v", p)
	}
	orig := p
	p = p.withHidden("a", false)
	if p.isHidden("a") || !p.isHidden("b") {
		t.Errorf("show: %+v", p)
	}
	if !orig.isHidden("a") {
		t.Error("withHidden changed the original value")
	}
}

func TestPrefsVizDefaultsTrueAndSurvivesMissingKey(t *testing.T) {
	if !defaultPrefs().Viz {
		t.Fatalf("defaultPrefs().Viz should be true")
	}
	p := defaultPrefs()
	if err := json.Unmarshal([]byte(`{"rerank":true,"web":true}`), &p); err != nil {
		t.Fatal(err)
	}
	if !p.Viz {
		t.Fatalf("viz should stay true when the key is absent, got false")
	}
}

func TestDefaultPrefsRagOn(t *testing.T) {
	if !defaultPrefs().Rag {
		t.Error("defaultPrefs().Rag = false, want true")
	}
}
