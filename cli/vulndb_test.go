package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The database directory follows XDG_CACHE_HOME, so an operator can place it off the home volume.
func TestVulnDBDirFollowsTheCacheHome(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", "/tmp/cache-home")
	dir, err := vulnDBDir()
	if err != nil {
		t.Fatal(err)
	}
	if dir != filepath.Join("/tmp/cache-home", "blkchain", "vulndb") {
		t.Errorf("the database directory is %q", dir)
	}
	t.Setenv("XDG_CACHE_HOME", "")
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	dir, err = vulnDBDir()
	if err != nil {
		t.Fatal(err)
	}
	if dir != filepath.Join(home, ".cache", "blkchain", "vulndb") {
		t.Errorf("the default database directory is %q", dir)
	}
}

// The cache directory a worker is given exists and is readable through its read-only mount.
func TestVulnDBCacheDirIsCreatedForBothScanners(t *testing.T) {
	cache := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cache)
	dir := vulnDBCacheDir()
	want := filepath.Join(cache, "blkchain", "vulndb")
	if dir != want {
		t.Fatalf("the cache directory is %q, want %q", dir, want)
	}
	for _, path := range []string{
		filepath.Join(dir, "osv", "osv-scanner"),
		grypeDatabaseDir(dir),
	} {
		info, err := os.Stat(path)
		if err != nil || !info.IsDir() {
			t.Errorf("%s was not created: %v", path, err)
		}
		if mode := info.Mode().Perm(); mode != 0o755 {
			t.Errorf("%s has mode %o, want 755", path, mode)
		}
	}
	// A second call is harmless, because every engagement asks for the directory.
	if again := vulnDBCacheDir(); again != dir {
		t.Errorf("a repeated call returned %q, want %q", again, dir)
	}
}

func TestVulnDBCacheDirMakesExistingDataReadable(t *testing.T) {
	cache := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cache)
	dir := filepath.Join(cache, "blkchain", "vulndb")
	path := osvDatabasePath(dir, "Go")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("database"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := vulnDBCacheDir(); got != dir {
		t.Fatalf("cache directory = %q, want %q", got, dir)
	}
	for _, p := range []string{dir, filepath.Dir(path)} {
		info, err := os.Stat(p)
		if err != nil || info.Mode().Perm() != 0o755 {
			t.Errorf("%s remains unreadable: %v", p, err)
		}
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Errorf("database remains unreadable: %v", err)
	}
}

// Every provisioned database is fetched from the published OSV location over TLS.
func TestOSVDatabaseURLsArePublishedLocations(t *testing.T) {
	if len(osvEcosystems()) == 0 {
		t.Fatal("no ecosystem is provisioned")
	}
	seen := map[string]bool{}
	for _, ecosystem := range osvEcosystems() {
		if seen[ecosystem] {
			t.Errorf("%s is provisioned twice", ecosystem)
		}
		seen[ecosystem] = true
		url := osvDatabaseURL(ecosystem)
		if !strings.HasPrefix(url, "https://") {
			t.Errorf("%s is fetched over %s", ecosystem, url)
		}
		if !strings.HasSuffix(url, "/"+ecosystem+"/all.zip") {
			t.Errorf("%s resolves to %s", ecosystem, url)
		}
	}
	for _, want := range []string{"Go", "npm", "PyPI"} {
		if !seen[want] {
			t.Errorf("%s has no provisioned database", want)
		}
	}
}

// A download is written through a temporary file, so a failed or oversized transfer leaves no partial archive a scan would read as a database.
func TestDownloadOSVDatabaseLeavesNoPartialArchive(t *testing.T) {
	var body []byte
	status := http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		w.Write(body)
	}))
	defer server.Close()
	previous := osvDatabaseBase
	t.Cleanup(func() { osvDatabaseBase = previous })
	osvDatabaseBase = server.URL

	dir := t.TempDir()
	path := osvDatabasePath(dir, "Go")
	client := server.Client()

	body, status = []byte("real-archive"), http.StatusOK
	if err := downloadOSVDatabase(context.Background(), client, dir, "Go"); err != nil {
		t.Fatalf("a served archive failed: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "real-archive" {
		t.Fatalf("the archive was not written: %q %v", got, err)
	}

	body, status = []byte("error page"), http.StatusNotFound
	if err := downloadOSVDatabase(context.Background(), client, dir, "Go"); err == nil {
		t.Error("a 404 was accepted as a database")
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "real-archive" {
		t.Errorf("a failed download replaced the archive: %q %v", got, err)
	}

	body, status = nil, http.StatusOK
	if err := downloadOSVDatabase(context.Background(), client, dir, "npm"); err == nil {
		t.Error("an empty body was accepted as a database")
	}
	if _, err := os.Stat(osvDatabasePath(dir, "npm")); !os.IsNotExist(err) {
		t.Error("an empty download left an archive behind")
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != "all.zip" {
			t.Errorf("a temporary file was left behind: %s", entry.Name())
		}
	}
}

// A worker receives the prewarmed cache read-only and receives no mount when the cache is unavailable.
func TestWorkerMountsTheDatabaseCache(t *testing.T) {
	want := "type=bind,src=/db/vulndb,dst=" + vulnDBMount
	with := strings.Join(engageWorkerArgs("w", "guard", "img", "", "/db/vulndb", nil), " ")
	if !strings.Contains(with, want) {
		t.Errorf("the worker does not mount the database cache: %s", with)
	}
	if !strings.Contains(with, want+",readonly") {
		t.Errorf("the worker can change the shared scanner database: %s", with)
	}
	raw := strings.Join(engageRawWorkerArgs("w", "guard", "img", "", "/db/vulndb", nil), " ")
	if !strings.Contains(raw, want) {
		t.Errorf("the raw worker does not mount the database cache: %s", raw)
	}
	without := strings.Join(engageWorkerArgs("w", "guard", "img", "", "", nil), " ")
	if strings.Contains(without, vulnDBMount) {
		t.Errorf("a worker with no cache directory still mounts one: %s", without)
	}
}

// The runner script points each scanner at the mount it reads its database from.
func TestRunnerScriptPointsScannersAtTheMount(t *testing.T) {
	script, err := engageRunnerFiles.ReadFile("runner/execute.py")
	if err != nil {
		t.Fatal(err)
	}
	body := string(script)
	for _, want := range []string{
		`VULN_DB_MOUNT = "` + vulnDBMount + `"`,
		`os.path.join(VULN_DB_MOUNT, "osv")`,
		`command_env["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"]`,
		`command_env["GRYPE_DB_CACHE_DIR"] = grype_db`,
		`"GRYPE_DB_AUTO_UPDATE": "false"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the runner script is missing %s", want)
		}
	}
}
