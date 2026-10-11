package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// vulndb.go provisions scanner databases on the host before a worker reads them.

// vulnDBMount is where the scanner cache appears inside a worker.
const vulnDBMount = "/opt/vulndb"

// maxOSVDatabaseBytes bounds one ecosystem download.
const maxOSVDatabaseBytes = 1 << 30

// osvDatabaseBase publishes the OSV databases osv-scanner reads offline. Stubbed in tests.
var osvDatabaseBase = "https://osv-vulnerabilities.storage.googleapis.com"

// osvEcosystems are the OSV databases provisioned, one archive each.
func osvEcosystems() []string {
	return []string{
		"Go", "npm", "PyPI", "Maven", "crates.io", "RubyGems",
		"Packagist", "NuGet", "Alpine", "Debian",
	}
}

// osvDatabaseURL returns the published location of one ecosystem's database.
func osvDatabaseURL(ecosystem string) string {
	return osvDatabaseBase + "/" + ecosystem + "/all.zip"
}

// osvDatabasePath returns where osv-scanner reads one ecosystem's database under dir.
func osvDatabasePath(dir, ecosystem string) string {
	return filepath.Join(dir, "osv", "osv-scanner", ecosystem, "all.zip")
}

// grypeDatabaseDir returns the directory grype reads its database from under dir.
func grypeDatabaseDir(dir string) string { return filepath.Join(dir, "grype") }

// vulnDBDir returns the directory holding the scanner databases, honoring XDG_CACHE_HOME.
func vulnDBDir() (string, error) {
	base := os.Getenv("XDG_CACHE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".cache")
	}
	return filepath.Join(base, "blkchain", "vulndb"), nil
}

// vulnDBCacheDir returns the scanner cache directory, readable through a worker's read-only mount.
func vulnDBCacheDir() string {
	dir, err := vulnDBDir()
	if err != nil {
		return ""
	}
	if err := os.MkdirAll(filepath.Join(dir, "osv", "osv-scanner"), 0o755); err != nil {
		return ""
	}
	if err := os.MkdirAll(grypeDatabaseDir(dir), 0o755); err != nil {
		return ""
	}
	if err := makeVulnDBReadable(dir); err != nil {
		return ""
	}
	return dir
}

func makeVulnDBReadable(dir string) error {
	return filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return os.Chmod(path, 0o755)
		}
		if entry.Type().IsRegular() {
			return os.Chmod(path, 0o644)
		}
		return nil
	})
}

// downloadOSVDatabase writes one ecosystem's database to its path under dir, through a temporary file so a failed download leaves no partial archive a scan would read as a database.
func downloadOSVDatabase(ctx context.Context, client *http.Client, dir, ecosystem string) error {
	path := osvDatabasePath(dir, ecosystem)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, osvDatabaseURL(ecosystem), nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s database: %s", ecosystem, resp.Status)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "all-*.zip")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	written, err := io.Copy(tmp, io.LimitReader(resp.Body, maxOSVDatabaseBytes+1))
	if err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if written > maxOSVDatabaseBytes {
		return fmt.Errorf("%s database exceeds %d bytes", ecosystem, maxOSVDatabaseBytes)
	}
	if written == 0 {
		return fmt.Errorf("%s database is empty", ecosystem)
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// updateVulnDB downloads both scanner databases into dir before workers scan offline.
func updateVulnDB(ctx context.Context, dir string, out io.Writer) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	client := &http.Client{Timeout: 30 * time.Minute}
	var failed []string
	for _, ecosystem := range osvEcosystems() {
		fmt.Fprintf(out, "osv-scanner: %s\n", ecosystem)
		if err := downloadOSVDatabase(ctx, client, dir, ecosystem); err != nil {
			if ctx.Err() != nil {
				return err
			}
			failed = append(failed, fmt.Sprintf("%s: %s", ecosystem, err))
		}
	}
	fmt.Fprintln(out, "grype: vulnerability database")
	if err := updateGrypeDatabase(ctx, grypeDatabaseDir(dir)); err != nil {
		failed = append(failed, "grype: "+err.Error())
	}
	if err := makeVulnDBReadable(dir); err != nil {
		failed = append(failed, "cache permissions: "+err.Error())
	}
	if len(failed) > 0 {
		return errors.New("scanner database update failed: " + strings.Join(failed, "; "))
	}
	return nil
}

// updateGrypeDatabase runs grype's own update in the runner image, which is where grype exists, with the database directory bound writable for this one step.
func updateGrypeDatabase(ctx context.Context, dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	image := defaultRunnerTag()
	args := []string{
		"run", "--rm", "--pull", "never", "--network", "bridge", "--read-only",
		"--tmpfs", "/work:rw,nosuid,nodev,size=64m", "--tmpfs", "/tmp:rw,nosuid,nodev,size=8g",
		"--mount", "type=bind,src=" + absolute + ",dst=/db",
		"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--memory", "2g", "--cpus", "2", "--pids-limit", "64",
		"--env", "HOME=/work", "--env", "GRYPE_DB_CACHE_DIR=/db",
		"--env", "GRYPE_CHECK_FOR_APP_UPDATE=false",
		"--entrypoint", "grype", image, "db", "update",
	}
	_, err = runnerDocker(ctx, nil, args...)
	return err
}
