package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// gateway.go implements `blk gateway`: the one optional setup step that unlocks
// the richer Hermes agent mode (streaming sessions, model switch). It provisions
// ~/.hermes/.env with API_SERVER_ENABLED=true and API_SERVER_KEY=<secret>, then
// launches `hermes gateway`.
//
// Security: the secret is read from OMLX_API (falling back to OMLX_API_KEY),
// preferring the process env, then the project .env. It is never written to
// stdout/stderr, argv, or logs — only key names are printed. ~/.hermes/.env is
// upserted (existing lines, comments, and order preserved) and written atomically
// with 0600 perms; a single backup is kept when a value actually changes.

const (
	// gatewayBackupSuffix is appended to ~/.hermes/.env for the pre-change backup.
	gatewayBackupSuffix = ".bak-before-blk-gateway"
	// hermesEnvKeyEnabled / hermesEnvKeySecret are the two keys we provision.
	hermesEnvKeyEnabled = "API_SERVER_ENABLED"
	hermesEnvKeySecret  = "API_SERVER_KEY"
)

// envKV is one line to upsert into an env file. When secret is true the value is
// redacted from all user-facing output.
type envKV struct {
	key    string
	val    string
	secret bool
}

// defineGatewayFlags declares `blk gateway`'s flags.
func defineGatewayFlags(fs *flag.FlagSet, setupOnly *bool) {
	fs.BoolVar(setupOnly, "setup-only", false, "write ~/.hermes/.env but do not start the gateway")
}

// runGateway provisions ~/.hermes/.env and launches `hermes gateway`. With
// --setup-only it provisions and exits without launching.
func runGateway(args []string) error {
	var setupOnly bool
	fs := newFlagSet("gateway")
	defineGatewayFlags(fs, &setupOnly)
	if err := parseFlags(fs, args); err != nil {
		return err
	}

	root, err := projectRoot()
	if err != nil {
		return fmt.Errorf("gateway: %w", err)
	}

	secret, source, err := resolveGatewaySecret(root)
	if err != nil {
		return err
	}

	envPath, err := hermesEnvPath()
	if err != nil {
		return err
	}

	updates := []envKV{
		{key: hermesEnvKeyEnabled, val: "true"},
		{key: hermesEnvKeySecret, val: secret, secret: true},
	}

	if err := os.MkdirAll(filepath.Dir(envPath), 0o700); err != nil {
		return fmt.Errorf("gateway: cannot create %s: %w", filepath.Dir(envPath), err)
	}

	changed, err := writeEnvFile(envPath, updates)
	if err != nil {
		return fmt.Errorf("gateway: %w", err)
	}

	fmt.Fprintf(os.Stderr, "%s %s\n", Meta.Render("gateway:"), Meta.Render(envPath))
	for _, line := range summarizeUpdates(updates) {
		fmt.Fprintf(os.Stderr, "  %s %s\n", OK.Render(Glyph(GlyphOK)), line)
	}
	fmt.Fprintf(os.Stderr, "  %s\n", Meta.Render(fmt.Sprintf("API_SERVER_KEY taken from %s", source)))
	if !changed {
		fmt.Fprintf(os.Stderr, "  %s\n", Meta.Render("(no changes needed)"))
	}

	if setupOnly {
		fmt.Fprintf(os.Stderr, "%s run %s to start it\n", Meta.Render(Glyph(GlyphArrow)), Key.Render("hermes gateway"))
		return nil
	}

	path, err := exec.LookPath(hermesBin)
	if err != nil {
		return fmt.Errorf("gateway: %q not found on PATH, install Hermes Agent or run %q yourself", hermesBin, "hermes gateway")
	}
	fmt.Fprintf(os.Stderr, "%s %s\n", Meta.Render(Glyph(GlyphArrow)), Meta.Render("hermes gateway"))
	c := exec.Command(path, "gateway")
	c.Stdin = os.Stdin
	// A piped Python child block-buffers stdout, which would hold log lines
	// until about 8 KB and reorder them against stderr.
	c.Env = append(os.Environ(), "PYTHONUNBUFFERED=1")
	// A foreground server is normally ended with ctrl+c, which is not an error.
	if _, err := runSanitized(c); err != nil {
		return fmt.Errorf("hermes gateway: %w", err)
	}
	return nil
}

// hermesEnvPath returns ~/.hermes/.env, honoring HERMES_HOME (matching doctor.go).
func hermesEnvPath() (string, error) {
	home := strings.TrimSpace(os.Getenv("HERMES_HOME"))
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("gateway: cannot resolve home dir: %w", err)
		}
		home = filepath.Join(h, ".hermes")
	}
	return filepath.Join(home, ".env"), nil
}

// resolveGatewaySecret finds the gateway secret, preferring the process env over
// the project .env, and OMLX_API over OMLX_API_KEY. It returns the value, a
// human-readable source label (never the value), and an error naming the var to
// set if nothing is found. The value is never included in the error.
func resolveGatewaySecret(root string) (value, source string, err error) {
	for _, key := range []string{"OMLX_API", "OMLX_API_KEY"} {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			return v, key, nil
		}
	}
	if data, rerr := os.ReadFile(filepath.Join(root, ".env")); rerr == nil {
		for _, key := range []string{"OMLX_API", "OMLX_API_KEY"} {
			if v, ok := parseDotenvValue(data, key); ok && v != "" {
				return v, key + " (.env)", nil
			}
		}
	}
	return "", "", fmt.Errorf(
		"gateway: no oMLX key found, set OMLX_API (or OMLX_API_KEY) in the environment or in %s",
		filepath.Join(root, ".env"))
}

// parseDotenvValue reads a KEY=value from a .env byte slice: it skips comments
// and blanks, tolerates a leading `export `, trims surrounding whitespace, and
// strips one layer of matching single or double quotes. The last occurrence wins.
func parseDotenvValue(data []byte, key string) (string, bool) {
	value, found := "", false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(k) != key {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 {
			if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
				v = v[1 : len(v)-1]
			}
		}
		value, found = v, true
	}
	return value, found
}

// upsertEnvLines returns existing with each update applied: an existing `KEY=...`
// line is replaced in place (last match wins), a missing key is appended. All
// other lines, comments, and ordering are preserved. The result always ends with
// a single trailing newline.
func upsertEnvLines(existing []byte, updates []envKV) []byte {
	lines := []string{}
	if len(existing) > 0 {
		lines = strings.Split(strings.TrimRight(string(existing), "\n"), "\n")
	}

	for _, u := range updates {
		newLine := u.key + "=" + u.val
		replaced := false
		for i, raw := range lines {
			trimmed := strings.TrimPrefix(strings.TrimSpace(raw), "export ")
			k, _, ok := strings.Cut(trimmed, "=")
			if ok && strings.TrimSpace(k) == u.key {
				lines[i] = newLine
				replaced = true
			}
		}
		if !replaced {
			lines = append(lines, newLine)
		}
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

// writeEnvFile upserts updates into the env file at path and writes it atomically
// with 0600 perms (preserving the existing mode if stricter). It reports whether
// the content changed. When it changes an existing file, one backup is written to
// path+gatewayBackupSuffix first. An unchanged file is left untouched (no write,
// no backup).
func writeEnvFile(path string, updates []envKV) (changed bool, err error) {
	existing, readErr := os.ReadFile(path)
	if readErr != nil && !os.IsNotExist(readErr) {
		return false, fmt.Errorf("read %s: %w", path, readErr)
	}
	fileExisted := readErr == nil

	next := upsertEnvLines(existing, updates)
	if fileExisted && string(existing) == string(next) {
		return false, nil
	}

	mode := os.FileMode(0o600)
	if fileExisted {
		if info, serr := os.Stat(path); serr == nil {
			mode = info.Mode().Perm() & 0o600 // never widen; clamp to owner rw at most
		}
		if err := os.WriteFile(path+gatewayBackupSuffix, existing, 0o600); err != nil {
			return false, fmt.Errorf("write backup: %w", err)
		}
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".env.tmp-*")
	if err != nil {
		return false, fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(next); err != nil {
		tmp.Close()
		return false, fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return false, fmt.Errorf("chmod temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return false, fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return false, fmt.Errorf("rename into place: %w", err)
	}
	return true, nil
}

// summarizeUpdates renders one status line per update, redacting secret values so
// they never reach the terminal or logs.
func summarizeUpdates(updates []envKV) []string {
	lines := make([]string, 0, len(updates))
	for _, u := range updates {
		if u.secret {
			lines = append(lines, "set "+u.key)
		} else {
			lines = append(lines, "set "+u.key+"="+u.val)
		}
	}
	return lines
}
