package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
)

// resolveBinVersion returns a fingerprint of binary's file contents: the first
// 16 hex characters of its sha256, so the cache key invalidates when the tool is
// upgraded. It resolves the binary with exec.LookPath, the SAME resolution the
// executor's exec.CommandContext uses (parent-process PATH, which on this
// platform includes e.g. /opt/homebrew/bin), so the fingerprint is of the binary
// that will actually run. Returns "unknown" on any failure (not found on PATH,
// not executable, unreadable), in which case the cache keys on binary name alone.
func resolveBinVersion(binary string) string {
	path, err := exec.LookPath(binary)
	if err != nil {
		return "unknown"
	}
	f, err := os.Open(path)
	if err != nil {
		return "unknown"
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil || info.IsDir() {
		return "unknown"
	}

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}
