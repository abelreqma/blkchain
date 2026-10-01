package secgate

import (
	"os/exec"
	"path/filepath"
	"strings"
)

// TargetSelfExecViolation reports whether c is a target-analysis command whose
// resolved binary IS its own analysis target. It returns the target path and true
// on a match, else ("", false). Both the binary and the target are canonicalized
// identically - a bare binary name via PATH, a relative path against scratch
// (run_command's working dir), then symlink resolution on both sides - so a
// symlink spelling, a relative/.. spelling, or the macOS /tmp -> /private/tmp link
// cannot defeat the comparison. An unresolvable bare binary yields "" and the rule
// is inert for it (it cannot equal an absolute target and would fail to exec).
func TargetSelfExecViolation(c Command, scratch string) (string, bool) {
	if !strings.EqualFold(strings.TrimSpace(c.Kind), "target-analysis") {
		return "", false
	}
	target := strings.TrimSpace(c.Target)
	if target == "" {
		return "", false
	}
	bin := canonExecPath(c.Binary, scratch)
	tgt := canonFilePath(target, scratch)
	if bin == "" || tgt == "" {
		return "", false
	}
	// Case-insensitive to match the macOS default (case-insensitive) filesystem;
	// on a case-sensitive filesystem this can only over-deny, never under-deny.
	if strings.EqualFold(bin, tgt) {
		return target, true
	}
	return "", false
}

// canonExecPath canonicalizes a command binary the way run_command resolves it: a
// bare name (no separator) via exec.LookPath over PATH; a name containing a
// separator as a path (relative against scratch). An unresolvable bare name
// returns "" (it cannot equal a target path, and it would fail to exec anyway).
func canonExecPath(bin, scratch string) string {
	b := strings.TrimSpace(bin)
	if b == "" {
		return ""
	}
	if !strings.ContainsRune(b, '/') {
		if lp, err := exec.LookPath(b); err == nil {
			return canonPath(lp)
		}
		return ""
	}
	return canonFilePath(b, scratch)
}

// canonFilePath canonicalizes a file path: an absolute path as given, a relative
// path resolved against scratch (or the process cwd when scratch is empty), then
// symlink resolution via canonPath.
func canonFilePath(p, scratch string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	switch {
	case filepath.IsAbs(p):
		// leave p as given; canonPath resolves symlinks and collapses "..".
	case scratch != "":
		p = filepath.Join(scratch, p)
	default:
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
	}
	return canonPath(p)
}

// canonPath resolves symlinks so both sides of the self-exec comparison are in the
// same canonical form. It tries the path as given first (EvalSymlinks handles ".."
// correctly relative to resolved components), then its lexically cleaned form
// (so a "/dir/x/../target" spelling that collapses onto the existing target still
// resolves to the target's real path), and finally falls back to the cleaned
// absolute string when the path does not exist (which, not being the real target,
// correctly will not match it).
func canonPath(p string) string {
	if p == "" {
		return ""
	}
	if ev, err := filepath.EvalSymlinks(p); err == nil {
		return ev
	}
	c := filepath.Clean(p)
	if ev, err := filepath.EvalSymlinks(c); err == nil {
		return ev
	}
	return c
}
