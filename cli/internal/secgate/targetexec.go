package secgate

import (
	"os/exec"
	"path/filepath"
	"strings"
)

// targetexec.go holds the target-self-exec structural denial: a target-analysis
// task must never EXECUTE its own analysis target. A task that exists to INSPECT a
// binary read-only must not run it. This is an always-on, profile- and mode-agnostic
// deny enforced in Gate.checkLocked (before the human-governed-path relaxation and
// the LOCAL/EXTERNAL split), so arming, mode, and the human-confirmed classifier
// relaxations cannot reach it. It is inert for any non-target-analysis Kind and
// for an empty Target, so it changes no other command's verdict.

// TargetSelfExecSuggestion is the operator- and model-facing remedy both call
// sites offer with this denial. One source, so the two paths cannot drift.
const TargetSelfExecSuggestion = "inspect the target read-only (file, stat, nm, readelf, objdump, strings, ldd, getcap) instead of executing it, and name that tool by its absolute path"

// TargetSelfExecViolation reports whether c is a target-analysis command whose
// resolved binary IS its own analysis target. It returns the target path and true
// on a match, else ("", false). Both the binary and the target are canonicalized
// identically - a bare binary name via PATH, a relative path against scratch
// (run_command's working dir), then symlink resolution on both sides - so a
// symlink spelling, a relative/.. spelling, or the macOS /tmp -> /private/tmp link
// cannot defeat the comparison. An unresolvable bare binary yields "" and the rule
// is inert for it (it cannot equal an absolute target and would fail to exec).
//
// offHost says the command executes somewhere other than this host, which a
// declared foothold covering the command's surface makes true. PATH lookup and
// symlink resolution then describe the wrong filesystem and cannot establish the
// identity of a file on the foothold, so an off-host command takes the lexical
// comparison in targetSelfExecOffHost instead.
func TargetSelfExecViolation(c Command, scratch string, offHost bool) (string, bool) {
	if !strings.EqualFold(strings.TrimSpace(c.Kind), "target-analysis") {
		return "", false
	}
	target := strings.TrimSpace(c.Target)
	if target == "" {
		return "", false
	}
	if offHost {
		return targetSelfExecOffHost(c.Binary, target)
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

// targetSelfExecOffHost compares a binary against an analysis target that lives on
// another host. Nothing here touches this host's filesystem: the comparison is
// lexical, because a PATH lookup or a symlink resolved here says nothing about what
// the name resolves to there.
//
// Two absolute paths name two files on that host, so comparing their cleaned forms
// settles it. When either side is not absolute, the only comparable part is the name
// the remote PATH or working directory would resolve, so the base names are compared
// and a match denies. That closes the spelling host resolution could not see at all:
// a bare "foo" against the target /usr/bin/foo resolves to the target there while
// resolving to nothing, or to an unrelated file, here. It can also deny a different
// tool that merely shares the target's base name, which an absolute path for that
// tool resolves.
func targetSelfExecOffHost(bin, target string) (string, bool) {
	b := strings.TrimSpace(bin)
	if b == "" {
		return "", false
	}
	cleanBin, cleanTarget := filepath.Clean(b), filepath.Clean(target)
	if filepath.IsAbs(cleanBin) && filepath.IsAbs(cleanTarget) {
		if strings.EqualFold(cleanBin, cleanTarget) {
			return target, true
		}
		return "", false
	}
	if strings.EqualFold(filepath.Base(cleanBin), filepath.Base(cleanTarget)) {
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
