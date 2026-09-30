package secgate

import "strings"

var metaTokens = []string{
	";", "|", "&", "$", "`", ">", "<", "\n", "\r", "\x00", "$(", "&&", "||",
}

// deniedBinaries are shells, interpreters, and exec-wrappers. Running one
// re-introduces the shell that argv execution exists to avoid (sh -c, bash -lc)
// or re-execs an arbitrary program behind the gate (env sh, sudo, xargs), so
// they are denied outright by basename rather than by flag.
var deniedBinaries = map[string]bool{
	// shells
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true,
	"csh": true, "tcsh": true, "fish": true, "ash": true, "rbash": true,
	"mksh": true, "yash": true, "pwsh": true, "powershell": true,
	"cmd": true, "nu": true, "xonsh": true,
	// exec wrappers
	"env": true, "xargs": true, "sudo": true, "su": true, "doas": true,
	"nohup": true, "nice": true, "timeout": true, "setsid": true,
	"stdbuf": true, "watch": true, "script": true, "chroot": true,
	"busybox": true, "command": true, "exec": true,
	// inline-code interpreters and exec-capable utilities
	"python": true, "python2": true, "python3": true, "perl": true,
	"ruby": true, "node": true, "nodejs": true, "php": true, "lua": true,
	"awk": true, "gawk": true, "find": true,
}

// unboundedRules maps a binary to the flags that bound it and the suggestion
// shown when none is present.
var unboundedRules = map[string]struct {
	flags      []string
	suggestion string
}{
	"nmap":    {[]string{"-p", "--top-ports", "-F"}, "add a port bound, e.g. -p 80,443 or --top-ports 100 or -F"},
	"hashcat": {[]string{"--runtime", "--keyspace", "-l", "--limit"}, "add a bound, e.g. --runtime 300"},
	"john":    {[]string{"--max-run-time", "--max-candidates"}, "add a bound, e.g. --max-run-time=300 or --max-candidates=1000000"},
}

// Classify inspects a command's structure (binary and literal args) and denies
// structurally-dangerous or structurally-unbounded commands, independent of
// whether the binary is allowlisted. It fails closed. When a bounded form
// exists, Decision.Suggestion names it.
func Classify(c Command) Decision {
	if strings.TrimSpace(c.Binary) == "" {
		return Decision{Allowed: false, Reason: "empty binary"}
	}
	for _, tok := range c.Args {
		if bad := firstMetaToken(tok); bad != "" {
			return Decision{Allowed: false, Reason: "argument contains a forbidden shell metacharacter: " + bad}
		}
	}
	if bad := firstMetaToken(c.Binary); bad != "" {
		return Decision{Allowed: false, Reason: "binary contains a forbidden shell metacharacter: " + bad}
	}
	if name := strings.ToLower(baseName(strings.TrimSpace(c.Binary))); deniedBinaries[name] {
		return Decision{Allowed: false, Reason: name + " is a shell, interpreter, or exec-wrapper and is not permitted directly"}
	}
	if d, tripped := classifyUnbounded(c); tripped {
		return d
	}
	return Decision{Allowed: true}
}

// firstMetaToken returns the first forbidden token found in s, or "".
func firstMetaToken(s string) string {
	for _, tok := range metaTokens {
		if strings.Contains(s, tok) {
			return tok
		}
	}
	return ""
}

// classifyUnbounded applies per-binary bounded-form rules. It returns
// (Decision, true) when a rule denies the command, else (zero, false).
func classifyUnbounded(c Command) (Decision, bool) {
	name := strings.ToLower(baseName(strings.TrimSpace(c.Binary)))
	rule, ok := unboundedRules[name]
	if !ok || hasAnyFlag(c.Args, rule.flags...) {
		return Decision{}, false
	}
	return Decision{
		Allowed:    false,
		Reason:     name + " without a bound is structurally unbounded",
		Suggestion: rule.suggestion,
	}, true
}

// baseName returns the final path element of a binary path.
func baseName(bin string) string {
	if i := strings.LastIndexByte(bin, '/'); i >= 0 {
		return bin[i+1:]
	}
	return bin
}

// hasAnyFlag reports whether args contains any of flags (exact token, or
// flag=value form for a long flag).
func hasAnyFlag(args []string, flags ...string) bool {
	for _, a := range args {
		for _, f := range flags {
			if a == f || (strings.HasPrefix(f, "--") && strings.HasPrefix(a, f+"=")) {
				return true
			}
		}
	}
	return false
}
