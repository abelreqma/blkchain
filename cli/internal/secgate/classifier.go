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
	if name := strings.ToLower(baseName(strings.TrimSpace(c.Binary))); name != "" {
		if flag, bad := execFlag(name, c.Args); bad {
			return Decision{Allowed: false, Reason: name + " " + flag + " runs arbitrary code and is not permitted"}
		}
	}
	if d, tripped := classifyUnbounded(c); tripped {
		return d
	}
	return Decision{Allowed: true}
}

// ncExecLong are the long options of nc/ncat that run a program or command.
var ncExecLong = []string{"exec", "sh-exec", "lua-exec"}

// execFlag reports the first argument that is a code-execution flag of a
// default-allowlist binary: nmap --script and its relatives (NSE runs arbitrary
// Lua, including os.execute), nmap --datadir (loads the NSE core from a
// model-writable directory), nc/ncat -e, -c, --exec, --sh-exec, --lua-exec (run
// a program on connect), curl --unix-socket (reaches local daemons such as
// docker.sock), and ip netns / ip vrf / ip -batch (netns exec and vrf exec run
// a program; a batch file can hold either). These bypass the shell and
// interpreter denials above, so they are structural denials too. Matching
// follows getopt: nmap uses getopt_long_only, so the flag may have one or two
// dashes, may be abbreviated (--scr), and may carry =value; nc/ncat long
// options may be abbreviated, and the short -e/-c may sit in a bundle (-ve) or
// be glued to a value (-e/bin/sh). Matching errs toward denial.
//
// This covers the default-allowlist binaries only. A binary an operator adds
// with an `allow` line that has its own exec flags needs its own review.
func execFlag(name string, args []string) (string, bool) {
	for _, a := range args {
		if name == "ip" {
			if f, bad := ipExecArg(a); bad {
				return f, true
			}
		}
		if len(a) < 2 || a[0] != '-' {
			continue
		}
		double := strings.HasPrefix(a, "--")
		fname, _, _ := strings.Cut(strings.TrimLeft(a, "-"), "=")
		switch name {
		case "nmap":
			if strings.HasPrefix(fname, "script") || (len(fname) >= 3 && strings.HasPrefix("script", fname)) {
				return a, true
			}
			// --datadir loads nse_main.lua and the NSE library from a directory
			// the model can write, so it is the same RCE as --script.
			if fname == "datadir" || (len(fname) >= 5 && strings.HasPrefix("datadir", fname)) || fname == "interactive" {
				return a, true
			}
		case "curl":
			// A unix socket reaches local daemons (docker.sock) that run code.
			if fname == "unix-socket" || fname == "abstract-unix-socket" {
				return a, true
			}
		case "nc", "ncat", "netcat":
			if double {
				for _, f := range ncExecLong {
					if fname != "" && strings.HasPrefix(f, fname) {
						return a, true
					}
				}
				continue
			}
			run := fname
			for i := 0; i < len(fname); i++ {
				if c := fname[i]; !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
					run = fname[:i]
					break
				}
			}
			if strings.ContainsAny(run, "ec") {
				return a, true
			}
		}
	}
	return "", false
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

// ipExecArg reports whether one argument of `ip` selects a code-execution
// feature. iproute2 accepts any prefix of an object name, so `ip netns exec`
// may be written `ip net exec`, and `ip vrf exec` as `ip v exec`. `ip -batch
// FILE` runs commands read from a file, which could include either. Enumeration
// objects (addr, route, link, neigh) and their flags are not matched.
func ipExecArg(a string) (string, bool) {
	if a == "" {
		return "", false
	}
	if a[0] == '-' {
		f := strings.TrimLeft(a, "-")
		f, _, _ = strings.Cut(f, "=")
		if f == "b" || (len(f) >= 2 && strings.HasPrefix("batch", f)) {
			return a, true
		}
		return "", false
	}
	t := strings.ToLower(a)
	if (len(t) >= 3 && strings.HasPrefix("netns", t)) || strings.HasPrefix("vrf", t) {
		return a, true
	}
	return "", false
}
