package secgate

import "strings"

var metaTokens = []string{
	";", "|", "&", "$", "`", ">", "<", "\n", "\r", "\x00", "$(", "&&", "||",
}

// deniedBinaries are shells, interpreters, and exec-wrappers. Running one
// re-introduces the shell that argv execution exists to avoid (sh -c, bash -lc)
// or re-execs an arbitrary program behind the gate (env sh, sudo, xargs), so
// they are denied outright by basename rather than by flag. This also covers
// exec wrappers that re-exec or bound another program (nsenter, unshare, flock,
// ...) and macOS interpreters and tracers that script or run arbitrary code
// (osascript, lldb, dtrace).
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
	// exec wrappers (S1)
	"nsenter": true, "unshare": true, "setpriv": true, "flock": true,
	"capsh": true, "ionice": true, "taskset": true, "setarch": true,
	"chrt": true, "runcon": true, "eatmydata": true,
	// interpreters (S1)
	"expect": true, "tclsh": true, "wish": true,
	// macOS interpreters and tracers (S1)
	"osascript": true, "lldb": true, "dtrace": true,
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
// exists, Decision.Suggestion names it. This is the full (unattended-path)
// classifier; ClassifyExternalConfirmed relaxes the structural code-exec denials
// for a human-confirmed path.
func Classify(c Command) Decision {
	if d := metaDecision(c); !d.Allowed {
		return d
	}
	name := strings.ToLower(baseName(strings.TrimSpace(c.Binary)))
	if deniedBinaries[name] {
		return Decision{Allowed: false, Reason: name + " is a shell, interpreter, or exec-wrapper and is not permitted directly"}
	}
	if name != "" {
		if flag, bad := execFlag(name, c.Args); bad {
			return Decision{Allowed: false, Reason: name + " " + flag + " runs arbitrary code and is not permitted"}
		}
	}
	return classifyNonStructuralExternal(c)
}

// ClassifyExternalConfirmed is the EXTERNAL classifier for a human-confirmed path
// (Safe, LOCAL always-confirm, or the Auto HITL-fallback - selected by the gate's
// humanGovernedPath). The structural code-execution denials (shell metacharacters,
// shells/interpreters/exec-wrappers, and per-binary exec flags) are relaxed because
// the operator approves the exact argv; the non-structural EXTERNAL denials
// (empty binary, per-binary resource bounds, and the enumeration scope-evasion,
// credential-file, and config-file denials) still apply. The gate's allowlist,
// scope, destructive, and sensitive-path layers are enforced separately and are
// unaffected.
func ClassifyExternalConfirmed(c Command) Decision {
	return classifyNonStructuralExternal(c)
}

// classifyNonStructuralExternal runs the EXTERNAL denials that are NOT structural
// code-execution denials, so they hold on every path (attended or not): the
// empty-binary check, per-binary resource bounds, and the enumeration
// scope-evasion / credential-file / config-file denials.
func classifyNonStructuralExternal(c Command) Decision {
	if strings.TrimSpace(c.Binary) == "" {
		return Decision{Allowed: false, Reason: "empty binary"}
	}
	if d, tripped := classifyUnbounded(c); tripped {
		return d
	}
	name := strings.ToLower(baseName(strings.TrimSpace(c.Binary)))
	if name == "dnsrecon" {
		if a, bad := dnsreconGluedFlag(c.Args); bad {
			return Decision{
				Allowed:    false,
				Reason:     "dnsrecon " + a + " glues or bundles a short flag with its value, which hides a target from the scope check",
				Suggestion: "give each short flag its value as a separate argument, e.g. -d example.com",
			}
		}
	}
	if enumConfigDeny[name].letters != "" {
		if a, bad := enumConfigFlag(name, c.Args); bad {
			return Decision{Allowed: false, Reason: name + " " + a + configOptionNote, Suggestion: enumConfigHint[name]}
		}
		if a, bad := enumGluedHostFlag(name, c.Args); bad {
			return Decision{
				Allowed:    false,
				Reason:     name + " " + a + " glues or bundles a host flag with its value, which hides a target from the scope check",
				Suggestion: "give the host flag its value as a separate argument, e.g. -I 10.0.0.5",
			}
		}
	}
	if d, bad := enumAudit(name, c.Args); bad {
		return d
	}
	return Decision{Allowed: true}
}

// metaDecision denies an empty binary and any shell metacharacter in the binary
// or an argument. It is the first structural check of both Classify and
// ClassifyLocal.
func metaDecision(c Command) Decision {
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
	return Decision{Allowed: true}
}

// findExecPredicates are the find primaries that run a program or write a file.
// Matching is case-insensitive, which errs toward denial.
var findExecPredicates = map[string]bool{
	"-exec": true, "-execdir": true, "-ok": true, "-okdir": true,
	"-delete": true, "-fprintf": true, "-fprint": true, "-fprint0": true,
	"-fls": true,
}

// findExecArg reports the first argument of find that is a code-exec or
// file-writing predicate.
func findExecArg(args []string) (string, bool) {
	for _, a := range args {
		if findExecPredicates[strings.ToLower(a)] {
			return a, true
		}
	}
	return "", false
}

// ClassifyLocal is the structural check of the local profile. It keeps only the
// denials that make gating enforceable: shell metacharacters, shells,
// interpreters and exec-wrappers, find code-exec predicates, and the known
// per-binary code-exec flags (execFlag, the same check Classify applies). There
// is no binary allowlist and no per-binary bound or enumeration audit; any other
// native binary passes. find is the one deniedBinaries entry that may run, as
// long as it carries no exec or file-writing predicate.
func ClassifyLocal(c Command) Decision {
	if d := metaDecision(c); !d.Allowed {
		return d
	}
	name := strings.ToLower(baseName(strings.TrimSpace(c.Binary)))
	if name == "find" {
		if a, bad := findExecArg(c.Args); bad {
			return Decision{Allowed: false, Reason: "find " + a + " runs arbitrary code or writes files and is not permitted"}
		}
		return Decision{Allowed: true}
	}
	if deniedBinaries[name] {
		return Decision{Allowed: false, Reason: name + " is a shell, interpreter, or exec-wrapper and is not permitted directly"}
	}
	if flag, bad := execFlag(name, c.Args); bad {
		return Decision{Allowed: false, Reason: name + " " + flag + " runs arbitrary code and is not permitted"}
	}
	return Decision{Allowed: true}
}

// ClassifyLocalConfirmed is the LOCAL classifier for a human-confirmed path. LOCAL
// always confirms (every command is surfaced to the operator), so the structural
// code-exec denials are relaxed and only the empty-binary check remains. The
// gate's destructive, sensitive-path, and scope layers still apply.
func ClassifyLocalConfirmed(c Command) Decision {
	if strings.TrimSpace(c.Binary) == "" {
		return Decision{Allowed: false, Reason: "empty binary"}
	}
	return Decision{Allowed: true}
}

// smbArgLetters are the single-letter smbclient and rpcclient options that
// certainly take a value (-I -M -L host flags, -t -m -D -b -p -d -l -R -n -W -U
// -i -O). The first one in a bundle consumes the rest of the bundle as its
// value, so letters after it are data, not flags. Each letter takes a value in
// every binary where it is valid, so one shared set is safe for both tools.
const smbArgLetters = "IMLtmDbpdlRnWUiO"

// enumDeny lists, for one enumeration binary, the short letters (matched inside
// a bundle, up to the first letter in takesArg) and long names (matched with
// unambiguous-prefix abbreviation, errs toward denial) denied outright because
// they read a config, credential, or target file, or open a file channel the
// arg layer cannot bound.
type enumDeny struct {
	letters  string
	longs    []string
	takesArg string
}

// smbDeny is shared by smbclient and rpcclient. -T/--tar names a local tar file
// as a positional argument, -A/--authentication-file reads credentials,
// -s/--configfile and --option load or set smb.conf parameters,
// --use-krb5-ccache names a credential cache, -P/--machine-pass reads the local
// machine secret. -c/--command is denied separately by execFlag.
var smbDeny = enumDeny{
	letters: "TAsP",
	longs: []string{
		"tar", "authentication-file", "configfile", "option",
		"use-krb5-ccache", "machine-pass",
	},
	takesArg: smbArgLetters,
}

// ldapArgLetters are the single-letter ldapsearch options that take a value.
const ldapArgLetters = "abDEefFhHlOopPRsSTUwXyYzd"

// snmpArgLetters are the single-letter snmpwalk options that take a value (-D
// takes an optional glued token list, so it ends a bundle too).
const snmpArgLetters = "vcaAeElnuxXZrtDmMPOILC"

// enumConfigDeny maps an enumeration binary to its outright denials. nbtscan -f
// and onesixtyone -i read the scan targets from a file, which the scope check
// never sees. ldapsearch: -y reads the bind password from a file, -t/-tt write
// values into a temp directory the caller does not choose, -C chases referrals
// to hosts the scope check never sees, and -h names the server outside a URI
// (deprecated for -H, and a single-label value would skip the scope check).
// snmpwalk: -L opens a log file, and -m/-M load MIB files and directories from
// arbitrary paths (a parse error prints part of the file). dig: -f reads a batch
// file whose lines are full dig command lines with their own @server (a resolver
// the scope check never sees), -k reads a TSIG key file, and -y puts the TSIG
// secret on the command line. dig has no long options; its value-taking letters
// besides those are b c p q t x, so the rest of a bundle after one of them is data.
var enumConfigDeny = map[string]enumDeny{
	"dig":         {letters: "fky", takesArg: "bcpqtx"},
	"smbclient":   smbDeny,
	"rpcclient":   smbDeny,
	"nbtscan":     {letters: "f", longs: []string{"file"}},
	"ldapsearch":  {letters: "yhtC", takesArg: ldapArgLetters},
	"snmpwalk":    {letters: "LMm", takesArg: snmpArgLetters},
	"onesixtyone": {letters: "i", takesArg: "ciow"},
}

// enumConfigHint is the suggestion shown with an outright denial.
var enumConfigHint = map[string]string{
	"dig":        "give the query and @server on the command line; -f, -k, and -y are not permitted",
	"ldapsearch": "pass the server as -H ldap://host; -h, -y, -t, and -C are not permitted",
}

// enumHostFlags maps a binary to the short flags whose value is a target host.
var enumHostFlags = map[string]string{"smbclient": "ILMB", "rpcclient": "I", "ldapsearch": "H"}

// enumFlagMatch reports whether a is one of the short letters (anywhere in a
// bundle before a letter in takesArg ends it) or one of the long names
// (including an abbreviation and a =value form).
func enumFlagMatch(a, letters string, longs []string, takesArg string) bool {
	if len(a) < 2 || a[0] != '-' {
		return false
	}
	if a[1] == '-' {
		fname, _, _ := strings.Cut(a[2:], "=")
		if fname == "" {
			return false
		}
		for _, l := range longs {
			if strings.HasPrefix(l, fname) {
				return true
			}
		}
		return false
	}
	for i := 1; i < len(a); i++ {
		if strings.IndexByte(letters, a[i]) >= 0 {
			return true
		}
		if strings.IndexByte(takesArg, a[i]) >= 0 {
			return false
		}
	}
	return false
}

// enumConfigFlag reports the first argument that matches the binary's outright
// denials in enumConfigDeny.
func enumConfigFlag(name string, args []string) (string, bool) {
	d := enumConfigDeny[name]
	for _, a := range args {
		if enumFlagMatch(a, d.letters, d.longs, d.takesArg) {
			return a, true
		}
	}
	return "", false
}

// enumGluedHostFlag reports the first single-dash argument in which a
// host-carrying short flag (-I, -L, -M, -B, ldapsearch -H) has its value glued
// or bundled after it (-Ievil.com, -NL8.8.8.8). ExtractTargets skips a dash-led
// token that has no '=', so that host would never be scope-checked. A separate
// value token, and the long form --ip-address=host, are seen by the extractor
// and stay allowed.
func enumGluedHostFlag(name string, args []string) (string, bool) {
	carriers := enumHostFlags[name]
	if carriers == "" {
		return "", false
	}
	takesArg := enumConfigDeny[name].takesArg
	for _, a := range args {
		if len(a) < 3 || a[0] != '-' || a[1] == '-' {
			continue
		}
		for i := 1; i < len(a); i++ {
			if strings.IndexByte(carriers, a[i]) >= 0 {
				if i+1 < len(a) {
					return a, true
				}
				break
			}
			if strings.IndexByte(takesArg, a[i]) >= 0 {
				break
			}
		}
	}
	return "", false
}

func dnsreconGluedFlag(args []string) (string, bool) {
	return gluedShortFlag(args, "-iL")
}

// gluedShortFlag reports the first single-dash argument longer than two
// characters, other than the exact token exempt.
func gluedShortFlag(args []string, exempt string) (string, bool) {
	for _, a := range args {
		if len(a) > 2 && a[0] == '-' && a[1] != '-' && a != exempt {
			return a, true
		}
	}
	return "", false
}

// ncExecLong are the long options of nc/ncat that run a program or command.
var ncExecLong = []string{"exec", "sh-exec", "lua-exec"}

// execFlag reports the first argument that is a code-execution flag of a
// default-allowlist binary: nmap --script and its relatives (NSE runs arbitrary
// Lua, including os.execute), nmap --datadir (loads the NSE core from a
// model-writable directory), nc/ncat -e, -c, --exec, --sh-exec, --lua-exec (run
// a program on connect), curl --unix-socket (reaches local daemons such as
// docker.sock), and ip netns / ip vrf / ip -batch (netns exec and vrf exec run
// a program; a batch file can hold either), ffuf -input-cmd/-input-shell, and
// nikto -Option/-Plugins (nikto.conf overrides and plugin selection). These
// bypass the shell and
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
		case "smbclient", "rpcclient":
			// -c/--command is an unbounded command channel (get and put touch
			// local files), the same class as nc -e.
			if enumFlagMatch(a, "c", []string{"command"}, smbArgLetters) {
				return a, true
			}
		case "ffuf":
			// -input-cmd runs a command to produce the wordlist, through the shell
			// named by -input-shell. Go's flag package matches names exactly.
			if l := strings.ToLower(fname); l == "input-cmd" || l == "input-shell" {
				return a, true
			}
		case "nikto":
			// -Option overrides any nikto.conf setting (PLUGINDIR names Perl code
			// that nikto loads) and -Plugins selects plugins. Getopt::Long accepts
			// any unique prefix, so match a prefix of two or more letters. The
			// audited-spelling list in enumAudit denies the rest of the surface.
			if l := strings.ToLower(fname); len(l) >= 2 && (strings.HasPrefix("option", l) || strings.HasPrefix("plugins", l)) {
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
