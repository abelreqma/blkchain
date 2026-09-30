package secgate

import (
	"slices"
	"strconv"
	"strings"
)

// enumAudit applies the structural rules of the LDAP, SNMP, and HTTP discovery
// binaries that Classify's shared tables do not express: net-snmp long options,
// gobuster modes and glued flags, nikto's audited option list, and the check
// that a target flag's value is one the scope check can see. It returns
// (Decision, true) when a rule denies the command.
func enumAudit(name string, args []string) (Decision, bool) {
	switch name {
	case "snmpwalk":
		// net-snmp turns every `--name=value` option into an snmp.conf directive,
		// so --mibfile=/etc/hosts reads a file and --includeFile includes one.
		for _, a := range args {
			if strings.HasPrefix(a, "--") {
				return Decision{
					Allowed: false,
					Reason:  "snmpwalk " + a + " is a net-snmp long option, which sets any snmp.conf directive and is not permitted",
				}, true
			}
		}
	case "gobuster":
		// The s3 and gcs modes brute-force bucket names against AWS and GCP, and
		// tftp names a server in -s; none has a target the scope check can verify.
		for _, a := range args {
			if a == "s3" || a == "gcs" || a == "tftp" {
				return Decision{
					Allowed:    false,
					Reason:     "gobuster " + a + " mode has no target the scope check can verify",
					Suggestion: "use the dir, dns, vhost, or fuzz mode",
				}, true
			}
		}
		if a, bad := gluedShortFlag(args, ""); bad {
			return Decision{
				Allowed:    false,
				Reason:     "gobuster " + a + " glues or bundles a short flag with its value, which hides a target from the scope check",
				Suggestion: "give each short flag its value as a separate argument, e.g. -u http://10.0.0.5",
			}, true
		}
	case "ffuf":
		// Go's flag package accepts no glued shorthand, so a glued -u or -x value
		// is a parse error in the tool. Deny it anyway: it would carry a target the
		// extractor skips if the parser ever accepted it.
		for _, a := range args {
			n, _, _ := strings.Cut(strings.TrimLeft(a, "-"), "=")
			if len(a) > 2 && a[0] == '-' && len(n) > 1 && (n[0] == 'u' || n[0] == 'x') && a[1] != '-' {
				return Decision{
					Allowed:    false,
					Reason:     "ffuf " + a + " glues or bundles a target flag with its value, which hides a target from the scope check",
					Suggestion: "give the flag its value as a separate argument, e.g. -u http://10.0.0.5/FUZZ",
				}, true
			}
		}
	case "nikto":
		if a, bad := niktoUnauditedOption(args); bad {
			return Decision{
				Allowed:    false,
				Reason:     "nikto " + a + " is not one of the audited options (exact spelling required, because nikto accepts abbreviations)",
				Suggestion: "use one of: -h -host -url -p -port -ssl -nossl -Tuning -timeout -maxtime -vhost -Display -Pause -o -output -Save -nointeractive -useragent -evasion -root",
			}, true
		}
	}
	return targetFlagAudit(name, args)
}

// niktoAudited is the exact list of nikto option names (no dashes, case
// sensitive) that nikto may use. Everything else is denied. That covers
// -config and -Option (settings from a file or the command line), -update (a
// network fetch that overwrites the databases), -Format (msf+ sends results to a
// Metasploit host), -mutate-options (reads a file), and every abbreviation of
// them, since Getopt::Long resolves any unique prefix. -Option and -Plugins are
// also denied by execFlag with a clearer reason.
var niktoAudited = map[string]bool{
	"h": true, "host": true, "url": true, "p": true, "port": true,
	"ssl": true, "nossl": true, "Tuning": true, "timeout": true,
	"maxtime": true, "useragent": true, "vhost": true, "id": true,
	"Display": true, "Pause": true, "o": true, "output": true, "Save": true,
	"IgnoreCode": true, "nolookup": true, "no404": true, "noslash": true,
	"root": true, "evasion": true, "mutate": true, "Cgidirs": true,
	"usecookies": true, "until": true, "nointeractive": true, "404code": true,
	"404string": true, "Add-header": true, "list-plugins": true,
	"Version": true, "Help": true, "dbcheck": true, "check6": true,
	"useproxy": true, "key": true, "RSAcert": true, "ask": true,
}

// niktoUnauditedOption reports the first dash-led argument whose option name
// (one or two dashes, before any '=') is not in niktoAudited. A lone "-" is a
// value, not an option.
func niktoUnauditedOption(args []string) (string, bool) {
	for _, a := range args {
		if len(a) < 2 || a[0] != '-' {
			continue
		}
		n, _, _ := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(a, "-"), "-"), "=")
		if !niktoAudited[n] {
			return a, true
		}
	}
	return "", false
}

// targetFlagSpec names the flags of one binary whose value is a scan target.
type targetFlagSpec struct {
	flags      []string // the value must resolve to a host the scope check sees
	optional   []string // a boolean in some modes: checked only when a non-flag value follows
	needScheme bool     // the value must be a scheme://host URL
	list       bool     // the value is a comma list: every part is checked on its own
	abbrevMin  int      // if >0, a long flag may be abbreviated to this many letters
	singleDash bool     // a long flag may also take one dash (getopt_long_only)
	denyGlued  bool     // a short flag with its value glued to it is denied: the extractor skips a dash-led token
}

// targetFlagSpecs lists the target-carrying flags of the enumeration binaries.
// ExtractTargets skips a single-label host (an "ordinary word"), and a tool
// resolves it through the search domain to any address, so a flag value that
// yields no target is denied instead of trusted. nikto -h may name a file of
// targets whose contents the scope check never reads; requiring a scheme URL
// keeps an ordinary file name out of that position. gobuster -d and -r are
// booleans in dir mode and take a value in dns mode.
//
// curl and nmap are here for their proxy flags only: each names a host the tool
// connects through, so an out-of-scope value is a scope bypass even when the
// target is in scope. curl -x also works glued (-xhost) and in a bundle (-sxhost),
// which the extractor never sees, so the glued form is denied and the value must
// be its own argument (-sx host stays allowed). curl accepts an unambiguous prefix
// of a long option (--prox, --socks5-h). nmap --proxies takes a comma list of
// URLs, uses getopt_long_only (-proxies, --prox), and needs a scheme on each part.
var targetFlagSpecs = map[string]targetFlagSpec{
	"gobuster":   {flags: []string{"-u", "--url", "--domain", "--resolver", "--proxy"}, optional: []string{"-d", "-r"}},
	"ffuf":       {flags: []string{"-u", "-x", "-replay-proxy"}},
	"ldapsearch": {flags: []string{"-H"}},
	"nikto":      {flags: []string{"-h", "-host", "-url", "-useproxy"}, needScheme: true},
	"curl": {
		flags: []string{
			"-x", "--proxy", "--preproxy", "--socks4", "--socks4a", "--socks5",
			"--socks5-hostname", "--proxy1.0",
		},
		abbrevMin: 3,
		denyGlued: true,
	},
	"nmap": {flags: []string{"--proxies"}, needScheme: true, list: true, abbrevMin: 4, singleDash: true},
}

// expandAbbrev rewrites an abbreviated (or, when singleDash is set, one-dash)
// spelling of a long target flag to its full double-dash name, so flagOccurrence
// sees it. A prefix that matches several flags maps to the first; every flag in
// the list is audited the same way, so which one it is does not matter.
func expandAbbrev(spec targetFlagSpec, args []string) []string {
	if spec.abbrevMin == 0 {
		return args
	}
	out := slices.Clone(args)
	for i, a := range out {
		dashes := len(a) - len(strings.TrimLeft(a, "-"))
		if dashes < 1 || dashes > 2 || (dashes == 1 && !spec.singleDash) {
			continue
		}
		n, rest, hasEq := strings.Cut(a[dashes:], "=")
		if len(n) < spec.abbrevMin {
			continue
		}
		for _, f := range spec.flags {
			if strings.HasPrefix(f, "--") && strings.HasPrefix(f[2:], n) {
				out[i] = f
				if hasEq {
					out[i] += "=" + rest
				}
				break
			}
		}
	}
	return out
}

// targetFlagAudit denies a target flag whose value ExtractTargets cannot turn
// into at least one verifiable host.
func targetFlagAudit(name string, args []string) (Decision, bool) {
	spec, ok := targetFlagSpecs[name]
	if !ok {
		return Decision{}, false
	}
	all := append(slices.Clone(spec.flags), spec.optional...)
	args = expandAbbrev(spec, args)
	for i := range args {
		f, v, ok := flagOccurrence(name, args, i, all)
		if !ok {
			continue
		}
		if slices.Contains(spec.optional, f) && (v == "" || strings.HasPrefix(v, "-")) {
			continue
		}
		// The extractor drops a dash-led token that has no '=', so a value glued to
		// or bundled after a short flag (-xevil.com, -sxevil.com) would reach the
		// scope check unseen. The separate-argument form is seen and stays allowed.
		if spec.denyGlued && len(f) == 2 && f[1] != '-' && v != "" && len(args[i]) > len(v) && strings.HasSuffix(args[i], v) {
			return Decision{
				Allowed:    false,
				Reason:     name + " " + args[i] + " glues a short flag to its value, which hides a target from the scope check",
				Suggestion: "give the value as a separate argument, e.g. " + f + " http://10.0.0.6:8080",
			}, true
		}
		parts := []string{v}
		if spec.list {
			parts = strings.Split(v, ",")
		}
		for _, p := range parts {
			if spec.needScheme && !strings.Contains(p, "://") {
				return Decision{
					Allowed:    false,
					Reason:     name + " " + f + " value " + strconv.Quote(p) + " needs an explicit scheme, because a bare value may name a file of targets the scope check never reads",
					Suggestion: "pass the target as a URL, e.g. " + f + " http://10.0.0.5",
				}, true
			}
			if t, ok := ExtractTargets(Command{Binary: name, Args: []string{p}}); !ok || len(t) == 0 {
				return Decision{
					Allowed:    false,
					Reason:     name + " " + f + " value " + strconv.Quote(p) + " is not a hostname, IP, or URL whose host the scope check can verify",
					Suggestion: "give the target as a dotted hostname, an IP, or a scheme://host URL",
				}, true
			}
		}
	}
	return Decision{}, false
}
