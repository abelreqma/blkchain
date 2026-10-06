package secgate

import "strings"

// impacket.go audits the impacket entry points. They share one target grammar,
// [domain/]user[:password]@host, which the generic extractor cannot read: it
// cuts the token at the first '/' and loses the host entirely, so the command
// would be denied for having no verifiable target. They also carry values that
// look like hosts to the extractor but are not, above all a -hashes pair whose
// LM:NT form parses as host:port.
//
// The credential stays in the argv and in the recorded command. These tools take
// the credential on the command line by design, and an engagement's transcript
// is expected to show exactly what ran.

// impacketBinaries are the entry points this grammar applies to.
var impacketBinaries = map[string]bool{
	"secretsdump.py": true, "GetUserSPNs.py": true, "GetNPUsers.py": true,
	"getTGT.py": true, "lookupsid.py": true, "rpcdump.py": true,
	"samrdump.py": true, "mssqlclient.py": true, "psexec.py": true,
	"smbexec.py": true, "wmiexec.py": true, "ntlmrelayx.py": true,
	"ticketer.py": true,
}

// impacketHostFlags name a destination the scope check must see.
var impacketHostFlags = map[string]bool{
	"-target-ip": true, "-dc-ip": true, "-dc-host": true, "-target": true, "-t": true,
}

// impacketOpaqueFlags take a value that is not a destination but that the
// extractor would otherwise read as one: a -hashes LM:NT pair parses as
// host:port, and an output filename like report.txt parses as a hostname.
var impacketOpaqueFlags = map[string]bool{
	"-hashes": true, "-aesKey": true, "-outputfile": true, "-codec": true,
	"-dc-user": true, "-just-dc-user": true, "-request-user": true,
	"-spn": true, "-impersonate": true, "-domain-sids": true,
	"-nthash": true, "-keytab": true, "-ts": true, "-debug-file": true,
}

// impacketTargets extracts every destination from an impacket argv: the host
// after the last '@' of the credential operand, and the value of each host
// flag, whether it is glued with '=' or given as the next argument. It returns
// ok=false when a destination is present but unusable, so the command fails
// closed rather than running untargeted.
func impacketTargets(args []string) (hosts []string, ok bool) {
	ok = true
	const (
		next    = iota // the following argument is a destination
		discard        // the following argument is an opaque value
		read           // read the following argument normally
	)
	state := read
	for _, a := range args {
		switch state {
		case next:
			state = read
			if h, good := impacketHost(a); good {
				hosts = append(hosts, h)
			} else {
				ok = false
			}
			continue
		case discard:
			state = read
			continue
		}
		if a == "" {
			continue
		}
		if a[0] == '-' {
			name, value, hasEq := strings.Cut(a, "=")
			switch {
			case impacketHostFlags[name] && hasEq:
				if h, good := impacketHost(value); good {
					hosts = append(hosts, h)
				} else {
					ok = false
				}
			case impacketHostFlags[name]:
				state = next
			case !hasEq && impacketOpaqueFlags[name]:
				state = discard
			}
			continue
		}
		if !strings.Contains(a, "@") {
			continue // a command operand for psexec and friends
		}
		if h, good := impacketHost(a[strings.LastIndex(a, "@")+1:]); good {
			hosts = append(hosts, h)
		} else {
			ok = false
		}
	}
	return hosts, ok
}

// impacketHost validates the host half of a destination. A scheme, a path and a
// port are stripped; anything that is not a hostname or IP fails closed.
func impacketHost(raw string) (string, bool) {
	h := strings.TrimSpace(raw)
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	if i := strings.LastIndex(h, "@"); i >= 0 {
		h = h[i+1:]
	}
	if h == "" {
		return "", false
	}
	if strings.HasPrefix(h, "[") {
		if j := strings.Index(h, "]"); j > 1 {
			h = h[1:j]
		}
	} else if i := strings.LastIndex(h, ":"); i >= 0 && strings.Count(h, ":") == 1 {
		h = h[:i]
	}
	if !validHost(h) {
		return "", false
	}
	return strings.ToLower(h), true
}

// impacketViolation denies the impacket forms whose destination the scope check
// cannot verify. ntlmrelayx is a relay: with no explicit target it relays to
// whatever authenticates to it, and -tf reads its targets from a file, so both
// forms put the destination outside the gate's reach.
func impacketViolation(name string, args []string) (Decision, bool) {
	if name != "ntlmrelayx.py" {
		return Decision{}, false
	}
	named := false
	for _, a := range args {
		flag, _, _ := strings.Cut(a, "=")
		switch flag {
		case "-tf", "--target-file", "-of", "--output-file":
			return Decision{
				Allowed:    false,
				Reason:     "ntlmrelayx.py " + flag + " reads its targets from a file the scope check never sees",
				Suggestion: "name one target with -t, e.g. -t smb://192.0.2.10",
			}, true
		case "-t", "--target":
			named = true
		}
	}
	if !named {
		return Decision{
			Allowed:    false,
			Reason:     "ntlmrelayx.py with no -t relays to whatever authenticates to it, so its destination cannot be checked against the scope",
			Suggestion: "name one target with -t, e.g. -t smb://192.0.2.10",
		}, true
	}
	return Decision{}, false
}

func init() {
	// Every entry point writes its results through -outputfile, which must stay
	// inside the scratch working directory, and shares the value-taking short
	// letters the bundle parser needs.
	for binary := range impacketBinaries {
		writeFlags[binary] = []string{"-outputfile", "-ts", "-keytab"}
	}
}
