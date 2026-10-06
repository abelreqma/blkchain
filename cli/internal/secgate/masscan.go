package secgate

import "strings"

// masscan.go denies masscan's file-bearing flags. masscan needs its own matcher
// because it normalizes a flag name before comparing it: the name is
// lowercased and every '-' and '_' is removed, so --excludefile,
// --exclude-file, --exclude_file and --EXCLUDEFILE are one flag. A literal
// denylist would catch one spelling and miss the rest.
//
// Every file channel is denied rather than bounded. masscan's evidence channel
// is its captured stdout, which the runner records; network-command output files
// are ephemeral by design, so a file flag buys nothing and each one is either a
// way to read targets and options the scope check never sees or a write the
// bound would have to chase through a normalizing parser.

// masscanFileFlags are the denied flags in masscan's own normalized form.
var masscanFileFlags = map[string]string{
	"c":              "reads options from a file",
	"conf":           "reads options from a file",
	"resume":         "reads options from a paused scan file",
	"excludefile":    "reads excluded targets from a file",
	"includefile":    "reads targets from a file",
	"il":             "reads targets from a file",
	"readscan":       "reads and prints a saved scan file",
	"pcap":           "writes a capture file",
	"pcappayloads":   "reads packet payloads from a file",
	"nmapdatadir":    "loads data files from a directory",
	"outputfilename": "writes a results file",
	"ox":             "writes a results file",
	"oj":             "writes a results file",
	"ol":             "writes a results file",
	"og":             "writes a results file",
	"ob":             "writes a results file",
	"ou":             "writes a results file",
	"rotatedir":      "writes rotated results into a directory",
}

// normalizeMasscanFlag renders a dash-led argument's name the way masscan's own
// parser compares it: dashes stripped from the front, lowercased, and every '-'
// and '_' removed from the rest. It returns "" for a non-flag argument.
func normalizeMasscanFlag(a string) string {
	if len(a) < 2 || a[0] != '-' {
		return ""
	}
	name, _, _ := strings.Cut(strings.TrimLeft(a, "-"), "=")
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if r == '-' || r == '_' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// masscanViolation reports the first denied masscan file flag, in whatever
// spelling it was written.
func masscanViolation(name string, args []string) (Decision, bool) {
	if name != "masscan" {
		return Decision{}, false
	}
	for _, a := range args {
		flag := normalizeMasscanFlag(a)
		if flag == "" {
			continue
		}
		if why, denied := masscanFileFlags[flag]; denied {
			return Decision{
				Allowed:    false,
				Reason:     "masscan " + a + " " + why + ", which the gate cannot bound through masscan's normalizing parser",
				Suggestion: "let the scan print to stdout, which is captured as evidence",
			}, true
		}
	}
	return Decision{}, false
}
