package secgate

import (
	"context"
	"strings"
	"testing"
)

// Flag audit for the DNS enumeration binaries host, nslookup, and dnsrecon.
//
// host (BIND9 9.10.6 man page and usage): -4 -6 -a -c -C -d -i -l -N -r -R -s
// -t -T -v -V -w -W -m. None takes a file, runs a program, or reads options
// from a file. -m only toggles memory debugging. Confirmed empirically: -f is
// an illegal option.
//
// nslookup (BIND9 9.10.6): options are name=value query settings (-query,
// -timeout, -retry, -port, -domain, -debug, -vc, ...). None takes a file or a
// program. The interactive `ls`, `view`, and `finger` commands are "not
// implemented". run_command gives no stdin, so interactive mode reads EOF and
// exits. Confirmed empirically: -file=... is an invalid option.
//
// dnsrecon (source of dnsrecon/cli.py, argparse): no exec, plugin, or config
// file option. File WRITE: -x/--xml, -c/--csv, -j/--json, --db. File READ whose
// lines become DNS queries (a read-and-exfiltrate primitive): -D/--dictionary,
// -iL/--input-list. All are bounded to the scratch dir. argparse accepts any
// unique prefix of a long option and (single-dash) -i for -iL.

func TestDNSEnumBenignInvocationsAllowed(t *testing.T) {
	benign := []Command{
		{Binary: "host", Args: []string{"10.0.0.5"}},
		{Binary: "host", Args: []string{"-t", "mx", "corp.example"}},
		{Binary: "host", Args: []string{"-a", "-W", "3", "corp.example", "10.0.0.5"}},
		{Binary: "host", Args: []string{"-l", "corp.example", "10.0.0.5"}},
		{Binary: "nslookup", Args: []string{"corp.example"}},
		{Binary: "nslookup", Args: []string{"-query=mx", "-timeout=5", "corp.example", "10.0.0.5"}},
		{Binary: "dnsrecon", Args: []string{"-d", "corp.example"}},
		{Binary: "dnsrecon", Args: []string{"-d", "corp.example", "-t", "std", "-n", "10.0.0.5"}},
		{Binary: "dnsrecon", Args: []string{"-d", "corp.example", "-t", "brt", "-D", "words.txt"}},
		{Binary: "dnsrecon", Args: []string{"-d", "corp.example", "-j", "out.json", "-c", "out.csv", "-x", "out.xml", "--db", "out.db"}},
		{Binary: "dnsrecon", Args: []string{"-d", "corp.example", "--json=out.json"}},
		{Binary: "dnsrecon", Args: []string{"-d", "corp.example", "-iL", "domains.txt"}},
	}
	for _, c := range benign {
		if d := Classify(c); !d.Allowed {
			t.Errorf("Classify(%q %v) denied a benign command: %q", c.Binary, c.Args, d.Reason)
		}
		if arg, bad := FileAccessViolation(c); bad {
			t.Errorf("FileAccessViolation(%q %v) denied a benign command (%q)", c.Binary, c.Args, arg)
		}
	}
}

func TestDNSEnumGateAllowsBenignInScope(t *testing.T) {
	stubEnumFixtureResolver(t)
	scope, err := ParseScope(strings.NewReader("10.0.0.0/24\ncorp.example\n"))
	if err != nil {
		t.Fatal(err)
	}
	g := &Gate{Mode: Auto, Scope: scope, Allow: NewAllowlist("host", "nslookup", "dnsrecon")}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	for _, c := range []Command{
		{Binary: "host", Args: []string{"10.0.0.5"}},
		{Binary: "nslookup", Args: []string{"corp.example"}},
		// A dotted output name such as out.json would read as a host target and
		// be denied as out of scope (fail closed), so the gate case uses a bare name.
		{Binary: "dnsrecon", Args: []string{"-d", "corp.example", "-j", "out"}},
	} {
		if d := g.Authorize(context.Background(), c); !d.Allowed {
			t.Errorf("Authorize(%q %v) denied a benign in-scope command: %q", c.Binary, c.Args, d.Reason)
		}
	}
	// An out-of-scope target or resolver is still denied.
	if d := g.Authorize(context.Background(), Command{Binary: "host", Args: []string{"corp.example", "8.8.8.8"}}); d.Allowed {
		t.Error("host with an out-of-scope resolver must be denied")
	}
}

// dnsreconPathFlags are the dnsrecon flags whose value is a file path (write
// or read). Each pair is {short, long}; an empty short means none.
var dnsreconPathFlags = []struct{ short, long string }{
	{"-x", "--xml"},
	{"-c", "--csv"},
	{"-j", "--json"},
	{"", "--db"},
	{"-D", "--dictionary"},
	{"-iL", "--input-list"},
}

func TestDNSReconPathFlagsDeniedEverySpelling(t *testing.T) {
	escapes := []string{"/etc/passwd", "/abs/x", "../audit.jsonl", "a/../../x"}
	for _, f := range dnsreconPathFlags {
		for _, v := range escapes {
			var cmds [][]string
			if f.short != "" {
				cmds = append(cmds,
					[]string{"-d", "corp.example", f.short, v},
					[]string{"-d", "corp.example", f.short + "=" + v},
					[]string{"-d", "corp.example", f.short + v},
				)
				if len(f.short) == 2 {
					cmds = append(cmds, []string{"-d", "corp.example", "-v" + f.short[1:], v})
					cmds = append(cmds, []string{"-d", "corp.example", "-v" + f.short[1:] + v})
				}
			}
			cmds = append(cmds,
				[]string{"-d", "corp.example", f.long, v},
				[]string{"-d", "corp.example", f.long + "=" + v},
			)
			// argparse accepts any unique prefix of a long option.
			name := strings.TrimPrefix(f.long, "--")
			for n := 1; n < len(name); n++ {
				cmds = append(cmds,
					[]string{"-d", "corp.example", "--" + name[:n], v},
					[]string{"-d", "corp.example", "--" + name[:n] + "=" + v},
				)
			}
			for _, args := range cmds {
				c := Command{Binary: "dnsrecon", Args: args}
				if arg, bad := FileAccessViolation(c); !bad {
					t.Errorf("FileAccessViolation(dnsrecon %v) allowed a path escape (flag %s, value %q)", args, f.long, v)
				} else if arg == "" {
					t.Errorf("FileAccessViolation(dnsrecon %v) must report the offending arg", args)
				}
			}
		}
	}
}

// ExtractTargets skips a dash-led token with no '=', so a glued or bundled
// short flag value would carry an unchecked target. The classifier denies it.
func TestDNSReconGluedShortFlagTargetDeniedByGate(t *testing.T) {
	stubEnumFixtureResolver(t)
	scope, err := ParseScope(strings.NewReader("10.0.0.0/24\ncorp.example\n"))
	if err != nil {
		t.Fatal(err)
	}
	g := &Gate{Mode: Auto, Scope: scope, Allow: NewAllowlist("dnsrecon")}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"-d", "corp.example", "-devil.com"},
		{"-d", "corp.example", "-vdevil.com"},
		{"-d", "corp.example", "-n8.8.8.8"},
		{"-d", "corp.example", "-r8.8.8.0/24", "-t", "rvl"},
	} {
		d := g.Authorize(context.Background(), Command{Binary: "dnsrecon", Args: args})
		if d.Allowed {
			t.Errorf("Authorize(dnsrecon %v) allowed a glued short-flag target", args)
		} else if !strings.Contains(d.Reason, "glues or bundles") {
			t.Errorf("Authorize(dnsrecon %v) denied for the wrong reason: %q", args, d.Reason)
		}
	}
	// Separate-token forms are still scope-checked and allowed when in scope.
	for _, args := range [][]string{
		{"-d", "corp.example"},
		{"-d", "corp.example", "-n", "10.0.0.5"},
		{"-d", "corp.example", "--json=out"},
	} {
		if d := g.Authorize(context.Background(), Command{Binary: "dnsrecon", Args: args}); !d.Allowed {
			t.Errorf("Authorize(dnsrecon %v) denied an in-scope command: %q", args, d.Reason)
		}
	}
	// -iL stays structurally accepted; its escaping value is denied by fileaccess.
	if d := Classify(Command{Binary: "dnsrecon", Args: []string{"-d", "corp.example", "-iL", "domains"}}); !d.Allowed {
		t.Errorf("Classify must accept -iL: %q", d.Reason)
	}
	if _, bad := FileAccessViolation(Command{Binary: "dnsrecon", Args: []string{"-iL", "/etc/passwd"}}); !bad {
		t.Error("-iL with an absolute value must still be denied by fileaccess")
	}
	// The rule is bounded to dnsrecon.
	if d := Classify(Command{Binary: "host", Args: []string{"-tmx", "corp.example"}}); !d.Allowed {
		t.Errorf("the glued-flag rule must not apply to host: %q", d.Reason)
	}
}

func TestDNSReconInputListAbbreviatedDashIDenied(t *testing.T) {
	// argparse accepts -i as an abbreviation of the single-dash -iL.
	for _, args := range [][]string{
		{"-i", "/etc/passwd"},
		{"-i=/etc/passwd"},
		{"-i../x"},
		{"-i", "../x"},
	} {
		if _, bad := FileAccessViolation(Command{Binary: "dnsrecon", Args: args}); !bad {
			t.Errorf("FileAccessViolation(dnsrecon %v) allowed a path escape via -i", args)
		}
	}
}

func TestDNSReconPathBinaryBaseNameChecked(t *testing.T) {
	c := Command{Binary: "/usr/bin/dnsrecon", Args: []string{"-d", "corp.example", "--csv", "/abs/x"}}
	if _, bad := FileAccessViolation(c); !bad {
		t.Error("a path-qualified dnsrecon must still be checked by base name")
	}
}

func TestDNSReconRelativePathsAllowedAndOthersUnaffected(t *testing.T) {
	for _, args := range [][]string{
		{"-d", "corp.example", "--csv", "out.csv"},
		{"-d", "corp.example", "-D", "sub/words.txt"},
		{"-d", "corp.example", "--dictionary=words.txt"},
		{"-d", "corp.example", "--input-list", "domains.txt"},
		{"-d", "corp.example", "-vj", "out.json"},
		{"-d", "corp.example", "--threads", "5", "--lifetime", "3.0", "--tcp"},
		{"-d", "corp.example", "-n", "10.0.0.5", "-t", "axfr"},
	} {
		if arg, bad := FileAccessViolation(Command{Binary: "dnsrecon", Args: args}); bad {
			t.Errorf("FileAccessViolation(dnsrecon %v) denied a relative path (%q)", args, arg)
		}
	}
}
